import requests
import pandas as pd
import datetime
from dateutil.relativedelta import relativedelta
import logging
import json
import os

# Configure logging to write to a file in the working directory
log_file = os.path.join(os.getcwd(), 'agent_inventory.log')
logging.basicConfig(
    level=logging.INFO,  # You can change to logging.DEBUG for more verbosity
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

# Function to calculate startTime and endTime for each day in the range
def get_daily_time_range(day):
    start_time = day.replace(hour=0, minute=0, second=0, microsecond=0)
    end_time = start_time + datetime.timedelta(days=1)
    return start_time.isoformat() + 'Z', end_time.isoformat() + 'Z'

# Function to run GraphQL query with pagination for each day
def run_graphql_query_for_day(query_template, endpoint, headers, start_time, end_time, environment, limit=10000):
    offset = 0
    all_results = []
    total_records = None

    while True:
        query = query_template.format(start_time=start_time, end_time=end_time, environment=environment, limit=limit, offset=offset)

        if logging.getLogger().getEffectiveLevel() == logging.DEBUG:
            logging.debug(f"Running full query: {query[:1000]}...")
        else:
            logging.info(f"Running query for {start_time} to {end_time} with offset {offset} and limit {limit}")

        result_json = run_graphql_query(query, endpoint, headers)

        if result_json is None:
            logging.error("No data returned from the query.")
            break  # Exit if no valid result

        # Handle different query structures
        if 'explore' in result_json['data']:
            current_results = result_json['data']['explore']['results']
            total_records = result_json['data']['explore'].get('total', None)
        elif 'entities' in result_json['data']:  # Handle List of Services query
            current_results = result_json['data']['entities']['results']
            total_records = result_json['data']['entities'].get('total', None)
        else:
            logging.error(f"Unexpected result structure: {result_json}")
            break  # Exit if the structure is unexpected

        all_results.extend(current_results)
        logging.info(f"Fetched {len(current_results)} records, total so far: {len(all_results)}")

        # Check if we've fetched all available records for the day
        if len(current_results) < limit:
            logging.info(f"Finished fetching all records for {start_time} to {end_time}.")
            break  # Exit when fewer than `limit` records are returned

        # Increment the offset to fetch the next page
        offset += limit

    return all_results


# Function to run GraphQL query with error handling
def run_graphql_query(query, endpoint, headers):
    try:
        response = requests.post(endpoint, json={'query': query}, headers=headers)
        response.raise_for_status()
        data = response.json()
        if 'errors' in data:
            logging.error(f"GraphQL errors: {data['errors']}")
            return None
        return data
    except requests.exceptions.RequestException as e:
        logging.error(f"Error running query: {e}")
        return None

# Function to process query results and extract IPs or services
def process_query_results(query_name, result_json):
    if result_json is None or 'data' not in result_json:
        logging.error(f"No valid data returned for {query_name}")
        return pd.DataFrame()  # Return an empty DataFrame
    try:
        if query_name == 'List of Services':
            # Extract fields for the services list
            data = [{
                'entityId': result.get('entityId'),
                'serviceName': result.get('serviceName'),
                'type': result.get('type'),
                'version': result.get('version'),
                'environment': result.get('environment'),
                'status': result.get('status'),
                'lastSeen': result.get('lastSeen')
            } for result in result_json['data']['entities']['results']]
            logging.info(f"{query_name} - Total records found: {len(data)}")
            return pd.DataFrame(data)

        elif query_name in ['Linux Agents Reporting', 'Windows Agents Reporting', 'Server Healthchecks']:
            data = []
            for result in result_json['data']['explore']['results']:
                ip = result.get('tags_host_ip', {}).get('value') or result.get('tags_net_peer_ip', {}).get(
                    'value') or result.get('requestHeaders_host_ip', {}).get('value')
                if ip:
                    ip = ip.strip()
                    data.append({
                        'intervalStart': result['__intervalStart'],
                        'ip': ip,
                        'call_count': result['count_calls']['value']
                    })
            logging.info(f"{query_name} - Total records found: {len(data)}")
            return pd.DataFrame(data) if data else pd.DataFrame()

        else:
            logging.error(f"Unexpected query name: {query_name}")
            return pd.DataFrame()

    except KeyError as e:
        logging.error(f"KeyError processing {query_name}: {e}")
        return pd.DataFrame()  # Return empty DataFrame if error occurs

# Define the GraphQL query templates directly in the code
query_templates = {
    'List of Services': '''
    {{
      entities(
        scope: "AGENT_MODULE"
        limit: {limit}
        between: {{
          startTime: "{start_time}"
          endTime: "{end_time}"
        }}
        offset: {offset}
        orderBy: [{{ direction: DESC, keyExpression: {{ key: "lastSeen" }} }}]
        filterBy: [
          {{
            keyExpression: {{ key: "environment" }}
            operator: EQUALS
            value: "{environment}"
            type: ATTRIBUTE
          }}
        ]
      ) {{
        results {{
          entityId: id
          serviceName: attribute(expression: {{ key: "serviceName" }})
          type: attribute(expression: {{ key: "type" }})
          version: attribute(expression: {{ key: "version" }})
          environment: attribute(expression: {{ key: "environment" }})
          status: attribute(expression: {{ key: "status" }})
          lastSeen: attribute(expression: {{ key: "lastSeen" }})
          __typename
        }}
        total
        __typename
      }}
    }}
    ''',
    'Linux Agents Reporting': '''
    {{
      explore(
        scope: "API_TRACE"
        limit: {limit}
        offset: {offset}
        between: {{
          startTime: "{start_time}"
          endTime: "{end_time}"
        }}
        interval: {{ size: 5, units: MINUTES }}
        filterBy: [
          {{
            keyExpression: {{ key: "tags", subpath: "traceableai.module.name" }}
            operator: EQUALS
            value: "ebpf"
            type: ATTRIBUTE
          }},
          {{
            keyExpression: {{ key: "environment" }}
            operator: EQUALS
            value: "{environment}"
            type: ATTRIBUTE
          }}
        ]
        groupBy: {{
          expressions: [{{ key: "tags", subpath: "host.ip" }}]
          groupLimit: 10000
        }}
      ) {{
        results {{
          __intervalStart: intervalStart
          tags_host_ip: selection(
            expression: {{ key: "tags", subpath: "host.ip" }}
          ) {{
            value
            type
            __typename
          }}
          count_calls: selection(expression: {{ key: "calls" }}, aggregation: COUNT) {{
            value
            type
            __typename
          }}
          __typename
        }}
        total
        __typename
      }}
    }}
    ''',
    'Windows Agents Reporting': '''
    {{
      explore(
        scope: "API_TRACE"
        limit: {limit}
        offset: {offset}
        between: {{
          startTime: "{start_time}"
          endTime: "{end_time}"
        }}
        interval: {{ size: 30, units: MINUTES }}
        filterBy: [
          {{
            keyExpression: {{ key: "tags", subpath: "traceableai.module.name" }}
            operator: EQUALS
            value: "mirroring-agent"
            type: ATTRIBUTE
          }},
          {{
            keyExpression: {{ key: "environment" }}
            operator: EQUALS
            value: "{environment}"
            type: ATTRIBUTE
          }}
        ]
        groupBy: {{
          expressions: [{{ key: "tags", subpath: "net.peer.ip" }}]
          groupLimit: 10000
        }}
      ) {{
        results {{
          __intervalStart: intervalStart
          tags_net_peer_ip: selection(
            expression: {{ key: "tags", subpath: "net.peer.ip" }}
          ) {{
            value
            type
            __typename
          }}
          count_calls: selection(expression: {{ key: "calls" }}, aggregation: COUNT) {{
            value
            type
            __typename
          }}
          __typename
        }}
        total
        __typename
      }}
    }}
    ''',
    'Server Healthchecks': '''
    {{
      explore(
        scope: "API_TRACE"
        limit: {limit}
        offset: {offset}
        between: {{
          startTime: "{start_time}"
          endTime: "{end_time}"
        }}
        interval: {{ size: 5, units: MINUTES }}
        filterBy: [
          {{ keyExpression: {{ key: "serviceName" }}, operator: EQUALS, value: "healthcheckservice", type: ATTRIBUTE }},
          {{ keyExpression: {{ key: "environment" }}, operator: EQUALS, value: "{environment}", type: ATTRIBUTE }}
        ]
        groupBy: {{
          expressions: [{{ key: "requestHeaders", subpath: "host-ip" }}]
          groupLimit: 10000
        }}
      ) {{
        results {{
          __intervalStart: intervalStart
          requestHeaders_host_ip: selection(expression: {{ key: "requestHeaders", subpath: "host-ip" }}) {{
            value
            type
            __typename
          }}
          count_calls: selection(expression: {{ key: "calls" }}, aggregation: COUNT) {{
            value
            type
            __typename
          }}
          __typename
        }}
        total
        __typename
      }}
    }}
    '''
}

# Main function to run all queries and write results to Excel files
def main(config):
    endpoint = config['graphql_endpoint']
    token = config['token']
    environment = config['environment']
    last_x_days = config['last_x_days']

    headers = {
        'Authorization': f'{token}',
        'Content-Type': 'application/json'
    }

    # Create an Excel writer to write data into multiple sheets
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'agent_inventory_report_{environment}_{timestamp}.xlsx'
    with pd.ExcelWriter(filename, engine='xlsxwriter') as writer:
        # Write the Inventory Description tab
        inventory_description = pd.DataFrame({
            'Inventory Description': [
                "This Inventory Captures inventory of servers where traceable is deployed.",
                "Information about:",
                "1. Services or App ID's deployed with Traceable.",
                "2. Inventory of Linux agents reporting.",
                "3. Inventory of Windows agents reporting.",
                "4. Inventory of servers with their health check details."
            ]
        })
        inventory_description.to_excel(writer, sheet_name='Inventory Description', index=False)

        # Process each dataset and generate unique IP tabs
        current_day = datetime.datetime.utcnow()
        for query_name, query_template in query_templates.items():
            all_results = []
            for day_offset in range(last_x_days):
                target_day = current_day - datetime.timedelta(days=day_offset)
                start_time, end_time = get_daily_time_range(target_day)
                logging.info(f"Processing {query_name} data for {start_time} to {end_time}")
                day_results = run_graphql_query_for_day(query_template, endpoint, headers, start_time, end_time,
                                                        environment)
                if not day_results:  # Check if results are valid
                    logging.error(f"No results found for {query_name} on {start_time}")
                    continue
                all_results.extend(day_results)

            # Process results and write them to the Excel file
            df = process_query_results(query_name, {'data': {
                'explore': {'results': all_results}}}) if 'explore' in query_template else process_query_results(
                query_name, {'data': {'entities': {'results': all_results}}})
            if df is None or df.empty:
                logging.warning(f"No data found for {query_name}")
            else:
                # Write full data to the query sheet
                df.to_excel(writer, sheet_name=query_name, index=False)
                logging.info(f"Saved {query_name} data to Excel.")

                # Deduplicate IPs and write to a new sheet for unique IPs
                if 'ip' in df.columns:
                    deduplicated_df = df.drop_duplicates(subset=['ip'])
                    # Shorten the deduplicated sheet names to fit Excel's 31-character limit
                    short_names = {
                        'Linux Agents Reporting': 'LinuxAgents_UniqIPs',
                        'Windows Agents Reporting': 'WinAgents_UniqIPs',
                        'Server Healthchecks': 'Healthchecks_UniqIPs'
                    }
                    dedup_sheet_name = short_names.get(query_name, f"{query_name}_UniqIPs")  # Use shortened names
                    deduplicated_df[['ip']].to_excel(writer, sheet_name=dedup_sheet_name, index=False)
                    logging.info(f"Saved {query_name} unique IPs to sheet: {dedup_sheet_name}")

    logging.info(f"Report generation complete. Check '{filename}'.")

# Load configuration from JSON file
def load_config(config_file):
    with open(config_file, 'r') as file:
        return json.load(file)

if __name__ == '__main__':
    config = load_config('config.json')
    main(config)
