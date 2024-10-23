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
    level=logging.INFO,
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
def run_graphql_query_for_day(query_name, query_template, endpoint, headers, start_time, end_time, environment, limit=10000):
    offset = 0
    all_results = []
    total_records = None
    while True:
        query = query_template.format(start_time=start_time, end_time=end_time, environment=environment, limit=limit, offset=offset)
        logging.info(f"Running '{query_name}' query for {start_time} to {end_time} with offset {offset} and limit {limit}")
        result_json = run_graphql_query(query, endpoint, headers)
        if result_json is None:
            logging.error("No data returned from the query.")
            break

        # Check if 'total' is available in the response to determine the total number of records
        if 'explore' in result_json['data']:
            current_results = result_json['data']['explore']['results']
            total_records = result_json['data']['explore'].get('total', None)  # Extract total records
        elif 'entities' in result_json['data']:
            current_results = result_json['data']['entities']['results']
            total_records = result_json['data']['entities'].get('total', None)
        else:
            logging.error(f"Unexpected result structure: {result_json}")
            break

        all_results.extend(current_results)
        logging.info(f"Fetched {len(current_results)} records for '{query_name}', total so far: {len(all_results)}")
        # Log the total records when fetched for the first time
        if total_records is not None:
            logging.info(f"Total records for '{query_name}': {total_records}")
        # If the number of records already fetched equals or exceeds total_records, stop paginating
        if total_records is not None and len(all_results) >= total_records:
            logging.info(f"All {total_records} records fetched for '{query_name}'.")
            break
        # If fewer records are returned than the limit, stop paginating
        if len(current_results) < limit:
            logging.info(f"Finished fetching all records for '{query_name}' from {start_time} to {end_time}. Total records fetched: {len(all_results)}")
            break

        # Increment the offset for the next page
        offset += limit
    return all_results

# Function to run GraphQL query with error handling
def run_graphql_query(query, endpoint, headers):
    try:
        with requests.Session() as session:
            response = session.post(endpoint, json={'query': query}, headers=headers)
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
        if query_name == 'Services':
            data = [{
                'entityId': result.get('entityId'),
                'serviceName': result.get('serviceName'),
                'type': result.get('type'),
                'version': result.get('version'),
                'environment': result.get('environment'),
                'status': result.get('status'),
                'lastSeen': result.get('lastSeen')
            } for result in result_json['data']['entities']['results']]
            return pd.DataFrame(data)

        elif query_name in ['Linux Agents', 'Windows Agents', 'Healthchecks']:
            data = []
            for result in result_json['data']['explore']['results']:
                ip = result.get('tags_host_ip', {}).get('value') or result.get('tags_net_peer_ip', {}).get('value') or result.get('requestHeaders_host_ip', {}).get('value')
                if ip:
                    ip = ip.strip()
                    data.append({
                        'intervalStart': result['__intervalStart'],
                        'ip': ip,
                        'call_count': result['count_calls']['value']
                    })
            return pd.DataFrame(data) if data else pd.DataFrame()
        else:
            logging.error(f"Unexpected query name: {query_name}")
            return pd.DataFrame()
    except KeyError as e:
        logging.error(f"KeyError processing {query_name}: {e}")
        return pd.DataFrame()  # Return empty DataFrame if error occurs

# Main function to run all queries for multiple environments and write results to CSV
def main(config):
    endpoint = config['graphql_endpoint']
    token = config['token']
    environments = config['environments'].split(',')  # Accept comma-separated environments
    last_x_days = config['last_x_days']
    headers = {
        'Authorization': f'{token}',
        'Content-Type': 'application/json'
    }
    # Define query templates (unchanged)
    query_templates = {
        'Services': '''
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
            }}
            total
          }}
        }}
        ''',
        'Linux Agents': '''
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
              }}
              count_calls: selection(expression: {{ key: "calls" }}, aggregation: COUNT) {{
                value
              }}
            }}
          }}
        }}
        ''',
        'Windows Agents': '''
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
              }}
              count_calls: selection(expression: {{ key: "calls" }}, aggregation: COUNT) {{
                value
              }}
            }}
          }}
        }}
        ''',
        'Healthchecks': '''
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
              }}
              count_calls: selection(expression: {{ key: "calls" }}, aggregation: COUNT) {{
                value
              }}
            }}
          }}
        }}
        '''
    }

    # Create an Excel writer to store all the environment data into one file
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f'agent_inventory_report_{timestamp}.xlsx'
    combined_summary_data = []  # Store data across environments for summary
    with pd.ExcelWriter(filename, engine='xlsxwriter') as writer:
        for environment in environments:
            environment = environment.strip()
            logging.info(f"Processing for environment: {environment}")
            current_day = datetime.datetime.utcnow()
            # Initialize summary data for this environment
            summary_data = {'environment': environment, 'total_linux_ips': 0, 'total_windows_ips': 0,
                            'total_services': 0, 'total_healthchecks': 0}
            # Dictionary to store unique IPs and totals
            unique_linux_ips = set()
            unique_windows_ips = set()
            total_services = 0
            total_healthchecks = 0
            # Process each dataset for the given environment
            for query_name, query_template in query_templates.items():
                all_results = []
                for day_offset in range(last_x_days):
                    target_day = current_day - datetime.timedelta(days=day_offset)
                    start_time, end_time = get_daily_time_range(target_day)
                    day_results = run_graphql_query_for_day(query_name,query_template, endpoint, headers, start_time, end_time,
                                                            environment)
                    all_results.extend(day_results)
                # Process results
                df = process_query_results(query_name, {'data': {
                    'explore': {'results': all_results}}}) if 'explore' in query_template else process_query_results(
                    query_name, {'data': {'entities': {'results': all_results}}})
                if not df.empty:
                    # Write each dataset to an individual tab in the Excel file
                    tab_name = f"{environment}_{query_name.replace(' ', '_')[:28]}"  # Limit tab name to 31 chars
                    df.to_excel(writer, sheet_name=tab_name, index=False)
                    # Update summary data
                    if query_name == 'Linux Agents':
                        unique_linux_ips.update(df['ip'].unique())
                    elif query_name == 'Windows Agents':
                        unique_windows_ips.update(df['ip'].unique())
                    elif query_name == 'Services':
                        total_services = len(df)
                    elif query_name == 'Healthchecks':
                        total_healthchecks = len(df)

            # Update summary data for this environment
            summary_data['total_linux_ips'] = len(unique_linux_ips)
            summary_data['total_windows_ips'] = len(unique_windows_ips)
            summary_data['total_services'] = total_services
            summary_data['total_healthchecks'] = total_healthchecks
            # Append summary data to the combined summary across environments
            combined_summary_data.append(summary_data)
        # Write the combined summary to the "Inventory Summary" tab
        summary_df = pd.DataFrame(combined_summary_data)
        summary_df.to_excel(writer, sheet_name='Inventory Summary', index=False)
    logging.info(f"Inventory report saved to: {filename}")

# Load configuration from JSON file
def load_config(config_file):
    with open(config_file, 'r') as file:
        return json.load(file)

if __name__ == '__main__':
    config = load_config('config.json')
    main(config)