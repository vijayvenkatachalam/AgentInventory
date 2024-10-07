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


# Function to calculate startTime and endTime based on last X days
def get_time_range(last_x_days):
    end_time = datetime.datetime.utcnow()
    start_time = end_time - relativedelta(days=last_x_days)
    return start_time.isoformat() + 'Z', end_time.isoformat() + 'Z'


# Function to run GraphQL query with error handling
def run_graphql_query(query, endpoint, headers):
    try:
        logging.info(f"Running query: {query[:1000]}...")  # Log first 100 characters of query for readability
        response = requests.post(endpoint, json={'query': query}, headers=headers)
        response.raise_for_status()  # Raise an error for bad status codes
        data = response.json()
        if 'errors' in data:
            logging.error(f"GraphQL errors: {data['errors']}")
            return None
        return data
    except requests.exceptions.RequestException as e:
        logging.error(f"Error running query: {e}")
        return None


# Function to process query results
def process_query_results(query_name, result_json):
    if result_json is None or 'data' not in result_json:
        logging.error(f"No valid data returned for {query_name}")
        return pd.DataFrame()  # Return empty DataFrame if there's no valid result

    try:
        if query_name == 'List of Services':
            # Extract relevant fields for query 1
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

        elif query_name in ['Linux Agents Reporting', 'Windows Agents Reporting', 'Server Healthchecks']:
            # Extract IPs, interval start, and call count for other queries
            data = [{
                'intervalStart': result['__intervalStart'],
                'ip': result['tags_net_peer_ip']['value'] if 'tags_net_peer_ip' in result else
                result['requestHeaders_host_ip']['value'],
                'call_count': result['count_calls']['value']
            } for result in result_json['data']['explore']['results']]
            return pd.DataFrame(data)

    except KeyError as e:
        logging.error(f"KeyError processing {query_name}: {e}")
        return pd.DataFrame()  # Return empty DataFrame if there's an issue


# Main function to run all queries and write results to a CSV file
def main(config):
    # Parse config inputs
    endpoint = config['graphql_endpoint']
    token = config['token']
    environment = config['environment']
    last_x_days = config['last_x_days']

    # Resolve startTime and endTime dynamically
    start_time, end_time = get_time_range(last_x_days)
    logging.info(f"Start time: {start_time}, End time: {end_time}")

    # Define headers for the API call
    headers = {
        'Authorization': f'{token}',
        'Content-Type': 'application/json'
    }

    # Define the queries (with dynamic time and environment resolution)
    query_1 = f'''
    {{
      entities(
        scope: "AGENT_MODULE"
        limit: 10000
        between: {{
          startTime: "{start_time}"
          endTime: "{end_time}"
        }}
        offset: 0
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
    '''

    query_2 = f'''
    {{
      explore(
        scope: "API_TRACE"
        limit: 10000
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
          groupLimit: 5
        }}
      ) {{
        results {{
          __intervalStart: intervalStart
          tags_net_peer_ip: selection(
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
        __typename
      }}
    }}
    '''

    query_3 = f'''
    {{
      explore(
        scope: "API_TRACE"
        limit: 10000
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
          groupLimit: 5
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
        __typename
      }}
    }}
    '''

    query_4 = f'''
    {{
      explore(
        scope: "API_TRACE"
        limit: 10000
        between: {{startTime: "{start_time}", endTime: "{end_time}"}}
        interval: {{size: 5, units: MINUTES}}
        filterBy: [
          {{keyExpression: {{key: "serviceName"}}, operator: EQUALS, value: "healthcheckservice", type: ATTRIBUTE}},
          {{keyExpression: {{key: "environment"}}, operator: EQUALS, value: "{environment}", type: ATTRIBUTE}}
        ]
        groupBy: {{
          expressions: [{{key: "requestHeaders", subpath: "host-ip"}}]
          groupLimit: 5
        }}
      ) {{
        results {{
          __intervalStart: intervalStart
          requestHeaders_host_ip: selection(expression: {{key: "requestHeaders", subpath: "host-ip"}}) {{
            value
            type
            __typename
          }}
          count_calls: selection(expression: {{key: "calls"}}, aggregation: COUNT) {{
            value
            type
            __typename
          }}
          __typename
        }}
        __typename
      }}
    }}
    '''

    # Run queries with descriptive names
    queries = {
        'List of Services': query_1,
        'Linux Agents Reporting': query_2,
        'Windows Agents Reporting': query_3,
        'Server Healthchecks': query_4
    }

    # Process the results for each query
    results_data = {}
    for query_name, query in queries.items():
        logging.info(f"Executing {query_name}...")
        result_json = run_graphql_query(query, endpoint, headers)
        results_data[query_name] = process_query_results(query_name, result_json)

    # Create a multi-tab CSV file using pandas ExcelWriter
    with pd.ExcelWriter('output_inventory_report.xlsx', engine='xlsxwriter') as writer:
        # Write inventory description
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

        # Write the results of each query to a separate tab with descriptive names
        for query_name, df in results_data.items():
            if df.empty:
                logging.warning(f"No data to write for {query_name}.")
            df.to_excel(writer, sheet_name=query_name, index=False)

    logging.info("Report generation complete. Check 'output_inventory_report.xlsx'.")


# Load configuration from JSON file
def load_config(config_file):
    with open(config_file, 'r') as file:
        return json.load(file)


if __name__ == '__main__':
    # Load config from a JSON file
    config = load_config('config.json')
    main(config)
