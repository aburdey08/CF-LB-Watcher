import os
import sys
import threading
import time
import logging
import requests
import urllib3
from dotenv import load_dotenv
from datetime import datetime, timedelta
from prometheus_client import start_http_server, Gauge
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

load_dotenv()

# Disable warnings for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

NODES_V4 = os.getenv('NODES_V4', '')
NODES_V6 = os.getenv('NODES_V6', '')
NODE_PROTOCOL = os.getenv('NODE_PROTOCOL', 'http')
NODE_PORT = int(os.getenv('NODE_PORT', '80'))
NODE_PATH = os.getenv('NODE_PATH', '/status')
NODE_CHECK_TIMEOUT_MS = int(os.getenv('NODE_CHECK_TIMEOUT', '5000'))
NODE_CHECK_TIMEOUT = NODE_CHECK_TIMEOUT_MS / 1000
NODE_CHECK_INTERVAL = int(os.getenv('NODE_CHECK_INTERVAL', '3'))
LOGGING_LEVEL = os.getenv('LOGGING_LEVEL', 'INFO').upper()

CLOUDFLARE_API_TOKEN = os.getenv('CLOUDFLARE_API_TOKEN', '')
CLOUDFLARE_ZONE_ID = os.getenv('CLOUDFLARE_ZONE_ID', '')
CLOUDFLARE_ENABLE_CF_PROXY = os.getenv('CLOUDFLARE_ENABLE_CF_PROXY', 'True').lower() == 'true'
CLOUDFLARE_DNS_TTL = int(os.getenv('CLOUDFLARE_DNS_TTL', '60'))
CLOUDFLARE_REQUEST_TIMEOUT = int(os.getenv('CLOUDFLARE_REQUEST_TIMEOUT', '10'))
CLOUDFLARE_DNS_RECORD_NAME = os.getenv('CLOUDFLARE_DNS_RECORD_NAME', '')
CLOUDFLARE_VALIDATION_INTERVAL = int(os.getenv('CLOUDFLARE_VALIDATION_INTERVAL', '60'))

FLAPPING_PROTECTION_TIME = int(os.getenv('FLAPPING_PROTECTION_TIME', '30'))

PROMETHEUS_PORT = int(os.getenv('PROMETHEUS_PORT', '8080'))

try:
    logging_level = getattr(logging, LOGGING_LEVEL, logging.INFO)
except AttributeError:
    logging_level = logging.INFO

logging.basicConfig(level=logging_level, format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

if not NODES_V4.strip() and not NODES_V6.strip():
    logger.error('At least one of NODES_V4 or NODES_V6 must be provided.')
    sys.exit(1)

# Split nodes into lists
nodes_v4 = [{'ip': ip.strip(), 'type': 'A'} for ip in NODES_V4.split(',')] if NODES_V4 else []
nodes_v6 = [{'ip': ip.strip(), 'type': 'AAAA'} for ip in NODES_V6.split(',')] if NODES_V6 else []
nodes = nodes_v4 + nodes_v6

nodes_status = {}
nodes_lock = threading.Lock()

for node in nodes:
    nodes_status[node['ip']] = {
        'ip': node['ip'],
        'type': node['type'],
        'status': 'unknown',
        'last_checked': None,
        'last_changed': datetime.min,
        'response_time': None,
        'flapping_timer': None,
        'removed_from_dns': False,
        'flapping_start_time': None,
        'dns_update_needed': False,
        'flapping_timer_thread': None,
    }

dns_update_event = threading.Event()

# Prometheus metrics
node_status_gauge = Gauge('node_status', 'Status of monitored nodes', ['node_ip'])
last_response_time_gauge = Gauge('last_response_time', 'Last response time of monitored nodes', ['node_ip'])
node_check_timeout_gauge = Gauge('node_check_timeout_seconds', 'Node check timeout in seconds')
nodes_info_gauge = Gauge('nodes_info', 'Configured nodes for monitoring (NODES_V4 and NODES_V6)', ['nodes'])
cloudflare_dns_record_name_info = Gauge('cloudflare_dns_record_name_info', 'Tracked DNS record name')
cloudflare_dns_request_duration_seconds = Gauge('cloudflare_dns_request_duration_seconds', 'Time taken to process DNS request')
cloudflare_dns_response_code = Gauge('cloudflare_dns_response_code', 'HTTP response code from Cloudflare')
cloudflare_dns_hosts_in_response = Gauge('cloudflare_dns_hosts_in_response', 'Number of hosts in DNS response')

def start_static_metrics():
    """Set static Prometheus metrics for nodes and DNS record name."""
    nodes_combined = ','.join([node['ip'] for node in nodes])

    node_check_timeout_gauge.set(NODE_CHECK_TIMEOUT)
    nodes_info_gauge.labels(nodes=nodes_combined).set(1)
    cloudflare_dns_record_name_info.set(1)
    
    logger.info(f"Prometheus metrics initialized: nodes_info ({nodes_combined}) and cloudflare_dns_record_name_info ({CLOUDFLARE_DNS_RECORD_NAME}).")

# Session for connection pooling and retries
session = requests.Session()
retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
adapter = HTTPAdapter(max_retries=retries)
session.mount("https://", adapter)

def monitor_nodes():
    """Main monitoring loop that periodically checks all nodes."""
    while True:
        threads = []
        with nodes_lock:
            current_nodes = list(nodes_status.keys())
        for ip in current_nodes:
            t = threading.Thread(target=check_node, args=(ip,))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        time.sleep(NODE_CHECK_INTERVAL)

def check_node(ip):
    """Checks the status of a single node."""
    node = nodes_status[ip]
    url = f"{NODE_PROTOCOL}://{ip}:{NODE_PORT}{NODE_PATH}"
    headers = {
        'Host': CLOUDFLARE_DNS_RECORD_NAME,
    }
    start_time = time.time()
    try:
        response = requests.get(url, headers=headers, timeout=NODE_CHECK_TIMEOUT, verify=False)
        response_time = time.time() - start_time
        if response.status_code == 200:
            with nodes_lock:
                previous_status = node['status']
                node['status'] = 'up'
                node['last_checked'] = datetime.now()
                node['response_time'] = response_time
                if previous_status != 'up':
                    node['last_changed'] = datetime.now()
                    node['dns_update_needed'] = True
                    logger.info(f"Node {ip} is now UP.")
                    dns_update_event.set()
            node_status_gauge.labels(node_ip=ip).set(1)
            last_response_time_gauge.labels(node_ip=ip).set(response_time)
        else:
            logger.warning(f"Node {ip} is DOWN. Response code: {response.status_code}, Response content: {response.text}")
            mark_node_down(ip)
    except requests.RequestException as e:
        logger.warning(f"Node {ip} check failed with error: {e}")
        mark_node_down(ip)

def mark_node_down(ip):
    """Mark a node as down and trigger DNS update if this down."""
    with nodes_lock:
        node = nodes_status[ip]
        previous_status = node['status']
        node['status'] = 'down'
        node['last_checked'] = datetime.now()
        node['response_time'] = None
        if previous_status != 'down':
            node['last_changed'] = datetime.now()
            node['flapping_start_time'] = None
            node['removed_from_dns'] = True
            node['dns_update_needed'] = True
            logger.warning(f"Node {ip} is now DOWN.")
            dns_update_event.set()
    node_status_gauge.labels(node_ip=ip).set(0)
    last_response_time_gauge.labels(node_ip=ip).set(0)

def start_flapping_timer(ip):
    """Starts the flapping protection timer and adds the node back to DNS after the timer expires."""
    node = nodes_status[ip]
    flapping_time_left = FLAPPING_PROTECTION_TIME
    while flapping_time_left > 0:
        time.sleep(1)
        flapping_time_left -= 1
        logger.debug(f"Node {ip} flapping protection time left: {flapping_time_left} seconds")
        with nodes_lock:
            if nodes_status[ip]['status'] != 'up':
                logger.info(f"Node {ip} went down during flapping protection. Cancelling timer.")
                return
    with nodes_lock:
        node['removed_from_dns'] = False
        node['flapping_start_time'] = None
    logger.info(f"Node {ip} passed flapping protection time and will be added back to DNS.")
    dns_update_event.set()

def manage_cloudflare_dns():
    """Manage Cloudflare DNS records by removing or adding A and AAAA records based on node availability."""
    time.sleep(NODE_CHECK_INTERVAL + 1)
    while True:
        dns_update_event.wait(timeout=CLOUDFLARE_VALIDATION_INTERVAL)
        dns_update_event.clear()
        update_dns_records()

def update_dns_records():
    """Update DNS records in Cloudflare based on current node statuses."""
    with nodes_lock:
        current_nodes_status = nodes_status.copy()

    available_nodes = []
    last_up_node = None

    # Collect available nodes and find the last available node
    for ip, node in current_nodes_status.items():
        if node['status'] == 'up':
            if not node.get('removed_from_dns', False):
                available_nodes.append({'ip': ip, 'type': node['type']})
            elif node.get('flapping_timer_thread') is None or not node['flapping_timer_thread'].is_alive():
                node['flapping_timer_thread'] = threading.Thread(target=start_flapping_timer, args=(ip,))
                node['flapping_timer_thread'].start()
                logger.info(f"Node {ip} is UP and removed from DNS. Starting flapping protection timer.")
            last_up_node = {'ip': ip, 'type': node['type']}
    
    # If no available nodes, keep the last one to prevent total DNS removal
    if not available_nodes:
        logger.warning("No available nodes found, keeping the last one to prevent complete DNS removal.")
        if last_up_node:
            available_nodes.append(last_up_node)
        else:
            # Find the last node that was up
            last_up_node_item = max(
                current_nodes_status.items(),
                key=lambda x: x[1]['last_changed'] if x[1]['last_changed'] else datetime.min
            )
            ip = last_up_node_item[0]
            node = last_up_node_item[1]
            last_up_node = {'ip': ip, 'type': node['type']}
            available_nodes.append(last_up_node)
        with nodes_lock:
            nodes_status[last_up_node['ip']]['protected'] = True

    # Get the current DNS records from Cloudflare
    success, current_dns_records = get_current_dns_records()
    if not success:
        logger.error("Failed to get current DNS records.")
        return
    
    current_dns_ips = {(record['ip'], record['type']) for record in current_dns_records}

    # Compare and find which records to add or remove
    desired_records = {(node['ip'], node['type']) for node in available_nodes}
    to_add = desired_records - current_dns_ips
    to_remove = current_dns_ips - desired_records

    # Remove A and AAAA records (protect the last available node)
    if to_remove:
        for ip, record_type in to_remove:
            if ip == last_up_node['ip'] and record_type == last_up_node['type']:
                logger.info(f"Skipping removal of the last available node {ip} to prevent total DNS removal.")
                continue
            success = remove_dns_records([ip], record_type)
            if not success:
                logger.error(f"Failed to remove DNS record for {ip} ({record_type})")

    # Add missing A and AAAA records
    if to_add:
        for ip, record_type in to_add:
            success = add_dns_record(ip, record_type)
            if not success:
                logger.error(f"Failed to add DNS record for {ip} ({record_type})")

def get_current_dns_records():
    """Fetch current DNS records from Cloudflare and update the number of records in Prometheus metrics."""
    url = f"https://api.cloudflare.com/client/v4/zones/{CLOUDFLARE_ZONE_ID}/dns_records"
    params = {'name': CLOUDFLARE_DNS_RECORD_NAME}
    headers = {'Authorization': f'Bearer {CLOUDFLARE_API_TOKEN}', 'Content-Type': 'application/json'}

    try:
        start_time = time.time()
        response = session.get(url, headers=headers, params=params, timeout=CLOUDFLARE_REQUEST_TIMEOUT)
        duration = time.time() - start_time
        cloudflare_dns_request_duration_seconds.set(duration)
        cloudflare_dns_response_code.set(response.status_code)

        if response.status_code == 200:
            data = response.json()
            dns_records = [{'id': rec['id'], 'ip': rec['content'], 'type': rec['type']} for rec in data['result']]
            
            # Update the number of DNS records in the Prometheus metrics
            cloudflare_dns_hosts_in_response.set(len(dns_records))
            
            return True, dns_records
        else:
            logger.error(f"Cloudflare API error: {response.status_code}")
            return False, []
    except Exception as e:
        logger.error(f"Failed to fetch DNS records: {e}")
        return False, []

def remove_dns_records(ips_to_remove, record_type):
    """Remove DNS records from Cloudflare."""
    success, current_dns_records = get_current_dns_records()
    if not success:
        return False

    headers = {'Authorization': f'Bearer {CLOUDFLARE_API_TOKEN}', 'Content-Type': 'application/json'}
    for record in current_dns_records:
        if record['ip'] in ips_to_remove and record['type'] == record_type:
            url = f"https://api.cloudflare.com/client/v4/zones/{CLOUDFLARE_ZONE_ID}/dns_records/{record['id']}"
            try:
                response = session.delete(url, headers=headers, timeout=CLOUDFLARE_REQUEST_TIMEOUT)
                if response.status_code == 200:
                    logger.info(f"Successfully deleted DNS record {record['ip']} ({record['type']}).")
                else:
                    logger.error(f"Failed to delete DNS record {record['ip']} ({record['type']}). Status code: {response.status_code}")
            except Exception as e:
                logger.error(f"Error deleting DNS record {record['ip']} ({record['type']}): {e}")
                return False

    # Update the number of DNS records in Prometheus metrics after deletion
    success, updated_dns_records = get_current_dns_records()
    if success:
        cloudflare_dns_hosts_in_response.set(len(updated_dns_records))

    return True

def add_dns_record(ip, record_type):
    """Add DNS records to Cloudflare."""
    url = f"https://api.cloudflare.com/client/v4/zones/{CLOUDFLARE_ZONE_ID}/dns_records"
    headers = {'Authorization': f'Bearer {CLOUDFLARE_API_TOKEN}', 'Content-Type': 'application/json'}
    data = {
        'type': record_type,
        'name': CLOUDFLARE_DNS_RECORD_NAME,
        'content': ip,
        'ttl': CLOUDFLARE_DNS_TTL,
        'proxied': CLOUDFLARE_ENABLE_CF_PROXY,
    }
    try:
        response = session.post(url, headers=headers, json=data, timeout=CLOUDFLARE_REQUEST_TIMEOUT)
        if response.status_code in [200, 201]:
            logger.info(f"Successfully added DNS record for {ip} ({record_type}).")
        else:
            logger.error(f"Failed to add DNS record for {ip} ({record_type}). Status code: {response.status_code}")
    except Exception as e:
        logger.error(f"Error adding DNS record for {ip} ({record_type}): {e}")
        return False

    # Update the number of DNS records in Prometheus metrics after addition
    success, updated_dns_records = get_current_dns_records()
    if success:
        cloudflare_dns_hosts_in_response.set(len(updated_dns_records))

    return True

def start_metrics_server():
    """Start Prometheus metrics server."""
    start_http_server(PROMETHEUS_PORT)
    logger.info(f"Prometheus metrics server started on port {PROMETHEUS_PORT}")

if __name__ == '__main__':
    # Start static metrics
    start_static_metrics()

    # Start Prometheus metrics server
    start_metrics_server()

    # Start node monitoring thread
    monitor_thread = threading.Thread(target=monitor_nodes)
    monitor_thread.daemon = True
    monitor_thread.start()

    # Start DNS management thread
    dns_manager_thread = threading.Thread(target=manage_cloudflare_dns)
    dns_manager_thread.daemon = True
    dns_manager_thread.start()

    # Keep the main thread alive
    while True:
        time.sleep(1)
