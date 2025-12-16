# @title Cymbal Cyber - Benign Continuous Event Generator

import time
import datetime
import random
import json
import logging
import hashlib
from google.cloud import bigquery
import google.auth

# --- Core Configuration ---
try:
    credentials, project_id = google.auth.default()
    PROJECT_ID = project_id
    if not PROJECT_ID:
        raise Exception("PROJECT_ID is not set.")
    logging.info(f"Successfully authenticated. Project ID: {PROJECT_ID}")
except Exception as e:
    logging.warning(f"Could not auto-detect project ID. Using 'my-project'. Error: {e}")
    PROJECT_ID = "my-project" # Fallback

# --- Table IDs ---
ACCESS_TABLE_ID = f"{PROJECT_ID}.Cymbal_Cyber.user_access_events"
NETWORK_TABLE_ID = f"{PROJECT_ID}.Cymbal_Cyber.network_events"

MESSAGES_PER_SECOND_TARGET = 50 # See note below on scale
# This demo is designed to be built at a low cost point and with default project quotas. BigQuery,
# Pub/Sub, and Vertex AI are all highly scalable services and can operate at far greater throughput
# than 50 events per second, however if you increase this rate, you'll likely run into the default Vertex AI
# project quotas which will result in ADK not processing some records due to quota exceeded errors.
REPORTING_INTERVAL_SECONDS = 10
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Benign User, Device & Event Persona Configuration ---
BENIGN_USERS = [
    'j.doe', 'a.smith', 'm.jones', 'svc_backup', 'svc_monitoring', 'admin', 'guest', 'r.patel',
    's.chen', 'e.williams', 'k.brown', 'd.davis', 't.miller', 'c.wilson', 'b.moore', 'l.taylor',
    'o.anderson', 'p.thomas', 'j.jackson', 'h.white', 'v.martin', 'n.thompson'
]
WINDOWS_DEVICES = ['ws-exec-01', 'ws-exec-02', 'ws-hr-01', 'ws-hr-05', 'ws-finance-03', 'ws-dev-10', 'ws-dev-11']
MACOS_DEVICES = ['ws-exec-mac-01', 'ws-dev-mac-01']
SERVER_DEVICES = [
    'srv-db-prod-01', 'srv-db-prod-02', 'srv-app-prod-01', 'srv-app-prod-02',
    'srv-web-prod-02', 'srv-dns-int-01', 'srv-proxy-01', 'srv-fileshare-01'
]
WINDOWS_PROCESSES = ['chrome.exe', 'outlook.exe', 'teams.exe', 'powershell.exe', 'svchost.exe', 'explorer.exe']
MACOS_PROCESSES = ['chrome', 'terminal', 'slack', 'vscode']
LINUX_PROCESSES = ['sshd', 'nginx', 'apache2', 'cron']

# --- Event Types for Network Activity ---
BASE_ACTIVITY_WEIGHTS = {
    'dns_query': 0.70,
    'connection_established': 0.255,
    'file_transfer': 0.04,
    'policy_violation': 0.005  # Benign noise
}
ACTIVITY_EVENT_TYPES = list(BASE_ACTIVITY_WEIGHTS.keys())
ACTIVITY_EVENT_WEIGHTS = list(BASE_ACTIVITY_WEIGHTS.values())

BENIGN_DNS_DOMAINS = ['google.com', 'office365.com', 'salesforce.com', 'github.com', 'internal.wiki.com', 'google-analytics.com', 'youtube.com']
BENIGN_COMMANDS = ['ipconfig /all', 'ping 8.8.8.8', 'ls -la /home', 'df -h', 'hostname']
NORMAL_USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"]

# --- IP Pool for Session Management ---
AVAILABLE_INTERNAL_IPS = set([f"10.1.{random.randint(0, 255)}.{random.randint(2, 254)}" for _ in range(200)])
USER_PROFILES = {}

# --- User Profile Generation ---
def create_user_profiles():
    global USER_PROFILES
    logging.info("Creating realistic user profiles...")
    for user in BENIGN_USERS:
        if 'svc_' in user or 'admin' in user:
            primary_device = random.choice(SERVER_DEVICES)
            os_type = "Linux"
        elif random.random() < 0.2:
            primary_device = random.choice(MACOS_DEVICES)
            os_type = "macOS"
        else:
            primary_device = random.choice(WINDOWS_DEVICES)
            os_type = "Windows"

        USER_PROFILES[user] = {
            "primary_device": primary_device,
            "os": os_type,
            "public_ip": f"74.125.{random.randint(0,255)}.{random.randint(0,255)}", # A simulated public IP
            "current_internal_ip": None, # User starts as logged out
            "last_login_time": None
        }
    logging.info(f"Created {len(USER_PROFILES)} user profiles.")

# --- Event Generation Logic ---
def generate_and_route_events():
    """
    Stateful event generator.
    Generates a login event if user is logged out.
    Generates network activity if user is logged in.
    Returns a tuple: (access_event, network_event)
    """
    chosen_user = random.choice(list(USER_PROFILES.keys()))
    profile = USER_PROFILES[chosen_user]
    now = datetime.datetime.now(datetime.timezone.utc)

    # --- Case 1: User is Logged IN ---
    if profile["current_internal_ip"]:
        # Logout probability from 0.1% to 5%
        # This creates shorter user sessions and generates "fresh"
        # login_success events more frequently for the continuous query.
        if random.random() < 0.05:
            AVAILABLE_INTERNAL_IPS.add(profile["current_internal_ip"])
            profile["current_internal_ip"] = None
            profile["last_login_time"] = None
            return (None, None)

        event_type = random.choices(ACTIVITY_EVENT_TYPES, weights=ACTIVITY_EVENT_WEIGHTS, k=1)[0]

        network_event = {
            "event_timestamp": now.isoformat(),
            "event_type": event_type,
            "user_id": chosen_user,
            "source_ip": profile["current_internal_ip"],
            "source_port": random.randint(1024, 65535),
            "destination_ip": f"10.100.{random.randint(0, 255)}.{random.randint(1, 254)}",
            "destination_port": random.choice([80, 443, 53, 22, 8080]),
            "protocol": random.choice(['TCP', 'UDP']),
            "bytes_transferred": random.randint(64, 1500000),
            "source_process_name": None,
            "network_domain": None,
            "file_name": None,
            "file_type": None,
            "command_line": None,
            "permission_level_requested": None,
            "file_hash_sha256": None
        }

        if profile["os"] == "Windows":
            network_event["source_process_name"] = random.choice(WINDOWS_PROCESSES)
        elif profile["os"] == "macOS":
            network_event["source_process_name"] = random.choice(MACOS_PROCESSES)
        else:
            network_event["source_process_name"] = random.choice(LINUX_PROCESSES)

        if event_type == 'dns_query':
            network_event["network_domain"] = random.choice(BENIGN_DNS_DOMAINS)
            network_event["destination_port"] = 53
            network_event["protocol"] = 'UDP'
        elif event_type == 'file_transfer':
            network_event['file_name'] = "archive.zip"
            network_event['file_type'] = "zip"
            network_event['file_hash_sha256'] = hashlib.sha256(str(random.random()).encode()).hexdigest()
        elif event_type == 'policy_violation':
            network_event['command_line'] = random.choice(BENIGN_COMMANDS)

        return (None, network_event)

    # --- Case 2: User is Logged OUT ---
    else:
        if not AVAILABLE_INTERNAL_IPS:
            logging.warning("No available internal IPs in pool!")
            return (None, None)

        access_event = {
            "event_timestamp": now.isoformat(),
            "event_type": None,
            "user_id": chosen_user,
            "source_ip": profile["public_ip"], # User's public IP
            "assigned_internal_ip": None,
            "device_id": profile["primary_device"],
            "device_os": "Windows 11" if profile["os"] == "Windows" else "macOS Sonoma",
            "user_agent": random.choice(NORMAL_USER_AGENTS),
            "application_name": random.choice(["Corporate-VPN", "Okta-SSO"])
        }

        if random.random() < 0.01: # 1% chance of benign login failure
            access_event["event_type"] = "login_failure"
        else: # 99% chance of success
            access_event["event_type"] = "login_success"
            new_ip = AVAILABLE_INTERNAL_IPS.pop() # Check out an IP
            access_event["assigned_internal_ip"] = new_ip
            # Update state
            profile["current_internal_ip"] = new_ip
            profile["last_login_time"] = now

        return (access_event, None)

# --- Global State Management ---
events_streamed_count = 0
events_failed_count = 0
start_time_global = time.time()

# --- Main streaming function ---
def stream_network_events_insertjson(rate: int):
    global events_streamed_count, events_failed_count, start_time_global
    create_user_profiles()

    try:
        client = bigquery.Client(project=PROJECT_ID, credentials=credentials)
        client.get_table(ACCESS_TABLE_ID)
        client.get_table(NETWORK_TABLE_ID)
        logging.info(f"Successfully connected to BigQuery.")
    except Exception as e:
        logging.error(f"Failed to initialize BigQuery client or find tables: {e}", exc_info=True)
        logging.error("Please ensure table IDs are correct and you have 'BigQuery Data Editor' permissions.")
        return

    logging.info(f"--- ✅ Starting Benign Traffic Streamer (v9 - No Location) ✅ ---")
    logging.info(f"Streaming Access Events to: {ACCESS_TABLE_ID}")
    logging.info(f"Streaming Network Events to: {NETWORK_TABLE_ID}")
    logging.info(">>> IMPORTANT: To stop, use Colab 'Interrupt execution' button <<<")
    last_report_time = time.time()

    try:
        while True:
            batch_start_time = time.time()
            access_events_batch = []
            network_events_batch = []

            for _ in range(rate):
                access_event, network_event = generate_and_route_events()
                if access_event:
                    access_events_batch.append(access_event)
                if network_event:
                    network_events_batch.append(network_event)

            all_errors = []

            if access_events_batch:
                errors = client.insert_rows_json(ACCESS_TABLE_ID, access_events_batch)
                if errors:
                    all_errors.extend(errors)
                    events_failed_count += len(access_events_batch)
                else:
                    events_streamed_count += len(access_events_batch)

            if network_events_batch:
                errors = client.insert_rows_json(NETWORK_TABLE_ID, network_events_batch)
                if errors:
                    all_errors.extend(errors)
                    events_failed_count += len(network_events_batch)
                else:
                    events_streamed_count += len(network_events_batch)

            if all_errors:
                logging.warning(f"Encountered {len(all_errors)} errors inserting rows: {all_errors[:5]}")

            time.sleep(max(0, 1.0 - (time.time() - batch_start_time)))

            if time.time() - last_report_time >= REPORTING_INTERVAL_SECONDS:
                elapsed_total = time.time() - start_time_global
                avg_rate = events_streamed_count / elapsed_total if elapsed_total > 0 else 0
                logging.info(f"Streamed: {events_streamed_count}, Failed: {events_failed_count}, Avg Rate: {avg_rate:.2f} evt/sec")
                last_report_time = time.time()

    except KeyboardInterrupt:
        logging.info("Shutdown signal received. Stopping streamer...")
    finally:
        elapsed_total = time.time() - start_time_global
        avg_rate = events_streamed_count / elapsed_total if elapsed_total > 0 else 0
        logging.info("--------------------")
        logging.info(f"Final Run Statistics: Total Time: {elapsed_total:.2f}s, Streamed: {events_streamed_count}, Failed: {events_failed_count}, Avg Rate: {avg_rate:.2f} evt/sec")
        logging.info("Streamer finished.")


if __name__ == "__main__":
    stream_network_events_insertjson(MESSAGES_PER_SECOND_TARGET)
