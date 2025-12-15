"""
Defines the collection of tools available to the Cymbal Cyber ADK Agent.

Each function in this file represents a distinct capability that the agent can
call upon to interact with external systems like BigQuery, Cloud Storage, and
Vertex AI models to gather information and perform actions.
"""
import os
import json
import time
import re
from datetime import datetime, timezone, timedelta
import google.auth
from google.auth import impersonated_credentials
from google.cloud import bigquery, storage
from google import genai
from google.genai import types

# --- Configuration details ---
# --- UNIQUE PROJECT CONFIGURATION DETAILS BELOW ---
PROJECT_ID = 'bigquery-demos-project'
LOCATION = 'us-central1'
BIGQUERY_ADK_THREAT_ASSESSMENT = "bigquery-demos-project.Cymbal_Cyber.adk_threat_assessment"
GCS_ESCALATION_BUCKET = "cymbal-cyber-adk-escalations-bucket_bigquery-demos-project" 
GCS_SIGNER_SERVICE_ACCOUNT = "bq-continuous-query-sa@bigquery-demos-project.iam.gserviceaccount.com"
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
# --- UNIQUE PROJECT CONFIGURATION DETAILS ABOVE ---

# Initialize the GenAI Client (Updated from legacy Vertex AI SDK)
client = genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)

bq_client = bigquery.Client()

# --- Helper Function for Data Parsing ---
def _parse_alert_payload_to_row(alert_payload_str: str) -> dict:
    """
    Parses the JSON string payload and extracts fields to match the 
    'adk_threat_assessment' BigQuery table schema.
    """
    row = {
        "transaction_window_end": None,
        "user_id": None,
        "device_id": None,
        "source_ip": None,
        "total_2_min_threat_score": None,
        "alert_payload": alert_payload_str,
        # Initialize decision columns to None
        "agent_decision": None,
        "agent_reason": None,
        "human_decision": None,
        "human_reason": None
    }
    
    try:
        data = json.loads(alert_payload_str)
        row["user_id"] = data.get("user") or data.get("user_id")
        row["device_id"] = data.get("device") or data.get("device_id")
        row["source_ip"] = data.get("ip_address") or data.get("source_ip")
        row["total_2_min_threat_score"] = data.get("threat_score") or data.get("total_2_min_threat_score")
        
        ts_str = data.get("window_end") or data.get("transaction_window_end")
        if ts_str:
            row["transaction_window_end"] = ts_str
            
    except json.JSONDecodeError:
        print(f"Error decoding alert_payload JSON: {alert_payload_str[:50]}...")
    except Exception as e:
        print(f"Error parsing payload for row: {e}")
        
    return row

def create_rich_ticket_id(user_id: str) -> str:
    """
    Generates a standardized, readable ticket ID. 
    
    Includes sanitation to prevent the Agent from accidentally passing 
    JSON objects or invalid characters as the ticket_id.
    
    Args:
        user_id (str): The user associated with the event (e.g., 'u.lewis').
                       If a full JSON string is passed by mistake, it will be sanitized.
    """
    if not user_id:
        clean_user = "unknown_user"
    else:
        match = re.match(r"^[a-zA-Z0-9\.]+", str(user_id))
        clean_user = match.group(0) if match else "invalid_id"

    timestamp = int(time.time())
    return f"ticket-{clean_user}-{timestamp}"
  
def build_event_logs_query(entity_type: str, entity_id: str, window_to_investigate: str):
  """
  Generates an SQL query to fetch event logs for a specific entity.
  """
  print(f"Building 24-hour SQL threat profile for entity: {entity_id}...")
  
  sql_query = rf"""
    -- (Query content remains exactly the same as before)
    WITH
    FlaggedSessions AS (
        SELECT DISTINCT
        assigned_internal_ip
        FROM
        `Cymbal_Cyber.user_access_events`
        WHERE
        event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
        AND event_type = 'login_success'
        AND user_id = '{entity_id}'
    ),
    AccessMetrics AS (
        SELECT
        COUNT(*) AS total_access_events_24h,
        COUNTIF(event_type = 'login_failure') AS total_login_failures_24h,
        COUNT(DISTINCT source_ip) AS distinct_public_source_ips_24h,
        COUNTIF(REGEXP_CONTAINS(user_agent, r'^(python-requests|curl|Go-http-client)')) AS suspicious_user_agent_logins_24h,
        COUNT(DISTINCT user_agent) AS distinct_user_agents_used_24h
        FROM
        `Cymbal_Cyber.user_access_events`
        WHERE
        event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
        AND user_id = '{entity_id}'
    ),
    NetworkMetrics AS (
        SELECT
        COUNT(*) AS total_network_events_24h,
        COUNTIF(permission_level_requested IN ('root', 'admin')) AS high_privilege_requests_24h,
        COUNTIF(file_type IN ('exe', 'dll', 'ps1', 'bat', 'vbs')) AS risky_file_transfers_24h,
        COUNTIF(REGEXP_CONTAINS(command_line, r'(?i)(powershell -enc|IEX|DownloadString|mimikatz|payload)')) AS malicious_commands_24h,
        COUNTIF(REGEXP_CONTAINS(network_domain, r'(\.ru|\.xyz|\.org|bad-domain|payload-downloader|c2-server)')) AS malicious_dns_queries_24h,
        COUNT(DISTINCT destination_ip) AS distinct_destination_ips_24h,
        COUNT(DISTINCT file_hash_sha256) AS distinct_files_transferred_24h
        FROM
        `Cymbal_Cyber.network_events`
        WHERE
        event_timestamp >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 24 HOUR)
        AND (
            user_id = '{entity_id}'
            OR source_ip IN (SELECT assigned_internal_ip FROM FlaggedSessions)
        )
    )
    SELECT
    *
    FROM
    AccessMetrics
    CROSS JOIN NetworkMetrics;
    """
  return sql_query


def get_visual_analysis_for_user(gcs_uri: str) -> str:
    """
    Analyzes a screenshot at the provided GCS URI for security threats using
    a multimodal model.
    """
    if not gcs_uri or not gcs_uri.startswith("gs://"):
        return f"Cannot perform visual analysis. Invalid or missing GCS URI: {gcs_uri}"

    print(f"Sending screenshot {gcs_uri} to multi-modal model for analysis...")
    try:
        prompt_text = """
        You are a senior SOC analyst. This screenshot is the only visual context for a
        high-risk security alert associated with this user. Analyze the image and provide a
        concise, one-paragraph summary for an escalation report.
        Perform OCR on any terminals or command prompts. Note if the visual evidence
        confirms or contradicts suspicious activity. Note any other unusual applications,
        pop-ups, or error messages that are relevant to a security investigation.
        """
        
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=[
                types.Part.from_uri(
                    file_uri=gcs_uri, 
                    mime_type="image/png"
                ),
                types.Part.from_text(text=prompt_text)
            ]
        )
        
        analysis_text = response.text.strip()
        print(f"Received analysis from model: {analysis_text}")
        return analysis_text
    except Exception as e:
        return f"An error occurred during the visual analysis: {e}"


def get_gcs_uri_for_user(user: str) -> str:
    """
    Finds the GCS URI of a screenshot for a user with a recent high-risk event.
    """
    print(f"Searching for visual evidence GCS URI for user: {user}")
    sql = f"""
        SELECT
            t2.gcs_uri
        FROM `Cymbal_Cyber.user_access_events` AS t1
        JOIN `Cymbal_Cyber.user_screenshots_view` AS t2 ON t1.user_id = t2.user_id
        WHERE
            t1.user_id = '{user}'
        LIMIT 1;
    """
    try:
        query_job = bq_client.query(sql)
        results = list(query_job.result())

        if not results:
            return "No recent high-risk events with associated visual evidence found for this user."

        gcs_uri = results[0].gcs_uri
        print(f"Found associated screenshot for user {user} at: {gcs_uri}")
        return gcs_uri
    except Exception as e:
        return f"An error occurred while querying for the GCS URI: {e}"


def generate_signed_url(gcs_uri: str) -> str:
    """
    Generates a temporary URL for a GCS object using explicit
    Impersonated Credentials for keyless signing.
    """
    if not gcs_uri or not gcs_uri.startswith("gs://"):
        return "Invalid GCS URI provided."
        
    try:
        source_credentials, project = google.auth.default()
        target_credentials = impersonated_credentials.Credentials(
            source_credentials=source_credentials,
            target_principal=GCS_SIGNER_SERVICE_ACCOUNT,
            target_scopes=["https://www.googleapis.com/auth/devstorage.read_write"],
            lifetime=300,
        )
        storage_client = storage.Client(credentials=target_credentials)
        bucket_name, object_name = gcs_uri.replace("gs://", "").split("/", 1)
        bucket = storage_client.bucket(bucket_name)
        blob = bucket.blob(object_name)
        
        signed_url = blob.generate_signed_url(
            version="v4",
            expiration=timedelta(minutes=15),
            service_account_email=GCS_SIGNER_SERVICE_ACCOUNT
        )
        print(f"Generated signed URL for {gcs_uri} using explicit impersonation.")
        return signed_url
        
    except Exception as e:
        return f"Error generating signed URL: {e}"

def log_false_positive(alert_payload: str, agent_comment: str) -> str:
    """
    Logs the alert as a False Positive in the single ADK output table.
    """
    print(f"Logging false positive: {alert_payload}")
    try:
        row_data = _parse_alert_payload_to_row(alert_payload)
        row_data["agent_decision"] = "FALSE_POSITIVE"
        row_data["agent_reason"] = agent_comment
        row_data["human_decision"] = None
        row_data["human_reason"] = None
        
        errors = bq_client.insert_rows_json(BIGQUERY_ADK_THREAT_ASSESSMENT, [row_data])
        return "Successfully logged the alert as a false positive." if not errors else f"Failed to log false positive. Errors: {errors}"
    except Exception as e:
        return f"Error logging false positive: {e}"

def escalate_to_human(
    ticket_id: str,
    alert_payload: str,
    agent_reason_for_escalation: str,
    context_data: str
) -> str:
    """
    Logs an escalation to BigQuery and initiates a human handoff via GCS file exchange.
    This function uses GCS as a message queue for the human-in-the-loop workflow.
    """
    storage_client = storage.Client()
    bucket = storage_client.bucket(GCS_ESCALATION_BUCKET)

    # 1. Create and upload the escalation request
    request_filename = f"human_escalation_information_{ticket_id}.json"
    request_payload = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ticket_id": ticket_id,
        "context_for_human": context_data,
        "agent_reason_for_escalation": agent_reason_for_escalation
    }
    blob_request = bucket.blob(request_filename)
    blob_request.upload_from_string(
        data=json.dumps(request_payload, indent=2),
        content_type="application/json"
    )
    
    # 2. Polling Loop
    response_filename = f"human_escalation_response_{ticket_id}.json"
    print(f"Human handoff request sent. Waiting for a response in gs://{GCS_ESCALATION_BUCKET}/{response_filename}")

    blob_response = bucket.blob(response_filename)
    timeout_seconds = 300
    start_time = time.time()

    while time.time() - start_time < timeout_seconds:
        if blob_response.exists():
            print("Human response file found!")
            
            # Process response
            response_data = json.loads(blob_response.download_as_string())
            human_decision = response_data.get("human_decision", "No decision found.")
            human_comment = response_data.get("human_comment", "") 

            print(f"Logging human decision to BigQuery for ticket {ticket_id}...")
            
            # Log successful human interaction
            log_status = log_human_decision(
                ticket_id=ticket_id,
                human_decision=human_decision,
                human_comment=human_comment,
                alert_payload=alert_payload,
                agent_reason_for_escalation=agent_reason_for_escalation
            )
            print(log_status)

            # Cleanup
            print("Cleaning up handoff files...")
            blob_request.delete()
            blob_response.delete()
            
            return f"Human Approver responded with '{human_decision}'. Decision has been logged to BigQuery."

        time.sleep(2)

    print("Human response timed out.")
    
    # Log the unacknowledged event to BigQuery BEFORE deleting the file
    print(f"Logging unacknowledged event for ticket {ticket_id}...")
    log_status = log_human_decision(
        ticket_id=ticket_id,
        human_decision="Event not categorized in time",
        human_comment="N/A",
        alert_payload=alert_payload,
        agent_reason_for_escalation=agent_reason_for_escalation
    )
    print(log_status)

    # Cleanup the request file
    print("Cleaning up the request file.")
    if blob_request.exists():
        blob_request.delete()
        
    return "Human review timed out after 5 minutes. Event logged as 'Event not categorized in time'."


def log_human_decision(ticket_id: str, human_decision: str, human_comment: str, alert_payload: str, agent_reason_for_escalation: str) -> str:
    """
    Updates an existing escalation record with a human's decision and comments
    into the single ADK output table.
    """
    print(f"Logging human decision....{human_decision}")
    try:
        row_data = _parse_alert_payload_to_row(alert_payload)

        # 1. Agent Decision is explicitly PERCEIVED_THREAT 
        row_data["agent_decision"] = "PERCEIVED_THREAT"
        row_data["agent_reason"] = agent_reason_for_escalation
        
        # 2. Human Decision is logged
        row_data["human_decision"] = human_decision 
        row_data["human_reason"] = human_comment

        errors = bq_client.insert_rows_json(BIGQUERY_ADK_THREAT_ASSESSMENT, [row_data])
        return "Successfully logged human decision." if not errors else f"Failed to log human decision. Errors: {errors}"
    
    except Exception as e:
        return f"Error updating escalation: {e}"
