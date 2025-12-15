"""
Local Runner for ADK Agent
==========================
This script simulates the production pipeline locally. It allows you to:
1. Select a mock alert (Malicious vs Benign).
2. Wrap it in the same context format as the production Pub/Sub SMT.
3. Spin up the Agent Runner with the BigQuery Plugin.
4. Stream the response back to the console.
"""

import os
import asyncio
import uuid
import logging
import json
from dotenv import load_dotenv
import google.cloud.logging
from google.cloud.logging.handlers import CloudLoggingHandler
from google.genai import types

# --- ADK Imports ---
from google.adk.sessions import InMemorySessionService
from google.adk.runners import Runner

# --- Local Imports ---
from bigquery_agent_app.agent import root_agent, bq_analytics_plugin
from bigquery_agent_app.logging_utils import setup_logging, log_agent_event

load_dotenv()

APP_NAME = "bigquery_app"
USER_ID = "local_analyst_1"

# --- 1. Malicious Alert mock data (u.lewis) ---
MALICIOUS_ALERT = json.dumps({
    "window_end": "2025-12-09T17:42:00Z",
    "user_id": "u.lewis",
    "device_id": "ws-hr-05",
    "source_ip": "175.45.177.32",
    "total_2_min_threat_score": 3000,
    "max_event_score": 205,
    "avg_event_score": 115.38,
    "high_privilege_request_count": 8,
    "suspicious_user_agent_count": 26,
    "risky_file_transfer_count": 4,
    "malicious_command_count": 8,
    "malicious_dns_count": 14
})

# --- 2. Benign Alert mock data (l.taylor) ---
BENIGN_ALERT = json.dumps({
    "window_end": "2025-12-09T17:34:00Z",
    "user_id": "l.taylor",
    "device_id": "ws-hr-01",
    "source_ip": "74.125.49.231",
    "total_2_min_threat_score": 300,
    "max_event_score": 50,
    "avg_event_score": 0.2,
    "high_privilege_request_count": 0,
    "suspicious_user_agent_count": 0,
    "risky_file_transfer_count": 0,
    "malicious_command_count": 0,
    "malicious_dns_count": 0
})

async def run_conversation(message_payload: str):
   """
   Sets up the agent execution environment using the Runner + Plugin pattern.
   """
   try:      
       log_agent_event(message=f"Invoking adk app locally...")
       
       session_service = InMemorySessionService()
       session_id = f"{APP_NAME}-{uuid.uuid4().hex[:8]}"
       initial_state = {"ticket_id": f"ticket-{session_id}"}
       
       session = await session_service.create_session(
           app_name=APP_NAME,
           user_id=USER_ID,
           session_id=session_id,
           state=initial_state
       )
       
       log_agent_event(message=f"Session created: {session_id}")

       runner = Runner(
           agent=root_agent,
           app_name=APP_NAME, 
           session_service=session_service,
           plugins=[bq_analytics_plugin] 
       )
       
       log_agent_event(message=f"Runner created with BigQuery Analytics Plugin.")      

       # Log the incoming alert payload
       log_agent_event(message=f"\n[>>>] INCOMING ALERT PAYLOAD:\n{message_payload}\n")
       
       content = types.Content(role='user', parts=[types.Part(text=message_payload)])
       
       async for event in runner.run_async(
           user_id=USER_ID, 
           session_id=session_id, 
           new_message=content
       ):
          if event.is_final_response():
              if event.content and event.content.parts:
                  final_response_text = event.content.parts[0].text
                  log_agent_event(message=f"Final response provided: {final_response_text}")

   except Exception as e:
       log_agent_event(message=f"An error occurred: {e}")
       import traceback
       traceback.print_exc()

if __name__ == '__main__':
    setup_logging()
    
    print("\n--- Local Agent Runner ---")
    print("1. Run Malicious Alert (u.lewis)")
    print("2. Run Benign Alert (l.taylor)")
    choice = input("Select an option (1 or 2): ").strip()
    
    if choice == "2":
        print("\n[Running BENIGN Alert]...")
        selected_payload = BENIGN_ALERT
    else:
        print("\n[Running MALICIOUS Alert]...")
        selected_payload = MALICIOUS_ALERT
    
    try:
        asyncio.run(run_conversation(selected_payload))
        
        log_agent_event(message="\n--- Agent Run Complete! ---")
        
        for handler in logging.getLogger().handlers:
            if isinstance(handler, CloudLoggingHandler):
                handler.flush()
                handler.close()
                print("Successfully flushed and closed CloudLoggingHandler.")
                
    except Exception as e:
        print(f"Script finished with exception: {e}")
    finally:
        logging.shutdown()
