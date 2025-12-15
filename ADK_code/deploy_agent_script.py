"""
Deployment Script for ADK Agent
===============================
This script packages and deploys the local ADK Agent to Vertex AI as a persistent service.
It handles:
1. Configuration of the Vertex AI environment.
2. Packaging local code (plugins/agents) for upload.
3. defining runtime requirements (libraries).
4. Returning the invocation URL for Pub/Sub configuration.
"""

import vertexai
from vertexai import agent_engines
from google.adk.sessions.vertex_ai_session_service import VertexAiSessionService
from bigquery_agent_app.implicit_session_service import ImplicitSessionService
from bigquery_agent_app.agent import root_agent, bq_analytics_plugin 
import os

# --- UNIQUE PROJECT CONFIGURATION DETAILS BELOW ---
LOCATION = "us-central1"
STAGING_BUCKET = "gs://cymbal_cyber_adk_staging_bucket_bigquery-demos-project"
PROJECT_ID = "bigquery-demos-project"
SERVICE_ACCOUNT = "bq-continuous-query-sa@bigquery-demos-project.iam.gserviceaccount.com"
# --- UNIQUE PROJECT CONFIGURATION DETAILS ABOVE ---

# Global service instance to avoid recreation
_session_service = None

def get_session_service():
    """
    Builder function required by the AdkApp wrapper.
    It configures how the agent persists conversation state (Memory).
    """
    global _session_service
    if _session_service is None:
        vertex_session_service = VertexAiSessionService(
            project=PROJECT_ID,
            location=LOCATION,
        )
        # Wrap it so it automatically creates sessions for new users
        _session_service = ImplicitSessionService(vertex_session_service)
    return _session_service

def deploy_agent() -> str:
    """
    Deploys the agent to Vertex AI Agent Engines.
    Returns: The full resource name of the deployed application.
    """
    vertexai.init(
        project=PROJECT_ID,
        location=LOCATION,
        staging_bucket=STAGING_BUCKET,
    )
    
    # 1. Wrap your existing root_agent in the AdkApp standard wrapper
    app = agent_engines.AdkApp(
        agent=root_agent,
        enable_tracing=True,
        session_service_builder=get_session_service,
        plugins=[bq_analytics_plugin] 
    )

    # 2. Deploy using the verified requirements
    remote_app = agent_engines.create(
        app,
        display_name="bq_cq_app_v002",
        requirements=[
            "google-cloud-aiplatform[adk,agent_engines]>=1.119.0", 
            "google-adk>=1.15.1",
            "google-cloud-pubsub>=2.31.1",
            "google-genai",
            "google-cloud-logging",
            "google-cloud-bigquery",
            "google-cloud-storage",
            "db-dtypes",
            "pandas",
            "cloudpickle>=3.0.0", 
            "pydantic>=2.0.0"
        ],
        extra_packages=["./bigquery_agent_app"],
        env_vars = {
            "BIGQUERY_PROJECT_ID": PROJECT_ID,
            "GEMINI_MODEL": "gemini-2.5-flash",
            "OTEL_SDK_DISABLED": "true"            
        },
        service_account=SERVICE_ACCOUNT 
    )
    return remote_app.resource_name

if __name__ == "__main__":
    try:
        resource_name = deploy_agent()
        
        print(f"\n--- Deployment Complete! ---")
        print(f"RESOURCE_NAME: {resource_name}")
        
        # Construct the URL for the Pub/Sub Subscription
        api_endpoint = f"https://{LOCATION}-aiplatform.googleapis.com/v1/{resource_name}:streamQuery"
        
        print(f"\n[IMPORTANT] Save this URL for your Pub/Sub Push Endpoint (Note the ':streamQuery' at the end):")
        print(api_endpoint)
        print(f"\nDon't forget to update your 'adk_agent_trigger' Pub/Sub subscription with this URL!")
        
    except Exception as e:
        print(f"\n[ERROR] Deployment failed: {e}")
