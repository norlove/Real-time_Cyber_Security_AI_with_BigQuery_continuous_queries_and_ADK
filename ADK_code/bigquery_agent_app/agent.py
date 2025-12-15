"""
Defines the structure and logic of the multi-agent system for Cymbal Cyber.
"""
import re
import os
import json
import warnings
from typing import Dict, Any, Optional

# --- ADK Imports ---
from google.adk.agents import Agent, SequentialAgent, ParallelAgent
from google.adk.tools import BaseTool, FunctionTool, ToolContext, google_search
from google.adk.tools.bigquery import BigQueryToolset
from google.adk.apps import App
from google.adk.plugins.bigquery_agent_analytics_plugin import BigQueryAgentAnalyticsPlugin
from google.adk.agents.callback_context import CallbackContext

# --- Local Imports ---
from bigquery_agent_app.logging_utils import setup_logging, log_agent_event
from .tools import (
    build_event_logs_query, log_false_positive, escalate_to_human, 
    log_human_decision, create_rich_ticket_id, get_visual_analysis_for_user, 
    get_gcs_uri_for_user, generate_signed_url
)

# --- Configuration ---
# --- UNIQUE PROJECT CONFIGURATION DETAILS BELOW ---
PROJECT_ID = os.getenv("GOOGLE_CLOUD_PROJECT", "bigquery-demos-project")
# --- UNIQUE PROJECT CONFIGURATION DETAILS ABOVE ---
DATASET_ID = os.getenv("BIGQUERY_DATASET", "Cymbal_Cyber")
MODEL_NAME = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

# --- Warning Suppression ---
warnings.filterwarnings("ignore", category=UserWarning, module="vertexai")
warnings.filterwarnings("ignore", category=UserWarning, module="google.adk")

setup_logging()

# --- Initialize Plugin ---
bq_analytics_plugin = BigQueryAgentAnalyticsPlugin(
    project_id=PROJECT_ID,
    dataset_id=DATASET_ID, 
    table_id="agent_events" 
)

bigquery_toolset = BigQueryToolset()

# --- Custom Agent Classes  ---

class OrchestratorAgent(SequentialAgent):
    """
    A custom SequentialAgent that includes an 'instruction' field.
    
    Why this is needed:
    The BigQuery Analytics Plugin enforces that ALL agents must have an 'instruction' 
    attribute so it can log the agent's system prompt. Standard SequentialAgents 
    are purely routing logic and lack this field by default. This subclass 
    adds the field to the Pydantic schema to satisfy the plugin's validation requirements.
    """
    instruction: str = "Orchestrate the workflow between sub-agents."

class ParallelOrchestratorAgent(ParallelAgent):
    """
    A custom ParallelAgent that includes an 'instruction' field.
    
    Why this is needed:
    Similar to OrchestratorAgent, this ensures the parallel router has a valid
    'instruction' field for the analytics plugin to read and log without crashing.
    """
    instruction: str = "Run sub-agents in parallel."


# --- Agent Callback Functions ---
def forbidden_dml_check(tool: BaseTool, args: Dict[str, Any], tool_context: ToolContext) -> Optional[Dict]:
    """Inspects SQL queries before execution to prevent destructive operations."""
    safe_args_str = json.dumps(args, default=str)
    log_agent_event(message=f"Tool '{tool.name}' was called with args: \n{safe_args_str}\n")      

    if tool.name == 'execute_sql':
        try:
            sql_query = args.get('query')
            if sql_query:
                forbidden_dml = ['UPDATE', 'DELETE', 'MERGE', 'TRUNCATE']
                normalized_query = sql_query.upper().strip()
                if any(re.match(rf'\b{keyword}\b', normalized_query) for keyword in forbidden_dml):
                    return {"result": "Tool execution was blocked by before_tool_callback due to a DML statement."}
        except KeyError:
            return {"result": "Error: SQL query not provided in tool arguments."}
    return None

def before_sub_agent_starts(callback_context: CallbackContext):
    """Logs the start of any sub-agent."""
    log_agent_event(message=f"{callback_context.agent_name} Agent has been triggered")

def log_agent_completion(callback_context: CallbackContext):
    """Logs final output to catch silent failures."""
    output = getattr(callback_context, 'output', None) or getattr(callback_context, 'result', None)
    if output:
        log_agent_event(message=f"[{callback_context.agent_name}] FINISHED. Output:\n{output}")
    else:
        log_agent_event(message=f"[{callback_context.agent_name}] FINISHED.")

# --- Agent 1: Google Search Investigator ---
google_search_agent = Agent(
  model=MODEL_NAME,
  name="google_search_agent",
  description="Agent that researches IP addresses from security alerts.",
  instruction=(
        """
          You are an expert web researcher. Your task is to check the incoming security alert for IP addresses and then do a google search to check if they originate from high-risk countries like North Korea or Russia.
        
          **Instructions:**
          1.  **Extract IPs:** Identify and extract all IP addresses from the provided security alert.
          1.a  If no IP addresses are found, you do not need to do anything and can respond with: "No IP address present and so no suspicious IP addresses were found"
          2.  **Verify & Research:** For each IP, use web searches (e.g., IP lookup services, threat intelligence databases) to determine its:
              * Country of origin.
              * Associated threat intelligence.
          3.  Summarize your results and return it as an output for the decision agent 
        """
  ),
  output_key="google_search_results",
  before_agent_callback=before_sub_agent_starts,
  tools=[google_search]
)

# --- Agent 2: BigQuery Data Investigator ---
bq_investigation_agent = Agent(
  model=MODEL_NAME,
  name="bq_investigation_agent",
  description="Agent that answers questions about BigQuery data by executing SQL queries.",
  instruction=f"""
        You are a Level 1 Security Operations Center (SOC) analyst.
        Your goal is to triage the network security alert provided and determine if it is a false positive or genuine security threat.

        **IMPORTANT INSTRUCTIONS:**
        1. Use the `build_event_logs_query` tool to retrieve a query that creates a 24-hour behavioral profile for the entity.
        2. Execute the query and analyze the results returned.
        3. **Call the `get_gcs_uri_for_user` tool with the `user` from the alert to find the URI of any visual evidence.**
        4. **If a valid GCS URI is returned (starts with 'gs://'), call the `get_visual_analysis_for_user` tool PASSING THAT SPECIFIC URI AS THE ARGUMENT.**
        5. Use the analytical framework below to help distinguish the difference between a false positive and a genuine threat.
        6. Summarize all your results in the correct format. Your final output for the decision agent MUST be a single, valid JSON object string. This JSON object must contain two keys:
            - `summary`: A string containing your complete analysis and summary of all findings. You MUST include the text from the Google Search Agent and the visual analysis text.
            - `gcs_uri`: The string value of the GCS URI from the `get_gcs_uri_for_user` tool, or `null` if none was found.
        
        **OUTPUT FORMAT:**
        Return ONLY the raw JSON string. Do NOT use Markdown code blocks. Do NOT add preamble.

        **Analytical Framework: Threat vs. False Positive**
        * Look for signs of a Genuine Threat: Corroboration, Sustained Activity, Suspicious Location, Suspicious Screenshot.
        * Look for signs of a False Positive: Isolation, Benign Explanation, Benign Screenshot.

        NEVER, EVER DELETE OR MODIFY ANY EXISTING DATA IN BIGQUERY.
        All BigQuery queries MUST be run in the project-id: '{PROJECT_ID}' on the `{DATASET_ID}` dataset.
      """,
  tools=[get_visual_analysis_for_user, get_gcs_uri_for_user, bigquery_toolset, build_event_logs_query],
  before_tool_callback=forbidden_dml_check,
  before_agent_callback=before_sub_agent_starts,
  after_agent_callback=log_agent_completion,
  output_key="bigquery_investigation_results"
)

# --- Agent 3: Final Decision Maker ---
decision_agent = Agent(
  model=MODEL_NAME,
  name="decision_agent",
  description="Agent that consolidates findings and decides on best action to take.",
  instruction=(
     """
        You are the decision agent for the Security Operations Center (SOC).
        
        **INPUT DATA:**
        - Google Search Results: {google_search_results:}
        - Investigation Results: {bigquery_investigation_results:} (JSON object with 'summary' and 'gcs_uri')

        **YOUR GOAL:**
        Review the inputs and IMMEDIATELY trigger the correct workflow. If Investigation Results are missing or empty, this likely indicates a low-priority event or a system error.
        
        **RULES:**
        1. **NO CHIT-CHAT:** Do not output any conversational text directly to the user. 
        2. **TOOLS FIRST:** Your VERY FIRST output MUST be a tool call.
        3. **NO RAW JSON:** Never output raw JSON strings in the `context_data`. Always convert findings into clean, readable text.
        
        **DECISION LOGIC:**

        **IF THREAT DETECTED (ESCALATION_NEEDED):**
        1. Call `create_rich_ticket_id`.
        2. If `gcs_uri` is valid (starts with 'gs://'), call `generate_signed_url` to get a clickable HTTP link.
        3. Call `escalate_to_human`.

           **CRITICAL ARGUMENT RULES:**
           - `ticket_id`: You MUST use the output string from the `create_rich_ticket_id` tool. 
             NEVER use the "ticket-pubsub" ID found in the input context.
           - `context_data`: You must populate this argument with a **STRUCTURED REPORT** following this exact format:

           ### Security Incident Report
           
           **1. Alert Overview**
           * **User:** [User ID]
           * **Risk Score:** [Score]
           * **Decision:** [GENUINE THREAT / FALSE POSITIVE]
           
           **2. Key Findings (Behavioral)**
           * [Bullet point 1: Most critical anomaly (e.g. distinct IPs)]
           * [Bullet point 2: Other network metrics]
           * [Bullet point 3: Login failures or other risks]
           
           **3. Visual Analysis**
           * **Observation:** [Summary of visual findings]
           * **Screenshot:** [INSERT THE CLICKABLE HTTP LINK FROM generate_signed_url HERE]
           
           **4. External Intelligence**
           * [Summary of Google Search Results for the IP]

        **IF FALSE POSITIVE:**
        1. Call `log_false_positive` with a detailed explanation.

        **IF UNCERTAIN:**
        1. Treat as Escalation Needed and call `escalate_to_human` (using the Structured Report format above and passing the ticket id from `create_rich_ticket_id`).
      """
  ),
  tools=[generate_signed_url, bigquery_toolset, log_false_positive, escalate_to_human, log_human_decision, create_rich_ticket_id],
  before_tool_callback=forbidden_dml_check,
  before_agent_callback=before_sub_agent_starts,
  after_agent_callback=log_agent_completion
)

# --- Orchestration Agents (Using Custom Classes) ---

investigation_agent = ParallelOrchestratorAgent(
    name="InvestigationAgent",
    sub_agents=[bq_investigation_agent, google_search_agent],                 
    description="Executes the bigquery investigator agent and google search agent in parallel",
    instruction="Execute research and data gathering tasks simultaneously." 
)

root_agent = OrchestratorAgent(
    name="WorkflowAgent",
    sub_agents=[investigation_agent, decision_agent],        
    description="Executes a sequence of investigation agents and decision agents.",
    before_agent_callback=before_sub_agent_starts,
    instruction="Route the user request to the investigation team, then to the decision maker."
)

# --- App Definition ---
app = App(
    name="CymbalCyberSecurityAgent",
    root_agent=root_agent,
    plugins=[bq_analytics_plugin] 
)
