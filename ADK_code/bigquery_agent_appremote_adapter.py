"""
Defines the Adapter class that makes the ADK Agent compatible with
Vertex AI Reasoning Engines (Agent Engine).
"""
import uuid
import logging
import re
from typing import AsyncGenerator
from google.adk.sessions import InMemorySessionService
from google.adk.runners import Runner
from google.genai import types 
from .agent import root_agent, bq_analytics_plugin

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CymbalCyberAdapter:
    def __init__(self):
        self.app_name = "bq_cq_app_v001"
        self.project_id = "nickorlove-demos" 

    def set_up(self):
        """Called once at startup."""
        pass

    async def stream_query(self, message: dict, user_id: str = "pubsub_user") -> AsyncGenerator[str, None]:
        """
        The async entry point called by Vertex AI. 
        The SMT ensures 'message' is passed as a dictionary containing the prompt parts.
        """
        logger.info(f"Received request from user: {user_id}")
        
        try:
            # 1. Extract Text
            # We use safe .get() calls in case the payload structure varies slightly
            raw_text = ""
            if isinstance(message, dict):
                parts = message.get('parts', [])
                if parts and isinstance(parts, list):
                    raw_text = parts[0].get('text', '')
            
            if not raw_text:
                logger.warning("No text found in message parts. processing empty string.")

            # 2. Logic: Unwrap the Packet
            # 2.A. Find Ticket ID (if present in context)
            ticket_match = re.search(r"Ticket ID is ([\w-]+)", raw_text)
            if ticket_match:
                ticket_id = ticket_match.group(1)
            else:
                ticket_id = f"ticket-{uuid.uuid4().hex[:12]}"

            # 2.B. Extract Clean JSON (The Payload)
            json_start_index = raw_text.find('{')
            
            clean_payload = raw_text
            if json_start_index != -1:
                clean_payload = raw_text[json_start_index:]
                logger.info("Successfully unwrapped JSON payload.")
            else:
                logger.warning("Could not unwrap JSON. Passing raw text.")

            # 3. Setup Session
            session_service = InMemorySessionService()
            session_id = f"{self.app_name}-{uuid.uuid4().hex[:8]}"
            initial_state = {"ticket_id": ticket_id}

            await session_service.create_session(
                app_name=self.app_name,
                user_id=user_id,
                session_id=session_id,
                state=initial_state
            )

            # 4. Setup Runner
            runner = Runner(
                agent=root_agent,
                app_name=self.app_name, 
                session_service=session_service,
                plugins=[bq_analytics_plugin] 
            )

            # 5. Prepare Input
            content = types.Content(role='user', parts=[types.Part(text=clean_payload)])

            # 6. Run Agent
            async for event in runner.run_async(
                user_id=user_id, 
                session_id=session_id, 
                new_message=content
            ):
                if event.is_final_response():
                    if event.content and event.content.parts:
                        yield event.content.parts[0].text
                elif event.tool_use:
                    pass

        except Exception as e:
            logger.error(f"Critical Error in stream_query: {e}", exc_info=True)
            yield f"Error processing request: {str(e)}"
