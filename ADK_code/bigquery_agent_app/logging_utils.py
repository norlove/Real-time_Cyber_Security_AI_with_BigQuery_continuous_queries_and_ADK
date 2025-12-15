"""
Utility functions for setting up and using structured logging with Google Cloud Logging.

This module ensures that logging is configured only once per application lifecycle
and provides a simple helper function to log events with dictionary payloads, which
appear as structured `jsonPayload` in the Cloud Logging console.
"""
import logging
from google.cloud.logging import Client as LoggingClient
from google.cloud.logging.handlers import CloudLoggingHandler, setup_logging as setup_gcp_logging

# A global flag to ensure the logging setup is only performed once.
_logging_setup_complete = False

def setup_logging():
    """
    Configures a handler to send Python logs to Google Cloud Logging.
    
    This function is idempotent; it uses a global flag to ensure that handlers
    are not added multiple times, which would cause duplicate log entries.
    """
    global _logging_setup_complete
    if _logging_setup_complete:
        return

    # Use a specific, named logger instead of the root logger. This is a best
    # practice to avoid interfering with or capturing logs from other libraries
    # (e.g., gunicorn, Flask) that use the standard logging module.
    log = logging.getLogger('cymbal-cyber-agent')
    log.setLevel(logging.INFO)
    
    # Explicitly create the client. This works in all environments.
    client = LoggingClient()

    # Create the handler, passing in the explicit client.
    handler = CloudLoggingHandler(client)
    setup_gcp_logging(handler)
    log.addHandler(handler)
    
    _logging_setup_complete = True

def log_agent_event(message: str, payload: dict = None):
    """
    Logs a message and an optional dictionary payload to Cloud Logging.

    This function provides a simple, consistent interface for creating structured
    logs throughout the application.

    Args:
        message (str): The primary log message.
        payload (dict, optional): A dictionary of key-value pairs to be included
                                  as structured data in the log entry.
    """
    log = logging.getLogger('cymbal-cyber-agent')
    # The CloudLoggingHandler will automatically format this as a JSON payload.
    log.info(message, extra={"json_fields": payload or {}})
