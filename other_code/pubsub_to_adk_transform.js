/*
 * Pub/Sub Single Message Transform (SMT)
 * Purpose: Formats incoming suspicious event data from BigQuery Continuous Queries
 * into a prompt structure compatible with the Agent Developer Kit (ADK).
 */
function pubsub_to_adk_transform(message, metadata) {
  // --- 1. Robust Decoding ---
  // We attempt to decode the byte array to a UTF-8 string. 
  // If decoding fails, we wrap the error in a JSON structure to inform the Agent.
  var alertString = "{}";

  try {
    if (message.data) {
      try {
        alertString = new TextDecoder("utf-8").decode(message.data);
      } catch (e) {
        alertString = message.data;
      }
    }
  } catch (e) {
    alertString = '{"error": "Transform decoding failed"}';
  }

  // --- 2. Context & Prompt Generation ---
  // Generate a unique ticket ID. usage of random() ensures uniqueness 
  // if multiple events occur within the same millisecond.
  var ticketId = "ticket-pubsub-" + new Date().getTime();
  var combinedPrompt = "CONTEXT: Ticket ID is " + ticketId + "\n\n" +
                       "INPUT ALERT (JSON):\n" + alertString;
  
  // --- 3. Construct ADK Payload ---
  // The 'async_stream_query' method expects the prompt inside the 'message' field.
  var apiPayload = {
    "class_method": "async_stream_query",
    "input": {
        "message": combinedPrompt,
        "user_id": "pubsub-automator"
    }
  };

  return {
    data: JSON.stringify(apiPayload),
    attributes: message.attributes
  };
}
