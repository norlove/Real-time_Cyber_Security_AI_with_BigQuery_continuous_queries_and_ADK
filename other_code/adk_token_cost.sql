SELECT 
  agent,
  SUM(CAST(JSON_VALUE(content, '$.usage.prompt') AS INT64)) as prompt_tokens,
  SUM(CAST(JSON_VALUE(content, '$.usage.completion') AS INT64)) as completion_tokens,
  SUM(CAST(JSON_VALUE(content, '$.usage.total') AS INT64)) as total_tokens
FROM `Cymbal_Cyber.agent_events`
WHERE 
  event_type = 'LLM_RESPONSE'
GROUP BY 1
ORDER BY total_tokens DESC;
