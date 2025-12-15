SELECT
   COALESCE(JSON_VALUE(content, '$.tool_name'), JSON_VALUE(content, '$.tool')) AS tool_name,
   COUNT(*) AS total_finished_runs,
   COUNTIF(event_type = 'TOOL_ERROR' OR REGEXP_CONTAINS(TO_JSON_STRING(content), r'(?i)\berror\b')) AS failure_count
FROM
   `Cymbal_Cyber.agent_events`
WHERE
   event_type IN ('TOOL_COMPLETED', 'TOOL_ERROR')
GROUP BY
   1
