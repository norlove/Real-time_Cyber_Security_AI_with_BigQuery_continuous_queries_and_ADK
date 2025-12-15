/* =================================================================================
* This query correlates successful user access events with subsequent network events
* in near-real-time using a continuous query performing an INNER JOIN.
* It aggregates correlated threat events by user over a 2-minute window
* and exports any user with a total threat score of 100 or more to Pub/Sub.
* =================================================================================
*/

EXPORT DATA
OPTIONS (
  format = CLOUD_PUBSUB,
  # --- UNIQUE PROJECT CONFIGURATION DETAILS BELOW ---
  uri = "https://pubsub.googleapis.com/projects/my-project/topics/cymbal_cyber_alerts"
  # --- UNIQUE PROJECT CONFIGURATION DETAILS ABOVE ---
)
AS (

  /* =================================================================================
  * CTE 1: Correlate Access and Network Events
  * ---------------------------------------------------------------------------------
  * This CTE reads from the raw event tables using APPENDS streaming read
  * and performs a stateful INNER JOIN to find network events that happen
  * near a successful login event from the same IP.
  * =================================================================================*/

  WITH CorrelatedEventScores AS (
    SELECT
      network._CHANGE_TIMESTAMP AS bq_changed_ts,
      access.user_id,
      access.device_id,
      access.source_ip,
      access.user_agent,
      network.event_type,
      network.permission_level_requested,
      network.file_type,
      network.command_line,
      network.network_domain,
      /* --- THREAT SCORING LOGIC ---
       * This block assigns a numerical risk score to each *correlated*
       * event pair. Scores are additive based on different risk indicators.*/
      (
        CASE
          WHEN network.event_type = 'policy_violation' THEN 50
          WHEN network.event_type = 'dns_query' AND REGEXP_CONTAINS(network.network_domain, r'(\.ru|\.xyz|\.org|bad-domain|payload-downloader|c2-server)') THEN 60
          ELSE 0
        END
        + CASE WHEN network.permission_level_requested IN ('root', 'admin') THEN 35 ELSE 0 END
        + CASE WHEN REGEXP_CONTAINS(access.user_agent, r'^(python-requests|curl|Go-http-client)') THEN 20 ELSE 0 END
        + CASE WHEN network.event_type = 'file_transfer' AND network.file_type IN ('exe', 'dll', 'ps1', 'bat', 'vbs') THEN 40 ELSE 0 END
        + CASE
            WHEN REGEXP_CONTAINS(network.command_line, r'(?i)(powershell -enc|IEX|DownloadString|mimikatz|payload)') THEN 100
            WHEN REGEXP_CONTAINS(network.command_line, r'^(ipconfig|ping|ls -la|df -h|hostname)') THEN 0
            WHEN network.command_line IS NOT NULL THEN 10
            ELSE 0
          END
      ) AS event_score
    FROM
      APPENDS(TABLE `Cymbal_Cyber.user_access_events`, CURRENT_TIMESTAMP() - INTERVAL 10 MINUTE) AS access
    INNER JOIN
      APPENDS(TABLE `Cymbal_Cyber.network_events`, CURRENT_TIMESTAMP() - INTERVAL 10 MINUTE) AS network
      -- THE JOIN KEY: Join on the assigned IP
      ON access.assigned_internal_ip = network.source_ip
    WHERE
      access.event_type = 'login_success'
      /* --- TEMPORAL JOIN CONDITION ---
       * This is the stateful constraint. It ensures we only join network events
       * whose *ingestion time* (_CHANGE_TIMESTAMP) falls within a window
       * around the *login event's* ingestion time (from 5 min before to 60 min after).*/
      AND network._CHANGE_TIMESTAMP BETWEEN TIMESTAMP_SUB(access._CHANGE_TIMESTAMP, INTERVAL 5 MINUTE) AND TIMESTAMP_ADD(access._CHANGE_TIMESTAMP, INTERVAL 60 MINUTE)
  ),

  /* =================================================================================
  * CTE 2: Aggregate Correlated Events into User-Windows
  * ---------------------------------------------------------------------------------
  * This CTE takes the correlated, scored events from CTE 1 and aggregates
  * them into 2-minute, non-overlapping "tumbling" windows based on
  * the bq_changed_ts (ingestion time).
  * =================================================================================*/
  UserAggregates AS (
    SELECT
      window_end,
      user_id,
      ANY_VALUE(device_id) AS device_id,
      ANY_VALUE(source_ip) AS source_ip,
      SUM(event_score) AS total_2_min_threat_score,
      MAX(event_score) AS max_event_score,
      ROUND(AVG(event_score),2) AS avg_event_score,
      COUNTIF(permission_level_requested IN ('root', 'admin')) AS high_privilege_request_count,
      COUNTIF(REGEXP_CONTAINS(user_agent, r'^(python-requests|curl|Go-http-client)')) AS suspicious_user_agent_count,
      COUNTIF(file_type IN ('exe', 'dll', 'ps1', 'bat', 'vbs')) AS risky_file_transfer_count,
      COUNTIF(REGEXP_CONTAINS(command_line, r'(?i)(powershell -enc|IEX|DownloadString|mimikatz|payload)')) AS malicious_command_count,
      COUNTIF(REGEXP_CONTAINS(network_domain, r'(\.ru|\.xyz|\.org|bad-domain|payload-downloader|c2-server)')) AS malicious_dns_count
    FROM
      -- Tumble over the change timestamp, creating 2-minute-wide windows
      TUMBLE(TABLE CorrelatedEventScores, "bq_changed_ts", INTERVAL 2 MINUTE)
    GROUP BY
      window_end,
      user_id
  )

/* =================================================================================
 * FINAL SELECT: Format and Filter for Export
 * ---------------------------------------------------------------------------------
 * This final step formats the aggregated data as a single JSON string
 * (required for the Pub/Sub sink) and filters out any windows
 * that do not meet the minimum threat score threshold.
 * =================================================================================*/
SELECT
  TO_JSON_STRING(
    STRUCT(
      window_end,
      user_id,
      device_id,
      source_ip,
      total_2_min_threat_score,
      max_event_score,
      avg_event_score,
      high_privilege_request_count,
      suspicious_user_agent_count,
      risky_file_transfer_count,
      malicious_command_count,
      malicious_dns_count
  )) as data
FROM
  UserAggregates
WHERE
  -- This is the final alert threshold. Only windows where a user's
  -- total score meets this threshold will be sent to Pub/Sub.
  total_2_min_threat_score >= 100
);
