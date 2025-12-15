SELECT 
  device_id,
  -- How many times was this device flagged as a threat?
  COUNT(*) as suspicious_alert_count,
  -- What is the average risk score when it gets flagged?
  ROUND(AVG(total_2_min_threat_score), 1) as avg_risk_score,
  -- How many times did a human confirm it was actually malicious?
  COUNTIF(human_decision = 'GENUINE THREAT') as confirmed_actual_threats
FROM `Cymbal_Cyber.adk_threat_assessment`
WHERE 
  agent_decision = 'PERCEIVED_THREAT'
  AND device_id IS NOT NULL
GROUP BY 1
ORDER BY suspicious_alert_count DESC
LIMIT 5;
