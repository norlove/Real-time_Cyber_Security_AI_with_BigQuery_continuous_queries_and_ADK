SELECT 
  agent_decision,
  COUNT(*) as count,
  ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(), 1) as percentage
FROM `Cymbal_Cyber.adk_threat_assessment`
GROUP BY agent_decision
ORDER BY count DESC;
