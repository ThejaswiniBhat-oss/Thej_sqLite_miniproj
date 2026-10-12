-- =====================================================================
-- demo_queries.sql : paste into DB Browser for SQLite  ->  "Execute SQL" tab
--
-- HOW TO USE: DB Browser shows only the result of the LAST statement it runs,
-- so HIGHLIGHT ONE QUERY at a time (from its SELECT to its semicolon) and press
-- Ctrl+Return (or the blue play button). Only the highlighted text is executed.
--
-- These use the latest completed scan. Change the number in
--   (SELECT MAX(id) FROM scans WHERE status='completed')
-- to a specific scan id (e.g. 1) to look at an older scan.
-- =====================================================================


-- Q1. All scans (scan history). is_sample = 1 means SAMPLE data.
SELECT id, started_at, finished_at, status, scope, is_sample, notes
FROM scans ORDER BY started_at DESC;


-- Q2. Counts of every result status in the latest scan.
--     'not_checked' is its own row. It is NEVER counted as passed.
SELECT c.status, COUNT(*) AS results
FROM check_results c JOIN hosts h ON h.id = c.host_id
WHERE h.scan_id = (SELECT MAX(id) FROM scans WHERE status='completed')
GROUP BY c.status;


-- Q3. Failed findings by project severity (latest scan).
SELECT c.severity, COUNT(*) AS findings
FROM check_results c JOIN hosts h ON h.id = c.host_id
WHERE h.scan_id = (SELECT MAX(id) FROM scans WHERE status='completed')
  AND c.status = 'failed'
GROUP BY c.severity
ORDER BY CASE c.severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3
                         WHEN 'Medium' THEN 2 ELSE 1 END DESC;


-- Q4. Per-host compliance %.  compliance = passed / (passed + failed).
--     not_checked is excluded from the percentage but shown beside it,
--     and coverage_pct shows how much of the rulebook could be evaluated.
SELECT h.ip, h.hostname, h.winrm_status,
       SUM(c.status = 'passed')      AS passed,
       SUM(c.status = 'failed')      AS failed,
       SUM(c.status = 'not_checked') AS not_checked,
       ROUND(100.0 * SUM(c.status = 'passed')
             / NULLIF(SUM(c.status IN ('passed','failed')), 0), 1) AS compliance_pct,
       ROUND(100.0 * SUM(c.status IN ('passed','failed'))
             / NULLIF(COUNT(c.id), 0), 1)                          AS coverage_pct
FROM hosts h LEFT JOIN check_results c ON c.host_id = h.id
WHERE h.scan_id = (SELECT MAX(id) FROM scans WHERE status='completed')
GROUP BY h.id ORDER BY h.ip;


-- Q5. Findings with remediation (latest scan), worst first.
SELECT h.ip, h.hostname, c.rule_id, r.title, c.severity,
       c.observed_value, c.expected_value, r.remediation
FROM check_results c
JOIN hosts h ON h.id = c.host_id
JOIN rules r ON r.rule_id = c.rule_id
WHERE h.scan_id = (SELECT MAX(id) FROM scans WHERE status='completed')
  AND c.status = 'failed'
ORDER BY CASE c.severity WHEN 'Critical' THEN 4 WHEN 'High' THEN 3
                         WHEN 'Medium' THEN 2 ELSE 1 END DESC, h.ip;


-- Q6. Why was something NOT checked? (never shown as 'secure')
SELECT h.ip, c.rule_id, c.status, c.reason_not_checked
FROM check_results c JOIN hosts h ON h.id = c.host_id
WHERE h.scan_id = (SELECT MAX(id) FROM scans WHERE status='completed')
  AND c.status IN ('not_checked','error')
ORDER BY h.ip, c.rule_id;


-- Q7. Open ports per host (observations to review, NOT automatic vulnerabilities).
SELECT h.ip, h.hostname, p.port, p.protocol, p.state, p.service_name
FROM ports p JOIN hosts h ON h.id = p.host_id
WHERE h.scan_id = (SELECT MAX(id) FROM scans WHERE status='completed')
  AND p.state = 'open'
ORDER BY h.ip, p.port;


-- Q8. Trend: failed findings per completed scan (feeds the Chart.js line chart).
SELECT s.id AS scan_id, s.started_at,
       SUM(c.status = 'failed') AS failed_total,
       SUM(c.status = 'passed') AS passed,
       SUM(c.status IN ('not_checked','error')) AS not_checked
FROM scans s
LEFT JOIN hosts h ON h.scan_id = s.id
LEFT JOIN check_results c ON c.host_id = h.id
WHERE s.status = 'completed'
GROUP BY s.id ORDER BY s.started_at;


-- Q9. Repeat offenders: same host failed the same rule in 2+ completed scans.
SELECT h.ip, c.rule_id, r.title, COUNT(DISTINCT s.id) AS scans_failed,
       MIN(s.started_at) AS first_seen, MAX(s.started_at) AS last_seen
FROM check_results c
JOIN hosts h ON h.id = c.host_id
JOIN scans s ON s.id = h.scan_id
JOIN rules r ON r.rule_id = c.rule_id
WHERE c.status = 'failed' AND s.status = 'completed'
GROUP BY h.ip, c.rule_id
HAVING COUNT(DISTINCT s.id) >= 2
ORDER BY scans_failed DESC, h.ip;


-- Q10. FIXED between scan 1 and scan 2 (failed before, PASSED now).
--      Change the two scan ids to compare other scans.
--      NEW and UNCHANGED findings are produced by compare_scans() in queries.py.
SELECT oh.ip, oc.rule_id, r.title, oc.severity AS old_severity
FROM check_results oc
JOIN hosts oh ON oh.id = oc.host_id AND oh.scan_id = 1
JOIN hosts nh ON nh.ip = oh.ip       AND nh.scan_id = 2
JOIN check_results nc ON nc.host_id = nh.id AND nc.rule_id = oc.rule_id
JOIN rules r ON r.rule_id = oc.rule_id
WHERE oc.status = 'failed' AND nc.status = 'passed'
ORDER BY oh.ip, oc.rule_id;
