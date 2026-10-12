-- =====================================================================
-- Windows Vulnerability & Network Scanner : DATABASE SCHEMA (SQLite)
-- Owner of this file: database team member.
--
-- Design principles (explain these to the review committee):
--   1. "not_checked" is a FIRST-CLASS status. It is never counted as passed.
--   2. Severity is a PROJECT severity (Critical/High/Medium/Low). It is NOT
--      CVSS. CVSS appears only on the optional cve_cache table.
--   3. An open port is stored as an OBSERVATION (ports table), not as a
--      vulnerability. Only a rule evaluation creates a "failed" result.
--   4. NO passwords, tokens or credentials are stored anywhere.
--   5. All timestamps are UTC, ISO-8601 text (e.g. 2026-10-11T09:30:00Z).
--   6. Hosts belong to ONE scan (a snapshot). Scans are compared by IP.
--
-- Safe to run more than once (CREATE ... IF NOT EXISTS).
-- Connection-level PRAGMAs (foreign_keys, WAL) are set in db.py.
-- =====================================================================

-- ---------------------------------------------------------------------
-- scans : one row per scan run (the scan "history")
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scans (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at              TEXT    NOT NULL,                -- UTC ISO-8601
    finished_at             TEXT,                            -- NULL while running
    status                  TEXT    NOT NULL DEFAULT 'running'
                            CHECK (status IN ('running','completed','failed','cancelled')),
    scope                   TEXT    NOT NULL,                -- e.g. "192.168.56.0/24"
    authorization_confirmed INTEGER NOT NULL
                            CHECK (authorization_confirmed = 1),  -- must be confirmed
    started_by              TEXT,                            -- name/label only
    notes                   TEXT,
    is_sample               INTEGER NOT NULL DEFAULT 0
                            CHECK (is_sample IN (0,1)),      -- 1 = demo/sample data
    CHECK (finished_at IS NULL OR finished_at >= started_at)
);

-- ---------------------------------------------------------------------
-- hosts : every IP examined in a scan (reachable or not)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS hosts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip               TEXT    NOT NULL,
    hostname         TEXT,
    is_reachable     INTEGER NOT NULL DEFAULT 0 CHECK (is_reachable IN (0,1)),
    os_name          TEXT,
    os_version       TEXT,
    os_build         TEXT,
    winrm_status     TEXT    NOT NULL DEFAULT 'unknown'
                     CHECK (winrm_status IN ('ok','auth_failed','unreachable','not_enabled','unknown')),
    discovery_method TEXT,                                   -- e.g. "nmap ping/port probe"
    UNIQUE (scan_id, ip)
);

-- ---------------------------------------------------------------------
-- ports : observations from the Nmap port/service check
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id         INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port            INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol        TEXT    NOT NULL DEFAULT 'tcp' CHECK (protocol IN ('tcp','udp')),
    state           TEXT    NOT NULL CHECK (state IN ('open','closed','filtered')),
    service_name    TEXT,
    service_version TEXT,
    UNIQUE (host_id, port, protocol)
);

-- ---------------------------------------------------------------------
-- rules : the rulebook (mirrors the YAML/JSON rulebook file)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS rules (
    rule_id           TEXT PRIMARY KEY,                       -- e.g. "FW-001"
    title             TEXT NOT NULL,
    description       TEXT,
    cis_reference     TEXT,                                   -- guidance reference, may be NULL
    default_severity  TEXT NOT NULL
                      CHECK (default_severity IN ('Critical','High','Medium','Low')),
    check_description TEXT,                                   -- what is checked / which query
    remediation       TEXT,                                   -- suggested fix
    rule_version      TEXT NOT NULL DEFAULT '1',
    enabled           INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1))
);

-- ---------------------------------------------------------------------
-- check_results : one row per (host, rule). This is the "finding" table.
--   passed       -> rule evaluated, system meets expectation
--   failed       -> rule evaluated, system does NOT meet expectation (a finding)
--   not_checked  -> rule could not be evaluated (e.g. WinRM auth failed)
--   error        -> evaluation crashed unexpectedly
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS check_results (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id            INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    rule_id            TEXT    NOT NULL REFERENCES rules(rule_id),
    status             TEXT    NOT NULL
                       CHECK (status IN ('passed','failed','not_checked','error')),
    severity           TEXT
                       CHECK (severity IS NULL OR severity IN ('Critical','High','Medium','Low')),
    observed_value     TEXT,
    expected_value     TEXT,
    reason_not_checked TEXT,
    checked_at         TEXT    NOT NULL,                      -- UTC ISO-8601
    UNIQUE (host_id, rule_id),
    -- a failed result MUST carry a severity
    CHECK (status <> 'failed' OR severity IS NOT NULL),
    -- not_checked / error MUST explain why
    CHECK (status NOT IN ('not_checked','error') OR reason_not_checked IS NOT NULL)
);

-- ---------------------------------------------------------------------
-- OPTIONAL: CVE information (only when software/version matches reliably)
-- Cache locally so the demo does not depend on internet access.
-- cvss_score belongs to the CVE record, NOT to project severity.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cve_cache (
    cve_id            TEXT PRIMARY KEY,                       -- e.g. CVE-2019-0708
    cvss_score        REAL CHECK (cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)),
    description       TEXT,
    affected_software TEXT,
    fetched_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS check_result_cves (
    check_result_id INTEGER NOT NULL REFERENCES check_results(id) ON DELETE CASCADE,
    cve_id          TEXT    NOT NULL REFERENCES cve_cache(cve_id),
    PRIMARY KEY (check_result_id, cve_id)
);

-- ---------------------------------------------------------------------
-- scan_log : errors/events during a scan (justification: lets the
-- dashboard explain WHY something was "not_checked" or a scan failed,
-- and helps debugging without reading console output).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    host_ip   TEXT,
    level     TEXT NOT NULL DEFAULT 'info' CHECK (level IN ('info','warning','error')),
    message   TEXT NOT NULL,
    logged_at TEXT NOT NULL
);

-- ---------------------------------------------------------------------
-- Indexes for the dashboard queries
-- ---------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_hosts_scan        ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_hosts_ip          ON hosts(ip);
CREATE INDEX IF NOT EXISTS idx_ports_host        ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_results_host      ON check_results(host_id);
CREATE INDEX IF NOT EXISTS idx_results_rule      ON check_results(rule_id);
CREATE INDEX IF NOT EXISTS idx_results_status    ON check_results(status);
CREATE INDEX IF NOT EXISTS idx_log_scan          ON scan_log(scan_id);
