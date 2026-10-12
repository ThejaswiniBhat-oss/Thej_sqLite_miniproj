"""
queries.py : READ-ONLY dashboard queries for the Windows Vulnerability & Network Scanner.

WHO USES THIS FILE
    The dashboard (Flask) teammate. Every function returns plain Python lists/dicts, so it can be
    passed straight to jsonify() or a Jinja template.

KEY RULES (same as the whole project)
    * "not_checked" and "error" are NEVER counted as passed.
    * Compliance % = passed / (passed + failed). not_checked/error are excluded from the
      denominator but ALWAYS returned next to it, so the dashboard can show them.
    * Severity is the PROJECT severity (Critical/High/Medium/Low), not CVSS.
    * Every query is parameterised.
"""

from __future__ import annotations

import os
import sqlite3
from typing import Any, Optional

import db

PathLike = Optional[os.PathLike | str]

# Used in ORDER BY / MAX() so that Critical sorts first.
_SEV_RANK_SQL = """CASE {col} WHEN 'Critical' THEN 4 WHEN 'High' THEN 3
                           WHEN 'Medium' THEN 2 WHEN 'Low' THEN 1 ELSE 0 END"""
_RANK_TO_NAME = {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}


def _all(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[dict]:
    return [dict(row) for row in conn.execute(sql, params).fetchall()]


def _one(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> Optional[dict]:
    row = conn.execute(sql, params).fetchone()
    return dict(row) if row else None


# ---------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------
def list_scans(db_path: PathLike = None) -> list[dict]:
    """All scans, newest first (for a 'scan history' table / dropdown)."""
    with db.connect(db_path) as conn:
        return _all(conn, "SELECT * FROM scans ORDER BY started_at DESC, id DESC")


def latest_scan_id(db_path: PathLike = None, completed_only: bool = True) -> Optional[int]:
    """Id of the most recent scan (completed by default). None if there are no scans."""
    sql = "SELECT id FROM scans {where} ORDER BY started_at DESC, id DESC LIMIT 1"
    sql = sql.format(where="WHERE status = 'completed'" if completed_only else "")
    with db.connect(db_path) as conn:
        row = conn.execute(sql).fetchone()
        return int(row["id"]) if row else None


def previous_scan_id(scan_id: int, db_path: PathLike = None) -> Optional[int]:
    """The completed scan that came right before `scan_id` (for comparison)."""
    with db.connect(db_path) as conn:
        row = conn.execute(
            """SELECT id FROM scans
               WHERE status = 'completed'
                 AND (started_at, id) < (SELECT started_at, id FROM scans WHERE id = ?)
               ORDER BY started_at DESC, id DESC LIMIT 1""",
            (scan_id,),
        ).fetchone()
        return int(row["id"]) if row else None


# ---------------------------------------------------------------------
# 1. Per-scan summary
# ---------------------------------------------------------------------
def scan_summary(scan_id: int, db_path: PathLike = None) -> dict:
    """
    Headline numbers for one scan:
      hosts_found, hosts_reachable, hosts_checked (>=1 rule actually evaluated),
      rules_applied, passed / failed / not_checked / error, failed_by_severity.
    """
    with db.connect(db_path) as conn:
        scan = _one(conn, "SELECT * FROM scans WHERE id = ?", (scan_id,))
        if scan is None:
            raise ValueError(f"scan_id {scan_id} does not exist.")

        hosts = _one(
            conn,
            """SELECT COUNT(*) AS hosts_found,
                      COALESCE(SUM(is_reachable), 0) AS hosts_reachable
               FROM hosts WHERE scan_id = ?""",
            (scan_id,),
        )
        checked = _one(
            conn,
            """SELECT COUNT(DISTINCT h.id) AS hosts_checked
               FROM hosts h JOIN check_results c ON c.host_id = h.id
               WHERE h.scan_id = ? AND c.status IN ('passed','failed')""",
            (scan_id,),
        )
        counts = _all(
            conn,
            """SELECT c.status, COUNT(*) AS n
               FROM check_results c JOIN hosts h ON h.id = c.host_id
               WHERE h.scan_id = ? GROUP BY c.status""",
            (scan_id,),
        )
        rules = _one(
            conn,
            """SELECT COUNT(DISTINCT c.rule_id) AS rules_applied
               FROM check_results c JOIN hosts h ON h.id = c.host_id
               WHERE h.scan_id = ?""",
            (scan_id,),
        )
        by_sev = _all(
            conn,
            """SELECT c.severity, COUNT(*) AS n
               FROM check_results c JOIN hosts h ON h.id = c.host_id
               WHERE h.scan_id = ? AND c.status = 'failed' GROUP BY c.severity""",
            (scan_id,),
        )

    status_counts = {"passed": 0, "failed": 0, "not_checked": 0, "error": 0}
    status_counts.update({r["status"]: r["n"] for r in counts})
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    severity_counts.update({r["severity"]: r["n"] for r in by_sev})
    return {
        "scan_id": scan_id, "scope": scan["scope"], "status": scan["status"],
        "started_at": scan["started_at"], "finished_at": scan["finished_at"],
        "is_sample": bool(scan["is_sample"]),
        "hosts_found": hosts["hosts_found"], "hosts_reachable": hosts["hosts_reachable"],
        "hosts_checked": checked["hosts_checked"], "rules_applied": rules["rules_applied"],
        **status_counts, "failed_by_severity": severity_counts,
    }


# ---------------------------------------------------------------------
# 2. Per-host compliance %
# ---------------------------------------------------------------------
def host_compliance(scan_id: int, db_path: PathLike = None) -> list[dict]:
    """
    One row per host with passed / failed / not_checked / error counts and compliance_pct.
    compliance_pct = passed / (passed + failed) * 100, or None if nothing could be evaluated.
    not_checked and error are excluded from the denominator but returned alongside.
    coverage_pct = evaluated / total rules for the host. ALWAYS display it next to compliance_pct
    (e.g. "100% of 1 evaluated rule - coverage 14%").
    """
    sql = """
        SELECT h.ip, h.hostname, h.is_reachable, h.winrm_status,
               SUM(CASE WHEN c.status = 'passed'      THEN 1 ELSE 0 END) AS passed,
               SUM(CASE WHEN c.status = 'failed'      THEN 1 ELSE 0 END) AS failed,
               SUM(CASE WHEN c.status = 'not_checked' THEN 1 ELSE 0 END) AS not_checked,
               SUM(CASE WHEN c.status = 'error'       THEN 1 ELSE 0 END) AS error
        FROM hosts h LEFT JOIN check_results c ON c.host_id = h.id
        WHERE h.scan_id = ?
        GROUP BY h.id ORDER BY h.ip"""
    with db.connect(db_path) as conn:
        rows = _all(conn, sql, (scan_id,))
    for r in rows:
        evaluated = r["passed"] + r["failed"]
        total = evaluated + r["not_checked"] + r["error"]
        r["evaluated"] = evaluated
        r["compliance_pct"] = round(100.0 * r["passed"] / evaluated, 1) if evaluated else None
        # coverage = how much of the rulebook could actually be evaluated. Show it NEXT TO
        # compliance_pct, otherwise "100%" on a host where most rules were not checked misleads.
        r["coverage_pct"] = round(100.0 * evaluated / total, 1) if total else None
    return rows


# ---------------------------------------------------------------------
# 3. Network map data (vis-network)
# ---------------------------------------------------------------------
def network_map(scan_id: int, db_path: PathLike = None) -> list[dict]:
    """
    One row per host for the network map:
      risk = Critical | High | Medium | Low | Clean | Partially checked | Not checked
        - worst failed severity if there is any failed result,
        - 'Clean' if every rule was evaluated and all passed,
        - 'Partially checked' if no failures but some rules could not run (never shown as Clean),
        - 'Not checked' if NOTHING could be evaluated (e.g. unreachable, WinRM auth failed).
      Also: open_ports, finding_count, not_checked_count (so partly-checked hosts are visible).
    """
    sql = f"""
        SELECT h.ip, h.hostname, h.is_reachable, h.winrm_status,
               (SELECT COUNT(*) FROM ports p WHERE p.host_id = h.id AND p.state = 'open') AS open_ports,
               (SELECT COUNT(*) FROM check_results c WHERE c.host_id = h.id AND c.status = 'failed')
                   AS finding_count,
               (SELECT COUNT(*) FROM check_results c WHERE c.host_id = h.id AND c.status = 'passed')
                   AS passed_count,
               (SELECT COUNT(*) FROM check_results c
                 WHERE c.host_id = h.id AND c.status IN ('not_checked','error')) AS not_checked_count,
               (SELECT MAX({_SEV_RANK_SQL.format(col='c.severity')}) FROM check_results c
                 WHERE c.host_id = h.id AND c.status = 'failed') AS worst_rank
        FROM hosts h WHERE h.scan_id = ? ORDER BY h.ip"""
    with db.connect(db_path) as conn:
        rows = _all(conn, sql, (scan_id,))
    for r in rows:
        if r["finding_count"] > 0:
            r["risk"] = _RANK_TO_NAME[r["worst_rank"]]
        elif r["passed_count"] > 0 and r["not_checked_count"] == 0:
            r["risk"] = "Clean"
        elif r["passed_count"] > 0:
            r["risk"] = "Partially checked"   # no failures, but some rules could not run
        else:
            r["risk"] = "Not checked"
        del r["worst_rank"]
    return rows


# ---------------------------------------------------------------------
# Host detail + findings list
# ---------------------------------------------------------------------
def host_details(scan_id: int, ip: str, db_path: PathLike = None) -> Optional[dict]:
    """Everything for the side panel when a host is clicked: host, ports, all rule results."""
    with db.connect(db_path) as conn:
        host = _one(conn, "SELECT * FROM hosts WHERE scan_id = ? AND ip = ?", (scan_id, ip))
        if host is None:
            return None
        ports = _all(
            conn, "SELECT port, protocol, state, service_name, service_version "
                  "FROM ports WHERE host_id = ? ORDER BY port", (host["id"],))
        results = _all(
            conn,
            f"""SELECT c.rule_id, r.title, r.cis_reference, c.status, c.severity,
                       c.observed_value, c.expected_value, c.reason_not_checked,
                       r.remediation, c.checked_at
                FROM check_results c JOIN rules r ON r.rule_id = c.rule_id
                WHERE c.host_id = ?
                ORDER BY CASE c.status WHEN 'failed' THEN 0 WHEN 'error' THEN 1
                                       WHEN 'not_checked' THEN 2 ELSE 3 END,
                         {_SEV_RANK_SQL.format(col='c.severity')} DESC, c.rule_id""",
            (host["id"],),
        )
    return {"host": host, "ports": ports, "results": results}


def findings(scan_id: int, severity: Optional[str] = None, db_path: PathLike = None) -> list[dict]:
    """All FAILED results in a scan, worst first. Optional filter by project severity."""
    sql = f"""
        SELECT h.ip, h.hostname, c.rule_id, r.title, r.cis_reference, c.severity,
               c.observed_value, c.expected_value, r.remediation
        FROM check_results c
        JOIN hosts h ON h.id = c.host_id
        JOIN rules r ON r.rule_id = c.rule_id
        WHERE h.scan_id = ? AND c.status = 'failed' {{extra}}
        ORDER BY {_SEV_RANK_SQL.format(col='c.severity')} DESC, h.ip, c.rule_id"""
    params: tuple[Any, ...] = (scan_id,)
    extra = ""
    if severity:
        if severity not in db.SEVERITIES:
            raise ValueError(f"severity must be one of {db.SEVERITIES}")
        extra, params = "AND c.severity = ?", (scan_id, severity)
    with db.connect(db_path) as conn:
        return _all(conn, sql.format(extra=extra), params)


def scan_log(scan_id: int, db_path: PathLike = None) -> list[dict]:
    """Log lines for a scan (why something was not checked, warnings, errors)."""
    with db.connect(db_path) as conn:
        return _all(conn, "SELECT host_ip, level, message, logged_at FROM scan_log "
                          "WHERE scan_id = ? ORDER BY id", (scan_id,))


# ---------------------------------------------------------------------
# 4. Scan comparison (new / fixed / unchanged)
# ---------------------------------------------------------------------
def compare_scans(old_scan_id: int, new_scan_id: int, db_path: PathLike = None) -> dict:
    """
    Compare two scans, matching hosts by IP and rules by rule_id.

      new               failed now; was passed (or absent) before
      fixed             failed before; PASSED now (verified fix)
      unchanged         failed in both scans
      not_verified      failed before; now not_checked/error/absent -> we cannot say it is fixed
      newly_checked     failed now; was not_checked/error before -> may have existed earlier

    Each list item: {ip, hostname, rule_id, title, severity, observed_value}.
    """
    sql = """
        SELECT h.ip, h.hostname, c.rule_id, r.title, c.status, c.severity, c.observed_value
        FROM check_results c
        JOIN hosts h ON h.id = c.host_id
        JOIN rules r ON r.rule_id = c.rule_id
        WHERE h.scan_id = ?"""
    with db.connect(db_path) as conn:
        for sid in (old_scan_id, new_scan_id):
            if _one(conn, "SELECT id FROM scans WHERE id = ?", (sid,)) is None:
                raise ValueError(f"scan_id {sid} does not exist.")
        old = {(r["ip"], r["rule_id"]): r for r in _all(conn, sql, (old_scan_id,))}
        new = {(r["ip"], r["rule_id"]): r for r in _all(conn, sql, (new_scan_id,))}

    def item(row: dict) -> dict:
        return {k: row[k] for k in ("ip", "hostname", "rule_id", "title", "severity", "observed_value")}

    out: dict[str, list[dict]] = {
        "new": [], "fixed": [], "unchanged": [], "not_verified": [], "newly_checked": [],
    }
    for key in sorted(set(old) | set(new)):
        o, n = old.get(key), new.get(key)
        o_status = o["status"] if o else None
        n_status = n["status"] if n else None
        if n_status == "failed":
            if o_status == "failed":
                out["unchanged"].append(item(n))
            elif o_status in ("not_checked", "error"):
                out["newly_checked"].append(item(n))
            else:                      # passed before, or rule/host absent before
                out["new"].append(item(n))
        elif o_status == "failed":
            if n_status == "passed":
                out["fixed"].append(item(o))
            else:                      # not_checked / error / absent now
                out["not_verified"].append(item(o))
    return out


# ---------------------------------------------------------------------
# 5. Trend over time (Chart.js line chart)
# ---------------------------------------------------------------------
def trend(db_path: PathLike = None) -> list[dict]:
    """
    One row per completed scan, oldest first:
      scan_id, started_at, failed_total, failed per severity, passed, not_checked.
    Feed `started_at` as labels and `failed_total` as the data series in Chart.js.
    """
    sql = """
        SELECT s.id AS scan_id, s.started_at, s.is_sample,
               SUM(CASE WHEN c.status = 'failed' THEN 1 ELSE 0 END)                    AS failed_total,
               SUM(CASE WHEN c.status = 'failed' AND c.severity = 'Critical' THEN 1 ELSE 0 END) AS critical,
               SUM(CASE WHEN c.status = 'failed' AND c.severity = 'High'     THEN 1 ELSE 0 END) AS high,
               SUM(CASE WHEN c.status = 'failed' AND c.severity = 'Medium'   THEN 1 ELSE 0 END) AS medium,
               SUM(CASE WHEN c.status = 'failed' AND c.severity = 'Low'      THEN 1 ELSE 0 END) AS low,
               SUM(CASE WHEN c.status = 'passed' THEN 1 ELSE 0 END)                    AS passed,
               SUM(CASE WHEN c.status IN ('not_checked','error') THEN 1 ELSE 0 END)    AS not_checked
        FROM scans s
        LEFT JOIN hosts h ON h.scan_id = s.id
        LEFT JOIN check_results c ON c.host_id = h.id
        WHERE s.status = 'completed'
        GROUP BY s.id ORDER BY s.started_at, s.id"""
    with db.connect(db_path) as conn:
        rows = _all(conn, sql)
    for r in rows:  # SUM() over zero rows gives NULL -> make it 0
        for k in ("failed_total", "critical", "high", "medium", "low", "passed", "not_checked"):
            r[k] = r[k] or 0
    return rows


# ---------------------------------------------------------------------
# 6. Repeat offenders
# ---------------------------------------------------------------------
def repeat_offenders(min_scans: int = 2, db_path: PathLike = None) -> list[dict]:
    """Hosts (by IP) that FAILED the same rule in at least `min_scans` different completed scans."""
    if min_scans < 2:
        raise ValueError("min_scans must be at least 2.")
    sql = f"""
        SELECT h.ip, MAX(h.hostname) AS hostname, c.rule_id, r.title,
               COUNT(DISTINCT s.id) AS scans_failed,
               MIN(s.started_at) AS first_seen, MAX(s.started_at) AS last_seen,
               MAX({_SEV_RANK_SQL.format(col='c.severity')}) AS worst_rank
        FROM check_results c
        JOIN hosts h ON h.id = c.host_id
        JOIN scans s ON s.id = h.scan_id
        JOIN rules r ON r.rule_id = c.rule_id
        WHERE c.status = 'failed' AND s.status = 'completed'
        GROUP BY h.ip, c.rule_id
        HAVING COUNT(DISTINCT s.id) >= ?
        ORDER BY scans_failed DESC, worst_rank DESC, h.ip"""
    with db.connect(db_path) as conn:
        rows = _all(conn, sql, (min_scans,))
    for r in rows:
        r["worst_severity"] = _RANK_TO_NAME.get(r.pop("worst_rank"))
    return rows
