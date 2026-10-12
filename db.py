"""
db.py : database layer for the Windows Vulnerability & Network Scanner prototype.

WHO USES THIS FILE
    * Scanner teammate  -> create_scan(), save_host_result(), log_event(), finish_scan()
    * Rule-engine mate  -> load_rules(), load_rules_from_yaml()
    * Dashboard mate    -> uses queries.py (read-only functions)

SAFETY / DESIGN CHOICES (explain these to the committee)
    * Only the built-in sqlite3 module is required (PyYAML only if you load a YAML rulebook).
    * Every SQL statement is parameterised (no string-formatted SQL -> no SQL injection).
    * One connection PER CALL (never shared between threads) + WAL mode + busy_timeout,
      so parallel scan workers can write without "database is locked" errors.
    * Each host is saved in ONE transaction (all-or-nothing).
    * Credentials are never stored. Any payload containing a password/secret/token-style
      key is rejected before it touches the database.
    * Anything the rule engine did not evaluate is stored as "not_checked", never "passed".
    * Timestamps are UTC ISO-8601 text.
"""

from __future__ import annotations

import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "schema.sql"
DEFAULT_DB_PATH = Path(os.environ.get("VULNSCAN_DB", HERE / "vulnscan.db"))

SEVERITIES = ("Critical", "High", "Medium", "Low")
CHECK_STATUSES = ("passed", "failed", "not_checked", "error")

# Keys that must never appear in anything we store.
_SECRET_KEY_PATTERN = re.compile(r"pass(word|wd)?|secret|token|credential|apikey|api_key", re.I)


# ---------------------------------------------------------------------
# Connection helpers
# ---------------------------------------------------------------------
def utc_now() -> str:
    """Current time in UTC, ISO-8601, e.g. '2026-10-11T09:30:00Z'."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_connection(db_path: Optional[os.PathLike | str] = None) -> sqlite3.Connection:
    """
    Open a NEW connection with the safety PRAGMAs applied.
    Do not share the returned connection between threads; call this once per thread/task.
    """
    path = str(db_path or DEFAULT_DB_PATH)
    conn = sqlite3.connect(path, timeout=30, isolation_level=None)  # autocommit; we manage BEGIN/COMMIT
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")    # without this SQLite ignores foreign keys!
    conn.execute("PRAGMA journal_mode = WAL")   # readers do not block the writer
    conn.execute("PRAGMA busy_timeout = 30000") # wait up to 30 s instead of failing instantly
    return conn


@contextmanager
def connect(db_path: Optional[os.PathLike | str] = None) -> Iterator[sqlite3.Connection]:
    """Context manager: opens a connection and always closes it."""
    conn = get_connection(db_path)
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """
    All-or-nothing write block. BEGIN IMMEDIATE takes the write lock up front,
    which avoids deadlocks between parallel writers.
    """
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    else:
        conn.execute("COMMIT")


def init_db(db_path: Optional[os.PathLike | str] = None) -> Path:
    """Create all tables/indexes if they do not exist (safe to call repeatedly)."""
    path = Path(db_path or DEFAULT_DB_PATH)
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    with connect(path) as conn:
        conn.executescript(sql)
    return path


# ---------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------
def _reject_secrets(obj: Any, _path: str = "payload") -> None:
    """Raise ValueError if any dict key looks like a credential field (checked recursively)."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if _SECRET_KEY_PATTERN.search(str(key)):
                raise ValueError(
                    f"Refusing to store field '{_path}.{key}': credentials must never be saved."
                )
            _reject_secrets(value, f"{_path}.{key}")
    elif isinstance(obj, (list, tuple)):
        for i, item in enumerate(obj):
            _reject_secrets(item, f"{_path}[{i}]")


def _to_text(value: Any) -> Optional[str]:
    """Store observed/expected values as text (None stays NULL)."""
    return None if value is None else str(value)


# ---------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------
def create_scan(
    scope: str,
    authorization_confirmed: bool,
    started_by: Optional[str] = None,
    notes: Optional[str] = None,
    is_sample: bool = False,
    db_path: Optional[os.PathLike | str] = None,
) -> int:
    """
    Start a new scan record and return its scan_id.
    The scan is refused unless the administrator confirmed authorization (Phase 1).
    """
    if not authorization_confirmed:
        raise PermissionError("Scan refused: authorization_confirmed must be True (Phase 1).")
    if not scope or not str(scope).strip():
        raise ValueError("scope (IP range or target list) is required.")
    with connect(db_path) as conn, transaction(conn):
        cur = conn.execute(
            """INSERT INTO scans (started_at, status, scope, authorization_confirmed,
                                  started_by, notes, is_sample)
               VALUES (?, 'running', ?, 1, ?, ?, ?)""",
            (utc_now(), str(scope).strip(), started_by, notes, 1 if is_sample else 0),
        )
        return int(cur.lastrowid)


def finish_scan(
    scan_id: int, status: str = "completed", db_path: Optional[os.PathLike | str] = None
) -> None:
    """Mark a scan as completed / failed / cancelled and stamp finished_at."""
    if status not in ("completed", "failed", "cancelled"):
        raise ValueError("status must be completed, failed or cancelled.")
    with connect(db_path) as conn, transaction(conn):
        conn.execute(
            "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?",
            (status, utc_now(), scan_id),
        )


def log_event(
    scan_id: int,
    message: str,
    level: str = "info",
    host_ip: Optional[str] = None,
    db_path: Optional[os.PathLike | str] = None,
) -> None:
    """Write a line to scan_log (levels: info / warning / error)."""
    with connect(db_path) as conn, transaction(conn):
        conn.execute(
            "INSERT INTO scan_log (scan_id, host_ip, level, message, logged_at) VALUES (?,?,?,?,?)",
            (scan_id, host_ip, level, message, utc_now()),
        )


# ---------------------------------------------------------------------
# Rulebook
# ---------------------------------------------------------------------
_RULE_FIELDS = (
    "rule_id", "title", "description", "cis_reference", "default_severity",
    "check_description", "remediation", "rule_version", "enabled",
)


def load_rules(rules: Iterable[dict], db_path: Optional[os.PathLike | str] = None) -> int:
    """
    Insert or update rules (upsert on rule_id). Returns how many rules were loaded.
    Each rule dict needs: rule_id, title, default_severity. Others are optional.
    """
    rules = list(rules)
    _reject_secrets(rules, "rules")
    with connect(db_path) as conn, transaction(conn):
        for r in rules:
            for required in ("rule_id", "title", "default_severity"):
                if not r.get(required):
                    raise ValueError(f"Rule is missing required field '{required}': {r}")
            if r["default_severity"] not in SEVERITIES:
                raise ValueError(f"Rule {r['rule_id']}: severity must be one of {SEVERITIES}.")
            conn.execute(
                """INSERT INTO rules (rule_id, title, description, cis_reference, default_severity,
                                      check_description, remediation, rule_version, enabled)
                   VALUES (?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(rule_id) DO UPDATE SET
                       title=excluded.title, description=excluded.description,
                       cis_reference=excluded.cis_reference,
                       default_severity=excluded.default_severity,
                       check_description=excluded.check_description,
                       remediation=excluded.remediation,
                       rule_version=excluded.rule_version, enabled=excluded.enabled""",
                (
                    r["rule_id"], r["title"], r.get("description"), r.get("cis_reference"),
                    r["default_severity"], r.get("check_description"), r.get("remediation"),
                    str(r.get("rule_version", "1")), 0 if r.get("enabled") is False else 1,
                ),
            )
    return len(rules)


def load_rules_from_yaml(
    yaml_path: os.PathLike | str, db_path: Optional[os.PathLike | str] = None
) -> int:
    """
    Load the rulebook from a YAML file shaped like:  rules: [ {rule_id: ..., title: ...}, ... ]
    Requires PyYAML (pip install pyyaml). Uses safe_load only.
    """
    try:
        import yaml  # imported lazily so the rest of db.py works without PyYAML
    except ImportError as exc:
        raise RuntimeError("PyYAML is required for YAML rulebooks: pip install pyyaml") from exc
    data = yaml.safe_load(Path(yaml_path).read_text(encoding="utf-8"))
    rules = data.get("rules") if isinstance(data, dict) else data
    if not isinstance(rules, list):
        raise ValueError("YAML rulebook must contain a list of rules (top-level 'rules:').")
    return load_rules(rules, db_path)


# ---------------------------------------------------------------------
# Hosts, ports, check results
# ---------------------------------------------------------------------
def _upsert_host(conn: sqlite3.Connection, scan_id: int, host: dict) -> int:
    """Insert or update the host row inside an open transaction; return host_id."""
    if not host.get("ip"):
        raise ValueError("host['ip'] is required.")
    conn.execute(
        """INSERT INTO hosts (scan_id, ip, hostname, is_reachable, os_name, os_version, os_build,
                              winrm_status, discovery_method)
           VALUES (?,?,?,?,?,?,?,?,?)
           ON CONFLICT(scan_id, ip) DO UPDATE SET
               hostname=excluded.hostname, is_reachable=excluded.is_reachable,
               os_name=excluded.os_name, os_version=excluded.os_version,
               os_build=excluded.os_build, winrm_status=excluded.winrm_status,
               discovery_method=excluded.discovery_method""",
        (
            scan_id, host["ip"], host.get("hostname"), 1 if host.get("is_reachable") else 0,
            host.get("os_name"), host.get("os_version"), host.get("os_build"),
            host.get("winrm_status", "unknown"), host.get("discovery_method"),
        ),
    )
    row = conn.execute(
        "SELECT id FROM hosts WHERE scan_id = ? AND ip = ?", (scan_id, host["ip"])
    ).fetchone()
    return int(row["id"])


def _replace_ports(conn: sqlite3.Connection, host_id: int, ports: Iterable[dict]) -> None:
    conn.execute("DELETE FROM ports WHERE host_id = ?", (host_id,))
    for p in ports:
        conn.execute(
            """INSERT INTO ports (host_id, port, protocol, state, service_name, service_version)
               VALUES (?,?,?,?,?,?)""",
            (
                host_id, int(p["port"]), p.get("protocol", "tcp"), p["state"],
                p.get("service_name"), p.get("service_version"),
            ),
        )


def _save_check(conn: sqlite3.Connection, host_id: int, check: dict) -> None:
    """Validate and upsert one check result inside an open transaction."""
    rule_id = check.get("rule_id")
    status = check.get("status")
    if status not in CHECK_STATUSES:
        raise ValueError(f"check status must be one of {CHECK_STATUSES}, got {status!r}.")
    rule = conn.execute(
        "SELECT default_severity FROM rules WHERE rule_id = ?", (rule_id,)
    ).fetchone()
    if rule is None:
        raise ValueError(f"Unknown rule_id {rule_id!r}. Load the rulebook first (load_rules).")

    severity = check.get("severity")
    if status == "failed":
        severity = severity or rule["default_severity"]  # fall back to the rule's default
        if severity not in SEVERITIES:
            raise ValueError(f"severity must be one of {SEVERITIES}, got {severity!r}.")
    else:
        severity = None  # only failed results carry a severity

    reason = check.get("reason_not_checked")
    if status in ("not_checked", "error") and not reason:
        raise ValueError(f"{rule_id}: a reason_not_checked is required for status '{status}'.")

    conn.execute(
        """INSERT INTO check_results (host_id, rule_id, status, severity, observed_value,
                                      expected_value, reason_not_checked, checked_at)
           VALUES (?,?,?,?,?,?,?,?)
           ON CONFLICT(host_id, rule_id) DO UPDATE SET
               status=excluded.status, severity=excluded.severity,
               observed_value=excluded.observed_value, expected_value=excluded.expected_value,
               reason_not_checked=excluded.reason_not_checked, checked_at=excluded.checked_at""",
        (
            host_id, rule_id, status, severity, _to_text(check.get("observed_value")),
            _to_text(check.get("expected_value")), reason, check.get("checked_at") or utc_now(),
        ),
    )


def _fill_missing_as_not_checked(conn: sqlite3.Connection, host_id: int, reason: str) -> int:
    """
    Every ENABLED rule that has no result for this host becomes 'not_checked'.
    Rule of the project: absence of a result is NEVER treated as 'passed'.
    """
    cur = conn.execute(
        """INSERT INTO check_results (host_id, rule_id, status, reason_not_checked, checked_at)
           SELECT ?, r.rule_id, 'not_checked', ?, ?
           FROM rules r
           WHERE r.enabled = 1
             AND NOT EXISTS (SELECT 1 FROM check_results c
                             WHERE c.host_id = ? AND c.rule_id = r.rule_id)""",
        (host_id, reason, utc_now(), host_id),
    )
    return cur.rowcount


def save_host_result(
    scan_id: int,
    host: dict,
    auto_not_checked: bool = True,
    db_path: Optional[os.PathLike | str] = None,
) -> int:
    """
    MAIN FUNCTION FOR THE SCANNER TEAMMATE.
    Saves one host (details + ports + check results) in a single transaction and returns host_id.
    See INTERFACE_CONTRACT.md for the exact shape of `host`.

    If auto_not_checked is True, any enabled rule without a result is stored as 'not_checked'
    with a reason based on the host's winrm_status (so nothing silently counts as passed).
    """
    _reject_secrets(host, "host")
    with connect(db_path) as conn, transaction(conn):
        scan = conn.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if scan is None:
            raise ValueError(f"scan_id {scan_id} does not exist.")
        host_id = _upsert_host(conn, scan_id, host)
        _replace_ports(conn, host_id, host.get("ports", []))
        for check in host.get("checks", []):
            _save_check(conn, host_id, check)
        if auto_not_checked:
            winrm = host.get("winrm_status", "unknown")
            if not host.get("is_reachable"):
                reason = "Host unreachable"
            elif winrm != "ok":
                reason = f"WinRM status: {winrm}"
            else:
                reason = "No result supplied by the rule engine"
            _fill_missing_as_not_checked(conn, host_id, reason)
        return host_id


def save_check_result(
    host_id: int, check: dict, db_path: Optional[os.PathLike | str] = None
) -> None:
    """Save/update a single check result for an existing host (use save_host_result when possible)."""
    _reject_secrets(check, "check")
    with connect(db_path) as conn, transaction(conn):
        _save_check(conn, host_id, check)
