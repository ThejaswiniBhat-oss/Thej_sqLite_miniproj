"""
verify.py : automated self-check for the database part. Run:  python verify.py

It uses a TEMPORARY database, so it never touches vulnscan.db.
Prints PASS/FAIL for each rule of the design and exits with code 0 only if everything passes.
"""

from __future__ import annotations

import sqlite3
import sys
import tempfile
import threading
from pathlib import Path

import db
import queries as q
import seed_data

RESULTS: list[tuple[bool, str]] = []


def check(name: str, condition: bool, detail: str = "") -> None:
    RESULTS.append((bool(condition), name))
    print(f"  [{'PASS' if condition else 'FAIL'}] {name}" + (f"  -> {detail}" if detail and not condition else ""))


def raises(exc_types, func, *args, **kwargs) -> bool:
    try:
        func(*args, **kwargs)
    except exc_types:
        return True
    except Exception:
        return False
    return False


def main() -> int:
    tmp = tempfile.TemporaryDirectory()
    path = Path(tmp.name) / "verify.db"

    print("1. Schema and connection safety")
    db.init_db(path)
    db.init_db(path)  # second call must not fail (idempotent)
    check("init_db() can be run twice safely", True)
    with db.connect(path) as conn:
        check("foreign_keys PRAGMA is ON", conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1)
        check("WAL journal mode is ON", conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal")
        check("foreign key violation is rejected",
              raises(sqlite3.IntegrityError, conn.execute,
                     "INSERT INTO hosts (scan_id, ip) VALUES (9999, '10.0.0.1')"))
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        check("no table or column can hold passwords",
              not any(db._SECRET_KEY_PATTERN.search(c[1]) for t in tables
                      for c in conn.execute(f"PRAGMA table_info({t})")))

    print("2. Scan authorization and input rules")
    check("scan without authorization is refused",
          raises(PermissionError, db.create_scan, "10.0.0.0/24", False, db_path=path))
    check("scan without scope is refused", raises(ValueError, db.create_scan, " ", True, db_path=path))
    db.load_rules(seed_data.SAMPLE_RULES, path)
    sid = db.create_scan("10.0.0.0/24", True, "verify", "verify run", is_sample=True, db_path=path)
    check("credential-like keys are rejected",
          raises(ValueError, db.save_host_result, sid,
                 {"ip": "10.0.0.5", "is_reachable": True, "winrm_password": "x"}, db_path=path))
    check("unknown rule_id is rejected",
          raises(ValueError, db.save_host_result, sid,
                 {"ip": "10.0.0.6", "checks": [{"rule_id": "NOPE-1", "status": "passed"}]}, db_path=path))
    check("not_checked without a reason is rejected",
          raises(ValueError, db.save_host_result, sid,
                 {"ip": "10.0.0.7", "checks": [{"rule_id": "FW-001", "status": "not_checked"}]}, db_path=path))
    check("invalid severity in a rule is rejected",
          raises(ValueError, db.load_rules, [{"rule_id": "X-1", "title": "t", "default_severity": "Severe"}], path))
    with db.connect(path) as conn:
        conn.execute("INSERT INTO hosts (scan_id, ip) VALUES (?, '10.9.9.9')", (sid,))
        check("DB itself rejects a 'failed' result that has no severity",
              raises(sqlite3.IntegrityError, conn.execute,
                     "INSERT INTO check_results (host_id, rule_id, status, checked_at) "
                     "SELECT id, 'FW-001', 'failed', 'x' FROM hosts WHERE ip = '10.9.9.9'"))
        conn.execute("DELETE FROM hosts WHERE ip = '10.9.9.9'")

    print("3. 'not_checked' is never 'passed'")
    db.save_host_result(sid, {"ip": "10.0.0.20", "hostname": "AUTHFAIL", "is_reachable": True,
                              "winrm_status": "auth_failed"}, db_path=path)
    db.save_host_result(sid, {"ip": "10.0.0.21", "hostname": "OFFLINE", "is_reachable": False,
                              "winrm_status": "unreachable"}, db_path=path)
    db.save_host_result(sid, {"ip": "10.0.0.22", "hostname": "OK", "is_reachable": True, "winrm_status": "ok",
                              "checks": [{"rule_id": "FW-001", "status": "failed", "observed_value": "Off",
                                          "expected_value": "On"},
                                         {"rule_id": "SMB-001", "status": "passed"}]}, db_path=path)
    db.finish_scan(sid, "completed", path)
    comp = {r["ip"]: r for r in q.host_compliance(sid, path)}
    n_rules = len(seed_data.SAMPLE_RULES)
    check("auth-failed host: all rules stored as not_checked, 0 passed",
          comp["10.0.0.20"]["not_checked"] == n_rules and comp["10.0.0.20"]["passed"] == 0)
    check("auth-failed host: compliance % is None (not 100%)", comp["10.0.0.20"]["compliance_pct"] is None)
    check("unreachable host: all rules not_checked", comp["10.0.0.21"]["not_checked"] == n_rules)
    check("failed result without severity gets the rule's default severity",
          [f for f in q.findings(sid, db_path=path) if f["ip"] == "10.0.0.22"][0]["severity"] == "High")
    check("compliance excludes not_checked from the denominator (1 passed, 1 failed = 50%)",
          comp["10.0.0.22"]["compliance_pct"] == 50.0 and comp["10.0.0.22"]["not_checked"] == n_rules - 2)
    risk = {r["ip"]: r["risk"] for r in q.network_map(sid, path)}
    check("map: unchecked hosts shown as 'Not checked', never 'Clean'",
          risk["10.0.0.20"] == "Not checked" and risk["10.0.0.21"] == "Not checked")
    check("map: failed host shows its worst severity", risk["10.0.0.22"] == "High")
    summ = q.scan_summary(sid, path)
    check("summary counts add up to total results",
          summ["passed"] + summ["failed"] + summ["not_checked"] + summ["error"] == 3 * n_rules)

    print("4. Safe handling of hostile text")
    evil = "x'); DROP TABLE hosts;--"
    db.save_host_result(sid, {"ip": "10.0.0.30", "hostname": evil, "is_reachable": True}, db_path=path)
    with db.connect(path) as conn:
        check("SQL-injection style text is stored as plain text, tables survive",
              conn.execute("SELECT hostname FROM hosts WHERE ip='10.0.0.30'").fetchone()[0] == evil)

    print("5. Scan comparison (uses the sample data)")
    sample_db = Path(tmp.name) / "sample.db"
    seed_data.seed(sample_db)
    cmp_ = q.compare_scans(1, 2, sample_db)
    ident = lambda key: sorted((i["ip"], i["rule_id"]) for i in cmp_[key])
    check("NEW  = RDP host gets PWD-001", ident("new") == [("192.168.56.13", "PWD-001")])
    check("FIXED = firewall-off host fixed FW-001 and ACC-001",
          ident("fixed") == [("192.168.56.11", "ACC-001"), ("192.168.56.11", "FW-001")])
    check("UNCHANGED = SMBv1 and RDP findings",
          ident("unchanged") == [("192.168.56.12", "SMB-001"), ("192.168.56.13", "RDP-001")])
    check("auth-failed host never produces fixed/new findings",
          not any(i["ip"] == "192.168.56.14" for k in ("new", "fixed", "unchanged") for i in cmp_[k]))
    tr = q.trend(sample_db)
    check("trend: 4 failed findings in scan 1, 3 in scan 2", [t["failed_total"] for t in tr] == [4, 3])
    rep = {(r["ip"], r["rule_id"]) for r in q.repeat_offenders(2, sample_db)}
    check("repeat offenders: SMB-001 and RDP-001", rep == {("192.168.56.12", "SMB-001"), ("192.168.56.13", "RDP-001")})
    check("sample scans are flagged is_sample", all(s["is_sample"] == 1 for s in q.list_scans(sample_db)))

    # A fixed finding must not be claimed 'fixed' if the new scan could not check it.
    unverified = Path(tmp.name) / "unverified.db"
    db.init_db(unverified)
    db.load_rules(seed_data.SAMPLE_RULES, unverified)
    a = db.create_scan("10.1.0.0/24", True, db_path=unverified)
    db.save_host_result(a, {"ip": "10.1.0.5", "is_reachable": True, "winrm_status": "ok",
                            "checks": [{"rule_id": "SMB-001", "status": "failed"}]}, db_path=unverified)
    db.finish_scan(a, "completed", unverified)
    b = db.create_scan("10.1.0.0/24", True, db_path=unverified)
    db.save_host_result(b, {"ip": "10.1.0.5", "is_reachable": True, "winrm_status": "auth_failed"},
                        db_path=unverified)
    db.finish_scan(b, "completed", unverified)
    c2 = q.compare_scans(a, b, unverified)
    check("finding that could not be re-checked is 'not_verified', NOT 'fixed'",
          len(c2["fixed"]) == 0 and len(c2["not_verified"]) == 1)

    print("6. Parallel scan workers (no 'database is locked')")
    par = Path(tmp.name) / "parallel.db"
    db.init_db(par)
    db.load_rules(seed_data.SAMPLE_RULES, par)
    psid = db.create_scan("10.2.0.0/24", True, db_path=par)
    errors: list[BaseException] = []

    def worker(n: int) -> None:
        try:
            for i in range(10):
                db.save_host_result(psid, {
                    "ip": f"10.2.{n}.{i}", "is_reachable": True, "winrm_status": "ok",
                    "ports": [{"port": 445, "state": "open"}],
                    "checks": [{"rule_id": "SMB-001", "status": "failed", "observed_value": "True"}],
                }, db_path=par)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    with db.connect(par) as conn:
        total = conn.execute("SELECT COUNT(*) FROM hosts WHERE scan_id = ?", (psid,)).fetchone()[0]
    check("8 threads x 10 hosts written with no errors", not errors and total == 80,
          detail=str(errors[:1]) + f" hosts={total}")

    print("7. Seed script safety and YAML rulebook")
    real = Path(tmp.name) / "real.db"
    db.init_db(real)
    db.create_scan("10.3.0.0/24", True, "real user", db_path=real)  # is_sample defaults to 0
    check("seed --reset refuses a database that holds real scans", seed_data._has_real_scans(real))
    try:
        import yaml  # noqa: F401
        y = Path(tmp.name) / "yaml.db"
        db.init_db(y)
        loaded = db.load_rules_from_yaml(Path(__file__).with_name("rules_sample.yaml"), y)
        check("rules_sample.yaml loads all rules", loaded == len(seed_data.SAMPLE_RULES))
    except ImportError:
        print("  [SKIP] PyYAML not installed (only needed for YAML rulebooks: pip install pyyaml)")

    failed = [name for ok, name in RESULTS if not ok]
    print(f"\n{len(RESULTS) - len(failed)} of {len(RESULTS)} checks passed.")
    if failed:
        print("FAILED:", *failed, sep="\n  - ")
    tmp.cleanup()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
