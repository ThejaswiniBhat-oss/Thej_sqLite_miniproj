"""
seed_data.py : loads SAMPLE data so the dashboard and queries can be tested
before the real scanner is ready.

    *** EVERYTHING CREATED HERE IS SAMPLE DATA, NOT REAL SCAN RESULTS ***
    Every scan is flagged is_sample = 1 and its notes say "SAMPLE DATA".
    Never present it to the committee as a real scan.

Usage:
    python seed_data.py                 # create vulnscan.db with sample data
    python seed_data.py --db my.db      # use another database file
    python seed_data.py --reset         # wipe a database that holds ONLY sample data, then reseed

Safety: --reset refuses to touch a database that contains any real (non-sample) scan.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import db

# ---------------------------------------------------------------------
# Sample rulebook (project severity, NOT CVSS).
# cis_reference is descriptive: fill in the exact recommendation number from
# YOUR licensed copy of the CIS benchmark for the Windows version you test.
# ---------------------------------------------------------------------
SAMPLE_RULES = [
    {
        "rule_id": "FW-001", "title": "Windows Firewall enabled on all profiles",
        "description": "Domain, Private and Public firewall profiles should be On.",
        "cis_reference": "CIS Windows Benchmark: Windows Firewall (section no. to be confirmed)",
        "default_severity": "High",
        "check_description": "WinRM: Get-NetFirewallProfile | Select Name, Enabled",
        "remediation": "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True",
    },
    {
        "rule_id": "SMB-001", "title": "SMBv1 protocol disabled",
        "description": "SMBv1 is obsolete and should not be enabled.",
        "cis_reference": "CIS Windows Benchmark: SMB settings (section no. to be confirmed)",
        "default_severity": "High",
        "check_description": "WinRM: (Get-SmbServerConfiguration).EnableSMB1Protocol",
        "remediation": "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
    },
    {
        "rule_id": "RDP-001", "title": "Remote Desktop (TCP 3389) not exposed unnecessarily",
        "description": "An open RDP port is an observation to review; it fails only where RDP is not required.",
        "cis_reference": "CIS Windows Benchmark: Remote Desktop Services (section no. to be confirmed)",
        "default_severity": "Medium",
        "check_description": "Nmap: state of TCP/3389",
        "remediation": "Disable Remote Desktop if not required, or restrict it by firewall rule/VPN.",
    },
    {
        "rule_id": "PWD-001", "title": "Minimum password length is at least 14",
        "description": "Short minimum password length weakens account security.",
        "cis_reference": "CIS Windows Benchmark: Account Policies - Password Policy (section no. to be confirmed)",
        "default_severity": "Medium",
        "check_description": "WinRM: net accounts (Minimum password length)",
        "remediation": "Set the minimum password length to 14 or more via local/group policy.",
    },
    {
        "rule_id": "LOCK-001", "title": "Account lockout threshold configured",
        "description": "A lockout threshold of 0 allows unlimited password guessing.",
        "cis_reference": "CIS Windows Benchmark: Account Policies - Account Lockout (section no. to be confirmed)",
        "default_severity": "Medium",
        "check_description": "WinRM: net accounts (Lockout threshold)",
        "remediation": "Set an account lockout threshold greater than 0 via local/group policy.",
    },
    {
        "rule_id": "ACC-001", "title": "Guest account disabled",
        "description": "The built-in Guest account should be disabled.",
        "cis_reference": "CIS Windows Benchmark: Local Policies - Security Options (section no. to be confirmed)",
        "default_severity": "Low",
        "check_description": "WinRM: Get-LocalUser -Name Guest | Select Enabled",
        "remediation": "Disable-LocalUser -Name Guest",
    },
    {
        "rule_id": "UPD-001", "title": "Windows Update service not disabled",
        "description": "Disabled update service prevents security patches from installing.",
        "cis_reference": "CIS Windows Benchmark: Windows Update (section no. to be confirmed)",
        "default_severity": "Medium",
        "check_description": "WinRM: Get-Service wuauserv | Select StartType",
        "remediation": "Set-Service wuauserv -StartupType Manual; Start-Service wuauserv",
    },
]

# What a healthy machine looks like for each rule (observed == expected -> passed).
EXPECTED = {
    "FW-001": "Domain/Private/Public = On",
    "SMB-001": "EnableSMB1Protocol = False",
    "RDP-001": "TCP/3389 not open",
    "PWD-001": ">= 14",
    "LOCK-001": "threshold > 0",
    "ACC-001": "Guest disabled",
    "UPD-001": "wuauserv not Disabled",
}
HEALTHY = {
    "FW-001": "Domain/Private/Public = On",
    "SMB-001": "EnableSMB1Protocol = False",
    "RDP-001": "TCP/3389 closed",
    "PWD-001": "14",
    "LOCK-001": "5",
    "ACC-001": "Guest disabled",
    "UPD-001": "wuauserv = Manual",
}

SCAN1 = {"start": "2026-10-05T10:00:00Z", "end": "2026-10-05T10:06:40Z"}
SCAN2 = {"start": "2026-10-10T10:00:00Z", "end": "2026-10-10T10:05:55Z"}

COMMON_PORTS_OPEN = [
    {"port": 135, "state": "open", "service_name": "msrpc"},
    {"port": 445, "state": "open", "service_name": "microsoft-ds"},
    {"port": 5985, "state": "open", "service_name": "wsman"},
    {"port": 3389, "state": "closed", "service_name": "ms-wbt-server"},
]
RDP_OPEN_PORTS = [
    {"port": 135, "state": "open", "service_name": "msrpc"},
    {"port": 445, "state": "open", "service_name": "microsoft-ds"},
    {"port": 5985, "state": "open", "service_name": "wsman"},
    {"port": 3389, "state": "open", "service_name": "ms-wbt-server"},
]


def _checks(stamp: str, failures: dict | None = None) -> list[dict]:
    """All rules passed, except those listed in `failures` {rule_id: observed_value}."""
    failures = failures or {}
    out = []
    for rule_id, expected in EXPECTED.items():
        if rule_id in failures:
            out.append({"rule_id": rule_id, "status": "failed", "observed_value": failures[rule_id],
                        "expected_value": expected, "checked_at": stamp})
        else:
            out.append({"rule_id": rule_id, "status": "passed", "observed_value": HEALTHY[rule_id],
                        "expected_value": expected, "checked_at": stamp})
    return out


def _host(ip, name, os_name, build, ports, checks, reachable=True, winrm="ok"):
    return {
        "ip": ip, "hostname": name, "is_reachable": reachable, "os_name": os_name,
        "os_version": "10.0" if reachable else None, "os_build": build,
        "winrm_status": winrm, "discovery_method": "SAMPLE: nmap host discovery",
        "ports": ports, "checks": checks,
    }


def build_hosts(stamp: str, scan_number: int) -> list[dict]:
    """The six sample hosts. scan_number 1 or 2 changes some results to tell a story."""
    w11, srv = "Windows 11 Pro", "Windows Server 2019"

    # 1. Clean machine: passes everything in both scans.
    clean = _host("192.168.56.10", "WS-CLEAN-01", w11, "22631", COMMON_PORTS_OPEN, _checks(stamp))

    # 2. Firewall off (+ Guest enabled) in scan 1, FIXED in scan 2.
    fw_fail = {"FW-001": "Public profile = Off", "ACC-001": "Guest enabled"} if scan_number == 1 else {}
    fw_off = _host("192.168.56.11", "WS-FW-OFF-01", w11, "22631", COMMON_PORTS_OPEN, _checks(stamp, fw_fail))

    # 3. SMBv1 enabled in both scans (unchanged finding / repeat offender).
    smb = _host("192.168.56.12", "SRV-SMB1-01", srv, "17763", COMMON_PORTS_OPEN,
                _checks(stamp, {"SMB-001": "EnableSMB1Protocol = True"}))

    # 4. RDP exposed in both scans; short password length appears only in scan 2 (NEW finding).
    rdp_fail = {"RDP-001": "TCP/3389 open"}
    if scan_number == 2:
        rdp_fail["PWD-001"] = "8"
    rdp = _host("192.168.56.13", "WS-RDP-01", w11, "22631", RDP_OPEN_PORTS, _checks(stamp, rdp_fail))

    # 5. WinRM authentication FAILED: only the Nmap-based rule (RDP-001) could be evaluated.
    #    All WinRM-based rules are filled in automatically as 'not_checked'.
    authfail = _host(
        "192.168.56.14", "WS-AUTHFAIL-01", w11, None, COMMON_PORTS_OPEN,
        [{"rule_id": "RDP-001", "status": "passed", "observed_value": "TCP/3389 closed",
          "expected_value": EXPECTED["RDP-001"], "checked_at": stamp}],
        winrm="auth_failed",
    )
    authfail["os_name"], authfail["os_version"] = None, None  # OS details need WinRM

    # 6. Unreachable machine: no ports, no checks -> all 'not_checked'.
    offline = _host("192.168.56.15", None, None, None, [], [], reachable=False, winrm="unreachable")
    offline["os_version"] = None

    return [clean, fw_off, smb, rdp, authfail, offline]


def _has_real_scans(db_path: Path) -> bool:
    if not db_path.exists():
        return False
    with db.connect(db_path) as conn:
        try:
            row = conn.execute("SELECT COUNT(*) AS n FROM scans WHERE is_sample = 0").fetchone()
        except Exception:
            return False  # tables not created yet
        return row["n"] > 0


def _remove_db_files(db_path: Path) -> None:
    for suffix in ("", "-wal", "-shm"):
        p = Path(str(db_path) + suffix)
        if p.exists():
            p.unlink()


def seed(db_path: Path) -> None:
    db.init_db(db_path)
    db.load_rules(SAMPLE_RULES, db_path)

    for number, window in ((1, SCAN1), (2, SCAN2)):
        scan_id = db.create_scan(
            scope="192.168.56.0/24", authorization_confirmed=True, started_by="sample-seed-script",
            notes=f"SAMPLE DATA (scan {number} of 2) - not a real scan", is_sample=True, db_path=db_path,
        )
        for host in build_hosts(window["start"], number):
            db.save_host_result(scan_id, host, db_path=db_path)
            if host["winrm_status"] == "auth_failed":
                db.log_event(scan_id, "WinRM authentication failed; WinRM-based checks not run",
                             "warning", host["ip"], db_path)
            if not host["is_reachable"]:
                db.log_event(scan_id, "Host did not respond to discovery", "warning", host["ip"], db_path)
        db.finish_scan(scan_id, "completed", db_path)

        # Make the sample timeline realistic (finish_scan stamps 'now').
        with db.connect(db_path) as conn, db.transaction(conn):
            conn.execute("UPDATE scans SET started_at = ?, finished_at = ? WHERE id = ?",
                         (window["start"], window["end"], scan_id))


def main() -> int:
    parser = argparse.ArgumentParser(description="Load SAMPLE data into the scanner database.")
    parser.add_argument("--db", default=str(db.DEFAULT_DB_PATH), help="database file path")
    parser.add_argument("--reset", action="store_true", help="wipe a sample-only database first")
    args = parser.parse_args()
    db_path = Path(args.db)

    if _has_real_scans(db_path):
        print("REFUSED: this database contains real (non-sample) scans. Use a different --db file.")
        return 1

    if args.reset:
        _remove_db_files(db_path)
    elif db_path.exists():
        with db.connect(db_path) as conn:
            try:
                existing = conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
            except Exception:
                existing = 0
        if existing:
            print(f"{db_path} already has {existing} scan(s). Run with --reset to reseed the sample data.")
            return 1

    seed(db_path)
    print(f"Sample data loaded into {db_path}  (SAMPLE DATA: 2 scans, 6 hosts, {len(SAMPLE_RULES)} rules)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
