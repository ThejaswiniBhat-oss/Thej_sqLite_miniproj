# Database part: Windows Vulnerability & Network Scanner

SQLite database, write layer, dashboard queries, sample data and a self-check.
**Only Python is required** (3.10+, tested on 3.13). PyYAML is needed only to load the YAML rulebook.

## What is in this folder

| File | Purpose |
|---|---|
| `schema.sql` | The tables, keys and constraints (the blueprint) |
| `er_diagram.png` / `er_diagram.mmd` | ER diagram for slides (PNG, or Mermaid code to paste into mermaid.live) |
| `db.py` | Safe write layer. The scanner and rule-engine teammates call this |
| `queries.py` | Read-only dashboard queries. The dashboard teammate calls this |
| `seed_data.py` | **SAMPLE** data: 6 hosts, 2 scans, 7 rules (clearly flagged as sample) |
| `rules_sample.yaml` | Example rulebook in the format `db.load_rules_from_yaml()` reads |
| `demo_queries.sql` | 10 ready-made queries to run inside DB Browser for SQLite |
| `verify.py` | Automated self-check (32 checks, uses a temporary database) |
| `INTERFACE_CONTRACT.md` | The exact data shapes teammates must send. **Share this with them tonight** |

## Setup (one time)

Open a terminal **in this folder** (in File Explorer, click the address bar, type `cmd`, press Enter).

```
python --version
python -m venv venv
venv\Scripts\activate
pip install pyyaml
```
(`pip install pyyaml` is optional. Skip it if you will not load the YAML rulebook.)
On Mac/Linux, activate with `source venv/bin/activate`.

## Run and check it (about 5 minutes)

**Step 1: run the self-check**
```
python verify.py
```
Expected last line: `32 of 32 checks passed.` (31 of 31 plus a SKIP line if PyYAML is not installed.)
Any `[FAIL]` line names the rule that broke.

**Step 2: create the sample database**
```
python seed_data.py
```
Expected: `Sample data loaded into ...vulnscan.db  (SAMPLE DATA: 2 scans, 6 hosts, 7 rules)`.
To start over: `python seed_data.py --reset` (it refuses to wipe a database that holds real scans).

**Step 3: look at the data in DB Browser for SQLite**
1. Open DB Browser, then **File > Open Database**. If you do not see the file, set the file type filter to *All files*. Pick `vulnscan.db`.
2. **Database Structure** tab: you should see 8 tables (`scans`, `hosts`, `ports`, `rules`, `check_results`, `cve_cache`, `check_result_cves`, `scan_log`), plus a small `sqlite_sequence` table that SQLite creates by itself.
3. **Browse Data** tab: pick `check_results` from the dropdown. Rows with status `not_checked` and a `reason_not_checked` are the hosts where WinRM failed or the host was unreachable.
4. **Execute SQL** tab: open `demo_queries.sql` (folder icon), **highlight one query**, press **Ctrl+Return**. Only the highlighted text runs.

**Step 3b: open it read-only** (**File > Open Database Read Only**) while your teammates are running scans, so DB Browser cannot lock the file.

**Step 4: try the Python queries**
```
python -c "import queries, json; print(json.dumps(queries.scan_summary(queries.latest_scan_id()), indent=2))"
```

## What you should see (sample data, latest scan)

| Host | Story | Result |
|---|---|---|
| 192.168.56.10 | Clean machine | Clean, 100% |
| 192.168.56.11 | Firewall off + Guest enabled in scan 1, **fixed** in scan 2 | Clean in scan 2 |
| 192.168.56.12 | SMBv1 enabled in both scans | High finding (repeat offender) |
| 192.168.56.13 | RDP exposed in both scans; weak password length appears in scan 2 | Medium findings |
| 192.168.56.14 | WinRM login failed | **Partially checked**: 1 rule evaluated, 6 `not_checked` |
| 192.168.56.15 | Did not respond | **Not checked** |

Scan 1 to scan 2: **1 new**, **2 fixed**, **2 unchanged**. Failed findings fall from **4 to 3**.

## Suggested 3-minute demo for tomorrow

1. Show `er_diagram.png`: "8 tables, one per concept in our methodology."
2. Open `vulnscan.db` in DB Browser, show `check_results`: "A check that cannot run is stored as **not_checked** with a reason. It is never counted as passed."
3. Run demo query **Q4** (compliance + coverage) and **Q10** (fixed between scans).
4. Say: "This is **sample data**. The scanner and dashboard connect through `INTERFACE_CONTRACT.md`."

## Design choices you can defend

- **not_checked is a first-class status.** The database blocks a `failed` result without a severity and a `not_checked` result without a reason.
- **Compliance % excludes not_checked but is always shown beside coverage %**, so "100%" on a barely-checked host cannot mislead.
- **Open ports are observations** (`ports` table), not findings. Only rule results (`check_results`) can fail.
- **Severity is project severity.** CVSS exists only in the optional `cve_cache` table.
- **No credentials are stored.** No column holds one, and the write layer rejects password/token-style keys.
- **Authorization is enforced:** `create_scan()` refuses to start without it.
- **Safe for parallel workers:** one connection per call, WAL mode, busy timeout, short `BEGIN IMMEDIATE` transactions (tested with 8 threads).
- **Parameterised SQL everywhere**, so SQL injection is not possible through hostnames or values (tested).
- **Compare scans honestly:** a finding is only "fixed" if it now **passed**. If it could not be re-checked it is `not_verified`.

## Honest limits (say these if asked)

- Everything in `seed_data.py` is **sample data**. Real results appear only when the scanner calls `save_host_result()`.
- `cis_reference` values say "section no. to be confirmed". Fill in the exact recommendation numbers from your licensed copy of the CIS benchmark for the Windows version you test. Do not copy benchmark text into the project.
- `cve_cache` is created but empty. Fill it only when software and version match a CVE reliably.
- This part does not scan anything. It stores and reports what the scanner sends.
- Hosts are stored per scan and compared by IP address. If a machine's IP changes between scans, it appears as a different host.
- SQLite is right for a prototype. For a larger deployment, move to PostgreSQL (future scope).

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'db'` | Run commands from **inside this folder** |
| `database is locked` | Close DB Browser, or open the file read-only |
| `No module named 'yaml'` | `pip install pyyaml` (only needed for YAML rulebooks) |
| `seed_data.py` says "already has N scan(s)" | Use `python seed_data.py --reset` |
| `REFUSED: ... contains real scans` | Intended safety. Use another file: `python seed_data.py --db demo.db` |
| `pip` says "Defaulting to user installation" | Harmless notice. The install worked |
