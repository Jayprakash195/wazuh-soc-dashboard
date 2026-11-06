# Wazuh SOC Home Lab Dashboard
Flask + SQLite + vanilla JS + Chart.js dashboard for a Wazuh 4.14.8 home lab (SOC L1 portfolio). Starts in **DEMO** mode with no Wazuh connection needed.

## Lab
Wazuh Server 192.168.21.138 · Ubuntu Victim .144 · Kali Attacker .142 · Windows Agent 192.168.21.1

## Experiments represented
SSH brute force (5710, 2502, custom 100100, T1110) · FIM · Nmap recon (**log monitoring only; no automatic custom Nmap detection rule**) · hydratest user creation (5901/5902/5904/5555) · Windows failed logon (4625 / rule 60122).

## Setup (PowerShell, from G:\wazuh soc dashboard\wazuh-soc-dashboard)
    .\venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    python app.py          # http://127.0.0.1:5000
    pytest                 # run tests (no Wazuh needed)

## Data modes
- **DEMO** (default): sample alerts from `data/demo_alerts.json`. Timestamps and some levels are sample values, not your real alerts. Labeled DEMO.
- **IMPORTED**: paste a Wazuh alert JSON export in Settings. Original JSON is preserved.
- **LIVE**: only selectable after a successful sync. Copy `.env.example` to `.env` and fill in credentials, then use "Sync from Wazuh". Alerts are read from the Wazuh **Indexer** (`:9200`, `wazuh-alerts-*`); agent status from the manager API (`:55000`, JWT). This code has **not been verified against a live server**; confirm endpoints in the Wazuh 4.14 docs.
- TLS verification is on by default. For the lab's self-signed cert set `WAZUH_VERIFY_TLS` to your CA file path; `false` disables verification and exposes you to MITM.

## Notes
Evidence is metadata-only (no files are copied or served). Asset agent status stays "Unknown / Not verified" until a live sync succeeds. Add screenshots to a `docs/` folder and link them here.

## Future work
PDF export, evidence file browser with a safe directory, Nmap custom rule, scheduled sync.


## Sync and duplicate handling
- Open **Settings** in the sidebar and use **Sync from Wazuh**.
- The sync button shows progress, success, or failure.
- Live alerts use the Wazuh Indexer document `_id` as a stable identity when available.
- Imported alerts use their original `id` when present. Alerts without a stable ID are retained rather than deduplicated using a risky content hash.
- Existing databases receive a safe additive `external_id` column migration; tables and alert rows are not dropped.
- A successful sync timestamp means a sync was recorded successfully; it does not guarantee the Wazuh server is currently reachable.

## Verification note
The project source and Python syntax were checked during this update. The runtime environment used for this review did not have Flask installed and could not reach package indexes, so the pytest suite and live Wazuh connectivity could not be executed here. Install dependencies in your local virtual environment and run `pytest` before using the updated project.
