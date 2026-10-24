# Mini SIEM — SSH log analyzer

A small learning project that watches traditional `sshd` syslog entries, detects bursts of failed logins, stores alerts in SQLite, and shows recent alerts in a Flask/Chart.js dashboard. It is a demonstration of one detection rule, not a production SIEM.

## Quick demo

Requires Python 3.10+.

```bash
git clone https://github.com/khanakbhatia/mini-siem.git
cd mini-siem
python -m venv .venv
# macOS/Linux: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python src/main.py --once --year 2026
python src/api.py
```

Open http://127.0.0.1:5001. The sample log contains three separate bursts, so a fresh `data/alerts.db` produces **three alerts**. Delete the generated database before repeating the replay to avoid accumulating duplicate alerts.

For a clean, two-terminal live demo:

1. Run `python src/main.py` in terminal 1. By default, it starts at the *end* of `data/sample_auth.log` and waits for new lines.
2. Run `python src/api.py` in terminal 2 and open http://127.0.0.1:5001.
3. Run `python src/tests/attackgen.py` in terminal 3 to append eight failed logins over about 24 seconds. The fifth attempt triggers one alert. The dashboard polls every 10 seconds.

Use `python src/main.py --from-start` to process historical lines before monitoring new ones. Use `--once` for a finite replay. `--log PATH` and `--db PATH` accept alternative inputs/outputs. `--year YYYY` assigns a year to syslog records, which contain only month, day, and time.

Run the tests with `python -m unittest discover -s tests -v`.

## How it works

- `src/parser.py` extracts timestamps, user names, and IPv4 source addresses from SSH failed-password lines in traditional syslog format. Unrelated lines are ignored by the detector.
- `src/detectors.py` keeps a queue of recent failures per source IP. It discards attempts older than 60 seconds and triggers when the queue reaches **five** failures. Only one alert is issued for a continuous burst; another can fire after the count drops below five and reaches five again.
- `src/storage.py` records alert creation time in UTC and the rule details as JSON in SQLite.
- `src/main.py` tails a local file or replays it once. `src/api.py` returns the latest 50 alerts through `/api/alerts`; the browser charts and table refresh every 10 seconds. The summary cards and charts describe these *recent 50*, not all historical alerts.

## Limits and next steps

The rule detects a pattern for investigation, not proof of malicious activity. Shared IPs and mistyped passwords can trigger it. It assumes chronologically ordered events, a single traditional SSH log format with IPv4 addresses, and one process holding detection state in memory. Restarting the monitor resets the window, and replaying the same data into an existing database duplicates alerts. A production design would track offsets and rotations, handle more event sources and IPv6, persist rule state, measure false positives, and support authentication and access controls. The dashboard is meant for **local use**.
