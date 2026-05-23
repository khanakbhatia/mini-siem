# Mini SIEM — Log Analyzer & Threat Dashboard

A lightweight Security Information and Event Management (SIEM) tool 
that parses system auth logs, detects threats in real time, and 
visualises security events on a live dashboard.

## Features
- Real-time log tailing — monitors auth logs as they update
- Brute force detection using a sliding window algorithm
- SQLite storage for all triggered alerts
- Live dashboard with Chart.js — alerts by type, top IPs, recent events
- Auto-refreshes every 10 seconds

## Tech Stack
Python · Flask · SQLite · Chart.js · Regex

## How to Run
```bash
git clone https://github.com/khanakbhatia/mini-siem
cd mini-siem
pip install -r requirements.txt

# Terminal 1 — run the log monitor
cd src
python main.py

# Terminal 2 — run the dashboard
cd src
python api.py
```
Open http://127.0.0.1:5001 in your browser.

## How it works
- `parser.py` — parses syslog format lines using regex into structured events
- `detectors.py` — sliding window brute force detector: flags IPs with 5+ failed auths in 60 seconds
- `storage.py` — SQLite layer for persisting alerts
- `api.py` — Flask server serving the dashboard and REST API
- `main.py` — tails the log file in real time and pipes events through detectors
