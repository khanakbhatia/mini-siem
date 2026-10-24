"""SQLite persistence for alerts."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parents[1] / "data" / "alerts.db"


class Storage:
    def __init__(self, path=DEFAULT_DB):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                alert_type TEXT,
                ip TEXT,
                details TEXT
            )
        """)
        self.conn.commit()

    def insert_alert(self, alert_type, ip, details):
        self.conn.execute(
            "INSERT INTO alerts (ts, alert_type, ip, details) VALUES (?, ?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), alert_type, ip, json.dumps(details)),
        )
        self.conn.commit()

    def recent_alerts(self, limit=50):
        return self.conn.execute(
            "SELECT ts, alert_type, ip, details FROM alerts ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()

    def close(self):
        self.conn.close()
