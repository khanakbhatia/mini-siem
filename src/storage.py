import sqlite3
import os
from datetime import datetime

class Storage:
    def __init__(self, path='../data/alerts.db'):
        # Make sure folder exists
        os.makedirs(os.path.dirname(path), exist_ok=True)
        # Connect to database
        self.conn = sqlite3.connect(path, check_same_thread=False)
        # Setup tables
        self._setup()

    def _setup(self):
        c = self.conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                alert_type TEXT,
                ip TEXT,
                details TEXT
            )
        ''')
        self.conn.commit()

    def insert_alert(self, alert_type, ip, details):
        c = self.conn.cursor()
        c.execute(
            "INSERT INTO alerts (ts, alert_type, ip, details) VALUES (?, ?, ?, ?)",
            (datetime.utcnow().isoformat(), alert_type, ip, str(details))
        )
        self.conn.commit()

    def recent_alerts(self, limit=5):
        c = self.conn.cursor()
        c.execute("SELECT ts, alert_type, ip, details FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
        return c.fetchall()