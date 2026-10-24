"""SQLite persistence for alerts."""

import json
import hashlib
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
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL,
                ts TEXT NOT NULL, source TEXT NOT NULL, type TEXT NOT NULL,
                ip TEXT, username TEXT, host TEXT, raw_event TEXT NOT NULL,
                simulated INTEGER NOT NULL DEFAULT 0, enrichment TEXT
            );
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY, ip TEXT, first_event_ts TEXT, last_event_ts TEXT,
                status TEXT NOT NULL DEFAULT 'new', risk INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS incident_alerts (
                incident_id INTEGER NOT NULL, alert_id INTEGER NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS alert_evidence (
                alert_id INTEGER NOT NULL, event_id INTEGER NOT NULL,
                PRIMARY KEY(alert_id,event_id)
            );
        """)
        self.conn.commit()

    def insert_event(self, event):
        fingerprint = hashlib.sha256((event["source"] + "\0" + event["raw_event"]).encode()).hexdigest()
        cursor = self.conn.execute(
            "INSERT OR IGNORE INTO events (fingerprint,ts,source,type,ip,username,host,raw_event,simulated,enrichment) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (fingerprint, event["timestamp"].isoformat(), event["source"], event["type"],
             event.get("ip"), event.get("username"), event.get("host"), event["raw_event"],
             int(event.get("simulated", False)), json.dumps(event.get("enrichment"))),
        )
        self.conn.commit()
        return cursor.lastrowid if cursor.rowcount else None

    def add_detection(self, alert, event, event_id, evidence_ids=None):
        rule = alert["alert_type"]
        base = {"brute_force": 55, "failure_then_success": 80,
                "suspicious_web_request": 45, "port_scan": 50, "indicator_match": 60}[rule]
        # Heuristic priority, not a probability. Intelligence adds one capped signal.
        intel = event.get("enrichment") or {}
        risk = min(100, base + (15 if intel.get("status") == "match" else 0))
        alert = dict(alert, rule_id={"brute_force": "AUTH-001", "failure_then_success": "AUTH-002",
                                  "suspicious_web_request": "WEB-001", "port_scan": "NET-001",
                                  "indicator_match": "IOC-001"}[rule], risk=risk,
                     enrichment=intel, event_id=event_id,
                     attack={"brute_force": "T1110", "failure_then_success": "T1110",
                             "suspicious_web_request": "T1190", "port_scan": None,
                             "indicator_match": None}[rule])
        cursor = self.conn.execute(
            "INSERT INTO alerts (ts,alert_type,ip,details) VALUES (?,?,?,?)",
            (event["timestamp"].isoformat(), rule, alert.get("ip"), json.dumps(alert)),
        )
        alert_id = cursor.lastrowid
        for eid in set([event_id] + (evidence_ids or [])):
            self.conn.execute("INSERT OR IGNORE INTO alert_evidence VALUES (?,?)", (alert_id, eid))
        # Correlate by source IP and event time, within 30 minutes. Missing IP stays separate.
        ip = event.get("ip")
        incident = self.conn.execute(
            "SELECT * FROM incidents WHERE ip=? ORDER BY id DESC LIMIT 1", (ip,)
        ).fetchone() if ip else None
        from datetime import timedelta
        if incident and abs(datetime.fromisoformat(incident["last_event_ts"]) - event["timestamp"]) <= timedelta(minutes=30):
            incident_id = incident["id"]
            self.conn.execute("UPDATE incidents SET last_event_ts=?,risk=? WHERE id=?",
                              (event["timestamp"].isoformat(), min(100, max(incident["risk"], risk) + (5 if rule == "failure_then_success" else 0)), incident_id))
        else:
            incident_id = self.conn.execute(
                "INSERT INTO incidents (ip,first_event_ts,last_event_ts,risk) VALUES (?,?,?,?)",
                (ip, event["timestamp"].isoformat(), event["timestamp"].isoformat(), risk),
            ).lastrowid
        self.conn.execute("INSERT INTO incident_alerts VALUES (?,?)", (incident_id, alert_id))
        self.conn.commit()
        return alert_id

    def events(self, limit=100, ip=None):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM events WHERE (? IS NULL OR ip=?) ORDER BY id DESC LIMIT ?", (ip, ip, min(limit, 500)))]

    def incidents(self):
        return [dict(r) for r in self.conn.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 100")]

    def incident(self, incident_id):
        row = self.conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not row:
            return None
        item = dict(row)
        item["alerts"] = [dict(r) for r in self.conn.execute(
            "SELECT a.id,a.ts,a.alert_type,a.ip,a.details FROM alerts a JOIN incident_alerts ia ON a.id=ia.alert_id WHERE ia.incident_id=? ORDER BY a.id", (incident_id,))]
        item["events"] = [dict(r) for r in self.conn.execute(
            "SELECT DISTINCT e.* FROM events e JOIN alert_evidence ae ON e.id=ae.event_id JOIN incident_alerts ia ON ia.alert_id=ae.alert_id WHERE ia.incident_id=? ORDER BY e.ts,e.id", (incident_id,))]
        return item

    def set_status(self, incident_id, status):
        if status not in {"new", "investigating", "resolved", "false_positive"}:
            raise ValueError("Invalid status")
        cursor = self.conn.execute("UPDATE incidents SET status=? WHERE id=?", (status, incident_id))
        self.conn.commit()
        return cursor.rowcount > 0

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
