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
                simulated INTEGER NOT NULL DEFAULT 0, enrichment TEXT,
                path TEXT, destination_ip TEXT, destination_port INTEGER,
                http_status INTEGER, connection_outcome TEXT
            );
            CREATE TABLE IF NOT EXISTS incidents (
                id INTEGER PRIMARY KEY, ip TEXT, first_event_ts TEXT, last_event_ts TEXT,
                status TEXT NOT NULL DEFAULT 'new', risk INTEGER NOT NULL DEFAULT 0,
                entity_key TEXT
            );
            CREATE TABLE IF NOT EXISTS incident_alerts (
                incident_id INTEGER NOT NULL, alert_id INTEGER NOT NULL UNIQUE
            );
            CREATE TABLE IF NOT EXISTS alert_evidence (
                alert_id INTEGER NOT NULL, event_id INTEGER NOT NULL,
                PRIMARY KEY(alert_id,event_id)
            );
            CREATE TABLE IF NOT EXISTS ingest_offsets (
                path TEXT PRIMARY KEY, device INTEGER NOT NULL, inode INTEGER NOT NULL,
                offset INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS incident_actions (
                id INTEGER PRIMARY KEY, incident_id INTEGER NOT NULL,
                ts TEXT NOT NULL, actor TEXT NOT NULL, old_status TEXT NOT NULL,
                new_status TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON events(ip,ts);
            CREATE INDEX IF NOT EXISTS idx_events_type_ts ON events(type,ts);
        """)
        # Additive migration for databases created by earlier versions.
        for table, columns in {
            "events": {"path": "TEXT", "destination_ip": "TEXT", "destination_port": "INTEGER",
                       "http_status": "INTEGER", "connection_outcome": "TEXT"},
            "incidents": {"entity_key": "TEXT"},
        }.items():
            existing = {r[1] for r in self.conn.execute(f"PRAGMA table_info({table})")}
            for column, kind in columns.items():
                if column not in existing:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")
        self.conn.commit()

    def insert_event(self, event):
        fingerprint = hashlib.sha256((event.get("origin") or event["source"] + "\0" + event["raw_event"]).encode()).hexdigest()
        cursor = self.conn.execute(
            "INSERT OR IGNORE INTO events (fingerprint,ts,source,type,ip,username,host,raw_event,simulated,enrichment,path,destination_ip,destination_port,http_status,connection_outcome) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (fingerprint, event["timestamp"].isoformat(), event["source"], event["type"],
             event.get("ip"), event.get("username"), event.get("host"), event["raw_event"],
             int(event.get("simulated", False)), json.dumps(event.get("enrichment")),
             event.get("msg") if event["type"] == "web_request" else None,
             event.get("destination_ip"), event.get("destination_port"),
             event.get("http_status"), event.get("connection_outcome")),
        )
        self.conn.commit()
        return cursor.lastrowid if cursor.rowcount else None

    def set_enrichment(self, event_id, result):
        self.conn.execute("UPDATE events SET enrichment=? WHERE id=?", (json.dumps(result), event_id))
        self.conn.commit()

    def offset(self, path):
        return self.conn.execute("SELECT * FROM ingest_offsets WHERE path=?", (str(path),)).fetchone()

    def set_offset(self, path, stat, offset):
        self.conn.execute("INSERT INTO ingest_offsets (path,device,inode,offset) VALUES (?,?,?,?) "
                          "ON CONFLICT(path) DO UPDATE SET device=excluded.device,inode=excluded.inode,offset=excluded.offset",
                          (str(path), stat.st_dev, stat.st_ino, offset))
        self.conn.commit()

    def restore_events(self):
        """Replay stored detector inputs to restore window and suppression state."""
        for r in self.conn.execute("SELECT * FROM events ORDER BY ts,id"):
            yield {"timestamp": datetime.fromisoformat(r["ts"]), "type": r["type"],
                   "ip": r["ip"], "username": r["username"], "host": r["host"], "msg": r["path"],
                   "destination_ip": r["destination_ip"], "destination_port": r["destination_port"],
                   "http_status": r["http_status"], "connection_outcome": r["connection_outcome"]}

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
        # Separate hosts sharing an address. Missing IP stays separate.
        ip = event.get("ip")
        entity_key = json.dumps([ip, event.get("host")]) if ip else None
        incident = self.conn.execute(
            "SELECT * FROM incidents WHERE entity_key=? ORDER BY id DESC LIMIT 1", (entity_key,)
        ).fetchone() if entity_key else None
        from datetime import timedelta
        if incident and timedelta(0) <= event["timestamp"] - datetime.fromisoformat(incident["last_event_ts"]) <= timedelta(minutes=30):
            incident_id = incident["id"]
            scores = [(r[0], r[1]) for r in self.conn.execute(
                "SELECT CAST(json_extract(a.details,'$.risk') AS INTEGER),a.alert_type FROM alerts a JOIN incident_alerts ia ON ia.alert_id=a.id WHERE ia.incident_id=?",
                (incident_id,))]
            scores.append((risk, rule))
            incident_risk = min(100, max(score for score, _ in scores) +
                                (5 if any(kind == "failure_then_success" for _, kind in scores) else 0))
            self.conn.execute("UPDATE incidents SET last_event_ts=?,risk=? WHERE id=?",
                              (event["timestamp"].isoformat(), incident_risk, incident_id))
        else:
            incident_id = self.conn.execute(
                "INSERT INTO incidents (ip,first_event_ts,last_event_ts,risk,entity_key) VALUES (?,?,?,?,?)",
                (ip, event["timestamp"].isoformat(), event["timestamp"].isoformat(),
                 min(100, risk + (5 if rule == "failure_then_success" else 0)), entity_key),
            ).lastrowid
        self.conn.execute("INSERT INTO incident_alerts VALUES (?,?)", (incident_id, alert_id))
        self.conn.commit()
        return alert_id

    def events(self, limit=100, ip=None, kind=None, username=None, host=None, source=None,
               path_contains=None, destination_ip=None, destination_port=None,
               http_status=None, connection_outcome=None):
        return [dict(r) for r in self.conn.execute(
            "SELECT * FROM events WHERE (? IS NULL OR ip=?) AND (? IS NULL OR type=?) "
            "AND (? IS NULL OR username=?) AND (? IS NULL OR host=?) AND (? IS NULL OR source=?) "
            "AND (? IS NULL OR instr(path,?)>0) AND (? IS NULL OR destination_ip=?) "
            "AND (? IS NULL OR destination_port=?) AND (? IS NULL OR http_status=?) "
            "AND (? IS NULL OR connection_outcome=?) ORDER BY id DESC LIMIT ?",
            (ip, ip, kind, kind, username, username, host, host, source, source,
             path_contains, path_contains, destination_ip, destination_ip, destination_port, destination_port,
             http_status, http_status, connection_outcome, connection_outcome, min(limit, 500)))]

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

    def set_status(self, incident_id, status, actor="local-analyst"):
        if status not in {"new", "investigating", "resolved", "false_positive"}:
            raise ValueError("Invalid status")
        current = self.conn.execute("SELECT status FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not current:
            return False
        if current["status"] == status:
            return True
        cursor = self.conn.execute("UPDATE incidents SET status=? WHERE id=?", (status, incident_id))
        self.conn.execute("INSERT INTO incident_actions (incident_id,ts,actor,old_status,new_status) VALUES (?,?,?,?,?)",
                          (incident_id, datetime.now(timezone.utc).isoformat(), actor, current["status"], status))
        self.conn.commit()
        return cursor.rowcount > 0

    def actions(self, incident_id):
        return [dict(r) for r in self.conn.execute(
            "SELECT ts,actor,old_status,new_status FROM incident_actions WHERE incident_id=? ORDER BY id", (incident_id,))]

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
