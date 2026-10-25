"""Small, explainable rule for repeated failed SSH logins."""

from collections import defaultdict, deque
import re
from urllib.parse import unquote


class BruteForceDetector:
    def __init__(self, window_seconds=60, threshold=5):
        if window_seconds <= 0 or threshold <= 0:
            raise ValueError("window_seconds and threshold must be positive")
        self.window = window_seconds
        self.threshold = threshold
        self.failed = defaultdict(deque)
        self.active = set()
        self.scans = defaultdict(deque)
        self.scan_active = set()

    def add_event(self, event):
        kind, ip = event.get("type"), event.get("ip")
        if kind == "web_request":
            path = unquote(event.get("msg") or "")[:2048]
            if re.search(r"(?:\.\./|\bunion\s+select\b|['\"]\s+or\s+1\s*=\s*1)", path, re.I):
                return {"alert_type": "suspicious_web_request", "ip": ip, "path": path,
                        "http_status": event.get("http_status"),
                        "explanation": "Request path matches a traversal or SQL injection pattern; exploitation is unconfirmed."}
            return None
        if kind == "network_connection" and ip and event.get("destination_port"):
            ts = event["timestamp"].timestamp()
            key = (ip, event.get("destination_ip"))
            attempts = self.scans[key]
            while attempts and attempts[0][0] < ts - self.window:
                attempts.popleft()
            attempts.append((ts, event["destination_port"]))
            ports = {port for _, port in attempts}
            if len(ports) < 5:
                self.scan_active.discard(key)
            elif key not in self.scan_active:
                self.scan_active.add(key)
                return {"alert_type": "port_scan", "ip": ip, "ports": sorted(ports),
                        "destination_ip": event.get("destination_ip"),
                        "connection_outcome": event.get("connection_outcome"),
                        "window": self.window, "explanation": "Observed traffic to five distinct destination ports; individual connection outcomes require review."}
            return None
        if kind == "auth_success" and ip:
            ts = event["timestamp"].timestamp()
            auth_key = (ip, event.get("host"))
            candidates = [(t, user) for t, user in self.failed[auth_key] if ts - self.window <= t <= ts]
            username = event.get("username")
            # If both sides identify accounts, require the successful account to match.
            named = any(user for _, user in candidates)
            recent = [(t, user) for t, user in candidates if not (username and named) or user == username]
            if len(recent) >= self.threshold:
                return {"alert_type": "failure_then_success", "ip": ip,
                        "username": username, "count": len(recent), "window": self.window,
                        "identity_match": bool(username and named),
                        "explanation": "Success after repeated recent failures for the same account and source." if username and named else "Success from a source with repeated failures; account identity was unavailable."}
            return None
        if kind != "auth_fail" or not ip:
            return None
        ts = event["timestamp"].timestamp()
        auth_key = (ip, event.get("host"))
        attempts = self.failed[auth_key]
        # Input is expected in chronological order, as with a tailed log.
        while attempts and attempts[0][0] < ts - self.window:
            attempts.popleft()
        attempts.append((ts, event.get("username")))

        if len(attempts) < self.threshold:
            self.active.discard(auth_key)
            return None
        if auth_key in self.active:
            return None  # One alert per continuous burst, not one per attempt.

        self.active.add(auth_key)
        return {
            "alert_type": "brute_force",
            "ip": ip,
            "count": len(attempts),
            "window": self.window,
            "first_seen": attempts[0][0],
            "last_seen": attempts[-1][0],
            "explanation": f"{len(attempts)} failed logins from this IP within {self.window} seconds.",
        }
