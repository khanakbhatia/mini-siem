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
                        "explanation": "Request path matches a traversal or SQL injection pattern; exploitation is unconfirmed."}
            return None
        if kind == "network_connection" and ip and event.get("destination_port"):
            ts = event["timestamp"].timestamp()
            attempts = self.scans[ip]
            while attempts and attempts[0][0] < ts - self.window:
                attempts.popleft()
            attempts.append((ts, event["destination_port"]))
            ports = {port for _, port in attempts}
            if len(ports) < 5:
                self.scan_active.discard(ip)
            elif ip not in self.scan_active:
                self.scan_active.add(ip)
                return {"alert_type": "port_scan", "ip": ip, "ports": sorted(ports),
                        "window": self.window, "explanation": "Observed attempts to five distinct destination ports; connection success is unknown."}
            return None
        if kind == "auth_success" and ip:
            ts = event["timestamp"].timestamp()
            recent = [t for t in self.failed[ip] if ts - self.window <= t <= ts]
            if len(recent) >= self.threshold:
                return {"alert_type": "failure_then_success", "ip": ip,
                        "username": event.get("username"), "count": len(recent), "window": self.window,
                        "explanation": "Success from a source with repeated recent failures; verify the account and session."}
            return None
        if kind != "auth_fail" or not ip:
            return None
        ts = event["timestamp"].timestamp()
        attempts = self.failed[ip]
        # Input is expected in chronological order, as with a tailed log.
        while attempts and attempts[0] < ts - self.window:
            attempts.popleft()
        attempts.append(ts)

        if len(attempts) < self.threshold:
            self.active.discard(ip)
            return None
        if ip in self.active:
            return None  # One alert per continuous burst, not one per attempt.

        self.active.add(ip)
        return {
            "alert_type": "brute_force",
            "ip": ip,
            "count": len(attempts),
            "window": self.window,
            "first_seen": attempts[0],
            "last_seen": attempts[-1],
            "explanation": f"{len(attempts)} failed logins from this IP within {self.window} seconds.",
        }
