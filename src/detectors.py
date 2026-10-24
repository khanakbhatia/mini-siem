"""Small, explainable rule for repeated failed SSH logins."""

from collections import defaultdict, deque


class BruteForceDetector:
    def __init__(self, window_seconds=60, threshold=5):
        if window_seconds <= 0 or threshold <= 0:
            raise ValueError("window_seconds and threshold must be positive")
        self.window = window_seconds
        self.threshold = threshold
        self.failed = defaultdict(deque)
        self.active = set()

    def add_event(self, event):
        if event.get("type") != "auth_fail" or not event.get("ip"):
            return None

        ip = event["ip"]
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
        }
