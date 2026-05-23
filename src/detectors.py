
from collections import defaultdict, deque
import time


class BruteForceDetector:
    def __init__(self, window_seconds=60, threshold=5):
        self.window = window_seconds
        self.threshold = threshold
        self.failed = defaultdict(deque) # ip -> deque([timestamp_seconds])


    def add_event(self, event):
    # event must have 'type' and 'timestamp' and 'ip'
        if event.get('type') != 'auth_fail' or not event.get('ip'):
            return None


        ip = event['ip']
        ts = event['timestamp'].timestamp() # seconds as float
        dq = self.failed[ip]
        dq.append(ts)


        cutoff = ts - self.window
        # remove old timestamps
        while dq and dq[0] < cutoff:
            dq.popleft()


# Trigger when count strictly greater than threshold.
# Adjust to >= if you want threshold to be inclusive.
        if len(dq) > self.threshold:
            return {
                'alert_type': 'brute_force',
                'ip': ip,
                'count': len(dq),
                'window': self.window,
                'first_seen': dq[0],
                'last_seen': dq[-1]}
        return None