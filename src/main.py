import time
from parser import parse_syslog_line
from detectors import BruteForceDetector
from storage import Storage

LOGFILE = '../data/sample_auth.log'

def follow(path):
    with open(path, 'r') as f:
        f.seek(0, 2) # go to end
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.3)
                continue
            yield line


def run():
    detector = BruteForceDetector(window_seconds=60, threshold=5)
    store = Storage()

    for line in follow(LOGFILE):
        ev = parse_syslog_line(line)
        if not ev:
            continue
        alert = detector.add_event(ev)
        if alert:
            print(f"ALERT: {alert}")
            store.insert_alert(alert['alert_type'], alert['ip'], alert)


if __name__ == '__main__':
    run()