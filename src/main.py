"""Tail a syslog file, or replay it once for a reproducible demo."""

import argparse
import time
from pathlib import Path

from detectors import BruteForceDetector
from parser import parse_line
from intel import LocalIntel
from storage import DEFAULT_DB, Storage

DEFAULT_LOG = Path(__file__).resolve().parents[1] / "data" / "sample_auth.log"


def follow(path, from_start=False, poll_interval=0.3):
    with open(path, encoding="utf-8") as source:
        if not from_start:
            source.seek(0, 2)
        while True:
            line = source.readline()
            if line:
                yield line
            else:
                if path.stat().st_size < source.tell():
                    source.seek(0)  # Handle truncation of the same file.
                time.sleep(poll_interval)


def process_lines(lines, store, detector, year=None):
    count = 0
    intel = LocalIntel()
    for line in lines:
        event = parse_line(line, year=year)
        if event is None:
            continue
        event['enrichment'] = intel.lookup(event.get('ip'))
        event_id = store.insert_event(event)
        if event_id is None:
            continue  # Idempotent replay of identical source/raw record.
        alert = detector.add_event(event)
        if alert:
            evidence_ids = []
            if alert['alert_type'] in {'brute_force', 'failure_then_success'}:
                from datetime import timedelta
                start = (event['timestamp'] - timedelta(seconds=detector.window)).isoformat()
                evidence_ids = [r['id'] for r in store.conn.execute(
                    "SELECT id FROM events WHERE ip=? AND type='auth_fail' AND ts>=? AND ts<=? ORDER BY id",
                    (event['ip'], start, event['timestamp'].isoformat()))]
            store.add_detection(alert, event, event_id, evidence_ids)
            print(f"ALERT: {alert}", flush=True)
            count += 1
    return count


def run(argv=None):
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument("--log", type=Path, default=DEFAULT_LOG)
    cli.add_argument("--db", type=Path, default=DEFAULT_DB)
    cli.add_argument("--from-start", action="store_true", help="read existing lines before tailing")
    cli.add_argument("--once", action="store_true", help="process existing lines then exit")
    cli.add_argument("--year", type=int, help="year for syslog lines (which lack a year)")
    args = cli.parse_args(argv)
    detector = BruteForceDetector(window_seconds=60, threshold=5)
    store = Storage(args.db)
    try:
        if args.once:
            with args.log.open(encoding="utf-8") as source:
                print(f"Processed log; created {process_lines(source, store, detector, args.year)} alert(s).")
        else:
            print(f"Monitoring {args.log} (Ctrl+C to stop)", flush=True)
            process_lines(follow(args.log, args.from_start), store, detector, args.year)
    except KeyboardInterrupt:
        print("Stopped.")
    finally:
        store.close()


if __name__ == "__main__":
    run()
