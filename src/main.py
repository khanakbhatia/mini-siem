"""Ingest a log file once or monitor it with durable offsets and rule-state recovery."""

import argparse
import hashlib
import time
from datetime import timedelta
from pathlib import Path

from detectors import BruteForceDetector
from parser import parse_line
from intel import build_intel
from storage import DEFAULT_DB, Storage

DEFAULT_LOG = Path(__file__).resolve().parents[1] / "data" / "sample_auth.log"
MAX_LINE = 65536


def process_record(line, store, detector, intel, year=None, origin=None):
    event = parse_line(line, year=year)
    if event is None:
        return 0
    if origin:
        event['origin'] = origin
    # Insert before optional network lookup: duplicate replays never consume provider quota.
    event_id = store.insert_event(event)
    if event_id is None:
        return 0
    event['enrichment'] = intel.lookup(event.get('ip'))
    store.set_enrichment(event_id, event['enrichment'])
    alert = detector.add_event(event)
    if not alert:
        return 0
    evidence_ids = []
    if alert['alert_type'] in {'brute_force', 'failure_then_success'}:
        start = (event['timestamp'] - timedelta(seconds=detector.window)).isoformat()
        sql = "SELECT id,username FROM events WHERE ip=? AND host IS ? AND type='auth_fail' AND ts>=? AND ts<=? ORDER BY id"
        failures = store.conn.execute(sql, (event['ip'], event.get('host'), start, event['timestamp'].isoformat())).fetchall()
        if alert['alert_type'] == 'failure_then_success' and alert.get('identity_match'):
            failures = [r for r in failures if r['username'] == event.get('username')]
        evidence_ids = [r['id'] for r in failures]
    store.add_detection(alert, event, event_id, evidence_ids)
    print(f"ALERT: {alert}", flush=True)
    return 1


def process_lines(lines, store, detector, year=None, intel=None):
    """Process arbitrary line streams; repeat identical records are idempotent."""
    intel = intel or build_intel()
    return sum(process_record(line, store, detector, intel, year) for line in lines)


def restore_detector(store, detector):
    """Replay persisted normalized inputs into the state machine, without new alerts."""
    for event in store.restore_events():
        detector.add_event(event)


def file_records(path, store, from_start=False, once=False, poll_interval=0.3):
    """Yield complete lines with stable file-position IDs and checkpoint metadata."""
    path = path.resolve()
    first = True
    while True:
        with path.open('rb') as source:
            stat = path.stat()
            checkpoint = store.offset(path) if first else None
            if once or from_start or not first:
                start = 0
            elif checkpoint and checkpoint['device'] == stat.st_dev and checkpoint['inode'] == stat.st_ino and checkpoint['offset'] <= stat.st_size:
                start = checkpoint['offset']
            elif checkpoint:
                start = 0  # Rotated or truncated while the monitor was offline.
            else:
                start = stat.st_size  # First live launch starts at EOF.
            source.seek(start)
            first = False
            while True:
                start = source.tell()
                raw = source.readline(MAX_LINE + 1)
                if raw and raw.endswith(b'\n'):
                    end = source.tell()
                    origin = f"{path}\0{stat.st_dev}:{stat.st_ino}:{start}:{hashlib.sha256(raw).hexdigest()}"
                    yield raw.decode('utf-8', errors='replace'), origin, end, stat
                    continue
                if once:
                    if raw and len(raw) <= MAX_LINE:
                        origin = f"{path}\0{stat.st_dev}:{stat.st_ino}:{start}:{hashlib.sha256(raw).hexdigest()}"
                        yield raw.decode('utf-8', errors='replace'), origin, source.tell(), stat
                    return
                # Incomplete or oversized lines are not processed until a newline arrives.
                if raw and len(raw) > MAX_LINE:
                    source.readline()  # discard overlong remainder
                    store.set_offset(path, stat, source.tell())
                else:
                    source.seek(start)
                try:
                    current = path.stat()
                except FileNotFoundError:
                    time.sleep(poll_interval)
                    continue
                if (current.st_dev, current.st_ino) != (stat.st_dev, stat.st_ino) or current.st_size < source.tell():
                    break  # Reopen rotated/truncated file.
                time.sleep(poll_interval)


def run(argv=None):
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--log', type=Path, default=DEFAULT_LOG)
    cli.add_argument('--db', type=Path, default=DEFAULT_DB)
    cli.add_argument('--from-start', action='store_true', help='replay existing file before monitoring')
    cli.add_argument('--once', action='store_true', help='process existing file and exit')
    cli.add_argument('--year', type=int, help='year for timezone-free syslog records')
    args = cli.parse_args(argv)
    detector = BruteForceDetector()
    store = Storage(args.db)
    try:
        restore_detector(store, detector)
        intel = build_intel()
        count = 0
        if not args.once:
            print(f"Monitoring {args.log} (Ctrl+C to stop)", flush=True)
        for line, origin, end, stat in file_records(args.log, store, args.from_start, args.once):
            count += process_record(line, store, detector, intel, args.year, origin)
            store.set_offset(args.log.resolve(), stat, end)
        if args.once:
            print(f'Processed log; created {count} alert(s).')
    except KeyboardInterrupt:
        print('Stopped.')
    finally:
        store.close()


if __name__ == '__main__':
    run()
