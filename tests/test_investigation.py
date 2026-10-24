import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from detectors import BruteForceDetector
from parser import parse_line
from intel import LocalIntel
from main import process_lines
from storage import Storage

BASE = datetime(2026, 10, 24, 9, tzinfo=timezone.utc)


def event(kind, second, ip='192.0.2.23', **kw):
    return dict(type=kind, ip=ip, timestamp=BASE + timedelta(seconds=second), **kw)


def line(kind, second, ip='192.0.2.23', **kw):
    return json.dumps(dict(type=kind, ip=ip, timestamp=(BASE + timedelta(seconds=second)).isoformat(), source='test', simulated=True, **kw)) + '\n'


class InvestigationTests(unittest.TestCase):
    def test_json_validation_and_utc(self):
        self.assertEqual(parse_line(line('auth_fail', 0))['timestamp'], BASE)
        for bad in ('{', '{"type":"auth_fail"}', line('auth_fail', 0, ip='999.1.1.1'),
                    line('network_connection', 0, destination_port=70000)):
            self.assertIsNone(parse_line(bad))
        self.assertIsNone(parse_line('{"type":"auth_fail","timestamp":"2026-10-24T09:00:00","ip":"192.0.2.1"}'))

    def test_success_correlation_window(self):
        d = BruteForceDetector(threshold=3, window_seconds=60)
        for t in (0, 1, 2):
            d.add_event(event('auth_fail', t))
        self.assertEqual(d.add_event(event('auth_success', 3, username='admin'))['alert_type'], 'failure_then_success')
        self.assertIsNone(d.add_event(event('auth_success', 100, username='admin')))
        self.assertIsNone(d.add_event(event('auth_success', 4, ip='198.51.100.2')))

    def test_web_and_scan_positive_negative(self):
        d = BruteForceDetector()
        self.assertIsNone(d.add_event(event('web_request', 0, msg='/products')))
        self.assertEqual(d.add_event(event('web_request', 1, msg='/../etc/passwd'))['alert_type'], 'suspicious_web_request')
        for port in (80, 80, 81, 82, 83):
            self.assertIsNone(d.add_event(event('network_connection', 2, destination_port=port)))
        self.assertEqual(d.add_event(event('network_connection', 3, destination_port=84))['alert_type'], 'port_scan')

    def test_intel_cache_status(self):
        intel = LocalIntel()
        self.assertEqual(intel.lookup('192.0.2.23')['status'], 'match')
        self.assertEqual(intel.lookup('198.51.100.2')['status'], 'not_found')
        self.assertEqual(intel.lookup('broken')['status'], 'invalid')
        self.assertEqual(len(intel.cache), 2)

    def test_end_to_end_replay_and_status_api(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'siem.db'
            store = Storage(path)
            lines = [line('auth_fail', i) for i in range(5)] + [line('auth_success', 5, username='admin')]
            try:
                self.assertEqual(process_lines(lines, store, BruteForceDetector()), 2)
                self.assertEqual(process_lines(lines, store, BruteForceDetector()), 0)
                self.assertEqual(len(store.events()), 6)
                self.assertEqual(len(store.incidents()), 1)
                inc = store.incident(1)
                self.assertEqual(len(inc['alerts']), 2)
                self.assertEqual(len(inc['events']), 6)
                self.assertEqual(inc['risk'], 100)
            finally:
                store.close()
            with patch.dict(os.environ, {'SIEM_DB': str(path)}):
                from api import app
                client = app.test_client()
                self.assertEqual(client.get('/api/overview').json['alerts'], 2)
                self.assertEqual(client.get('/api/incidents/1').status_code, 200)
                self.assertEqual(client.patch('/api/incidents/1', json={'status': 'investigating'}).status_code, 200)
                self.assertEqual(client.get('/api/incidents/1').json['status'], 'investigating')
                self.assertEqual(client.patch('/api/incidents/1', json={'status': 'blocked'}).status_code, 400)
                self.assertEqual(client.get('/api/incidents/999').status_code, 404)
                self.assertEqual(client.get('/').status_code, 200)


if __name__ == '__main__':
    unittest.main()
