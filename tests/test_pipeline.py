import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from detectors import BruteForceDetector
from main import process_lines
from parser import parse_syslog_line
from storage import Storage


def event(ip, seconds, kind="auth_fail"):
    return {
        "ip": ip,
        "type": kind,
        "timestamp": datetime(2026, 10, 2, 12, 0) + timedelta(seconds=seconds),
    }


class ParserTests(unittest.TestCase):
    def test_failed_login(self):
        parsed = parse_syslog_line(
            "Oct  2 12:00:00 myhost sshd[123]: Failed password for invalid user "
            "admin from 192.0.2.23 port 55000 ssh2", year=2026
        )
        self.assertEqual((parsed["type"], parsed["username"], parsed["ip"]),
                         ("auth_fail", "admin", "192.0.2.23"))

    def test_invalid_or_unrelated_record(self):
        self.assertIsNone(parse_syslog_line("not a syslog line"))
        self.assertIsNone(parse_syslog_line(
            "Oct  2 12:00:00 myhost sshd[1]: Failed password for admin "
            "from 999.0.2.23 port 22 ssh2", year=2026
        ))
        self.assertIsNone(parse_syslog_line(
            "Oct  2 12:00:00 myhost cron[1]: Failed password for admin "
            "from 192.0.2.23 port 22 ssh2", year=2026
        ))


class DetectorTests(unittest.TestCase):
    def test_fifth_failure_alerts_once_per_burst(self):
        detector = BruteForceDetector()
        for second in range(4):
            self.assertIsNone(detector.add_event(event("192.0.2.1", second)))
        alert = detector.add_event(event("192.0.2.1", 4))
        self.assertEqual(alert["count"], 5)
        self.assertIsNone(detector.add_event(event("192.0.2.1", 5)))
        self.assertIsNone(detector.add_event(event("192.0.2.1", 66)))
        for second in (67, 68, 69):
            self.assertIsNone(detector.add_event(event("192.0.2.1", second)))
        self.assertIsNotNone(detector.add_event(event("192.0.2.1", 70)))

    def test_independent_ips_and_old_attempts(self):
        detector = BruteForceDetector()
        for second in (0, 1, 2, 3):
            self.assertIsNone(detector.add_event(event("192.0.2.1", second)))
        self.assertIsNone(detector.add_event(event("192.0.2.2", 4)))
        self.assertIsNone(detector.add_event(event("192.0.2.1", 100)))
        self.assertIsNone(detector.add_event(event("192.0.2.1", 101, "other")))


class PipelineTests(unittest.TestCase):
    def test_sample_replay_writes_three_bursts(self):
        sample = Path(__file__).resolve().parents[1] / "data" / "sample_auth.log"
        with tempfile.TemporaryDirectory() as temp:
            store = Storage(Path(temp) / "alerts.db")
            try:
                with sample.open(encoding="utf-8") as lines:
                    count = process_lines(lines, store, BruteForceDetector(), year=2026)
                self.assertEqual(count, 3)
                self.assertEqual(len(store.recent_alerts()), 3)
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
