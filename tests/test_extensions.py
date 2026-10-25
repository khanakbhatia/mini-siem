import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from api import app, write_requests
from detectors import BruteForceDetector
from intel import AbuseIPDBProvider, CombinedIntel, LocalIntel
from main import file_records, process_record, process_lines, restore_detector
from parser import parse_line
from storage import Storage


def auth(sec, kind='auth_fail', user='admin', host='one'):
    return json.dumps({'timestamp': f'2026-10-24T09:00:{sec:02}Z', 'type': kind,
                       'ip': '192.0.2.23', 'username': user, 'host': host,
                       'source': 'test', 'simulated': True}) + '\n'


class ExtensionTests(unittest.TestCase):
    def test_restart_restores_window_and_suppresses_old_alert(self):
        with tempfile.TemporaryDirectory() as d:
            store = Storage(Path(d)/'s.db')
            local = LocalIntel()
            try:
                first = BruteForceDetector()
                for sec in range(4):
                    self.assertEqual(process_record(auth(sec), store, first, local, origin=f'line:{sec}'), 0)
                next_process = BruteForceDetector()
                restore_detector(store, next_process)
                self.assertEqual(process_record(auth(4), store, next_process, local, origin='line:4'), 1)
                again = BruteForceDetector()
                restore_detector(store, again)
                self.assertEqual(process_record(auth(5), store, again, local, origin='line:5'), 0)
                self.assertEqual(process_record(auth(5), store, again, local, origin='line:5'), 0)
                self.assertEqual(len(store.recent_alerts()), 1)
            finally:
                store.close()

    def test_account_and_host_boundaries(self):
        with tempfile.TemporaryDirectory() as d:
            store=Storage(Path(d)/'s.db'); detector=BruteForceDetector(); local=LocalIntel()
            try:
                for sec in range(5):
                    process_record(auth(sec),store,detector,local)
                self.assertEqual(process_record(auth(5,'auth_success','alice'),store,detector,local),0)
                self.assertEqual(process_record(auth(6,'auth_success','admin'),store,detector,local),1)
                for sec in range(10,15):
                    process_record(auth(sec,'auth_fail','admin','two'),store,detector,local)
                self.assertEqual(len(store.incidents()),2)
                self.assertEqual(store.incident(1)['alerts'][-1]['alert_type'],'failure_then_success')
            finally: store.close()

    def test_searchable_fields_and_validation(self):
        raw=json.dumps({'timestamp':'2026-10-24T09:00:00Z','type':'network_connection','ip':'198.51.100.44',
                        'destination_ip':'198.51.100.80','destination_port':443,'connection_outcome':'rejected','source':'firewall'})
        with tempfile.TemporaryDirectory() as d:
            store=Storage(Path(d)/'s.db')
            try:
                store.insert_event(parse_line(raw))
                row=store.events(ip='198.51.100.44',kind='network_connection',source='firewall')[0]
                self.assertEqual((row['destination_port'],row['destination_ip'],row['connection_outcome']), (443,'198.51.100.80','rejected'))
                self.assertEqual(store.events(username='unknown'),[])
                self.assertEqual(len(store.events(destination_port=443,destination_ip='198.51.100.80')),1)
            finally: store.close()
        bad=dict(json.loads(raw),connection_outcome='superuser')
        self.assertIsNone(parse_line(json.dumps(bad)))
        bad=dict(json.loads(raw),http_status=600)
        self.assertIsNone(parse_line(json.dumps(bad)))

    def test_additive_migration_from_previous_schema(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'old.db'
            conn=sqlite3.connect(path)
            conn.executescript("""
                CREATE TABLE events (id INTEGER PRIMARY KEY, fingerprint TEXT UNIQUE NOT NULL,
                ts TEXT NOT NULL, source TEXT NOT NULL, type TEXT NOT NULL, ip TEXT,
                username TEXT, host TEXT, raw_event TEXT NOT NULL,
                simulated INTEGER NOT NULL DEFAULT 0, enrichment TEXT);
                CREATE TABLE incidents (id INTEGER PRIMARY KEY, ip TEXT,
                first_event_ts TEXT, last_event_ts TEXT, status TEXT, risk INTEGER);
            """)
            conn.close()
            store=Storage(path)
            try:
                self.assertIn('http_status',{r[1] for r in store.conn.execute('PRAGMA table_info(events)')})
                self.assertIn('entity_key',{r[1] for r in store.conn.execute('PRAGMA table_info(incidents)')})
            finally: store.close()

    def test_file_positions_allow_identical_lines_and_checkpoint(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'events.jsonl'; path.write_text(auth(0)*2)
            store=Storage(Path(d)/'s.db')
            try:
                records=list(file_records(path,store,once=True))
                self.assertNotEqual(records[0][1], records[1][1])
                detector=BruteForceDetector(); local=LocalIntel()
                for line,origin,end,stat in records:
                    process_record(line,store,detector,local,origin=origin)
                    store.set_offset(path.resolve(),stat,end)
                self.assertEqual(len(store.events()),2)
                self.assertEqual(store.offset(path.resolve())['offset'],path.stat().st_size)
                for line,origin,_,_ in file_records(path,store,once=True):
                    process_record(line,store,detector,local,origin=origin)
                self.assertEqual(len(store.events()),2)
            finally: store.close()

    def test_rotation_and_restart_checkpoint(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'events.jsonl'; path.write_text(auth(0))
            store=Storage(Path(d)/'s.db')
            try:
                reader=file_records(path,store,from_start=True,poll_interval=0.001)
                _,_,offset,stat=next(reader)
                store.set_offset(path.resolve(),stat,offset)
                path.rename(Path(d)/'old.jsonl')
                path.write_text(auth(1))
                self.assertIn('09:00:01',next(reader)[0])
                reader.close()
                # After an offline rotation, the new inode is read from its start.
                self.assertIn('09:00:01',next(file_records(path,store,poll_interval=0.001))[0])
            finally: store.close()

    def test_provider_cache_privacy_and_failure(self):
        calls=[]
        def opener(request, timeout):
            calls.append((request.full_url, timeout))
            return io.BytesIO(json.dumps({'data':{'abuseConfidenceScore':85,'totalReports':4}}).encode())
        live=AbuseIPDBProvider('fake-test-key',opener=opener)
        self.assertEqual(live.lookup('192.0.2.23')['status'],'unavailable')
        self.assertEqual(live.lookup('8.8.8.8')['status'],'match')
        self.assertTrue(live.lookup('8.8.8.8')['cached'])
        self.assertEqual(len(calls),1)
        self.assertEqual(calls[0][1],3)
        failed=AbuseIPDBProvider('fake-test-key',opener=lambda *a,**k: (_ for _ in ()).throw(OSError('secret')))
        self.assertEqual(failed.lookup('8.8.8.8')['status'],'error')
        self.assertNotIn('secret',str(failed.lookup('8.8.8.8')))
        combined=CombinedIntel(LocalIntel(),live)
        self.assertEqual(combined.lookup('192.0.2.23')['source'],'local simulated IOC fixture')
        capped=AbuseIPDBProvider('fake-test-key',max_requests=0,opener=opener)
        self.assertEqual(capped.lookup('8.8.8.8')['status'],'unavailable')

    def test_live_provider_result_flows_into_alert_risk(self):
        def opener(request, timeout):
            return io.BytesIO(json.dumps({'data':{'abuseConfidenceScore':85,'totalReports':4}}).encode())
        intel=CombinedIntel(LocalIntel(),AbuseIPDBProvider('fake-test-key',opener=opener))
        lines=[auth(sec).replace('192.0.2.23','8.8.8.8') for sec in range(5)]
        with tempfile.TemporaryDirectory() as d:
            store=Storage(Path(d)/'s.db')
            try:
                self.assertEqual(process_lines(lines,store,BruteForceDetector(),intel=intel),1)
                details=json.loads(store.recent_alerts()[0]['details'])
                self.assertEqual(details['risk'],70)
                self.assertEqual(details['enrichment']['source'],'AbuseIPDB live')
                self.assertEqual(intel.live.requests,1)
            finally: store.close()

    def test_bearer_and_audit(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ,{'SIEM_DB':str(Path(d)/'s.db'),'SIEM_API_TOKEN':'a-test-token'}):
            write_requests.clear()
            store=Storage(Path(d)/'s.db'); local=LocalIntel(); detector=BruteForceDetector()
            for sec in range(5): process_record(auth(sec),store,detector,local)
            store.close()
            client=app.test_client()
            self.assertEqual(client.get('/api/overview').status_code,401)
            self.assertEqual(client.get('/api/overview',headers={'Authorization':'Bearer a-test-token'}).status_code,200)
            self.assertEqual(client.get('/api/events?destination_port=bad',headers={'Authorization':'Bearer a-test-token'}).status_code,400)
            headers={'Authorization':'Bearer a-test-token'}
            self.assertEqual(client.patch('/api/incidents/1',json={'status':'investigating'},headers=headers).status_code,200)
            result=client.get('/api/incidents/1',headers=headers).json
            self.assertEqual(result['actions'][0]['old_status'],'new')
            self.assertEqual(result['actions'][0]['new_status'],'investigating')
            self.assertEqual(client.get('/').status_code,200)


if __name__=='__main__': unittest.main()
