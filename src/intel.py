"""Offline, explicitly simulated IOC feed for reproducible training demonstrations."""
import ipaddress
import json
from pathlib import Path

FEED = Path(__file__).resolve().parents[1] / 'data' / 'demo_iocs.json'


class LocalIntel:
    def __init__(self, path=FEED):
        self.records = json.loads(Path(path).read_text(encoding='utf-8'))
        self.cache = {}

    def lookup(self, ip):
        if not ip:
            return {'status': 'unavailable', 'reason': 'No indicator'}
        try:
            indicator = str(ipaddress.ip_address(ip))
        except ValueError:
            return {'status': 'invalid'}
        if indicator not in self.cache:
            item = self.records.get(indicator)
            self.cache[indicator] = ({'status': 'match', 'indicator': indicator,
                                      'source': 'local simulated IOC fixture', **item}
                                     if item else {'status': 'not_found', 'indicator': indicator,
                                                   'source': 'local simulated IOC fixture'})
        return dict(self.cache[indicator])
