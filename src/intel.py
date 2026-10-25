"""Local simulated IOC data, plus optional public-IP AbuseIPDB lookups."""
import ipaddress
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

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
                                      'source': 'local simulated IOC fixture',
                                      'checked_at': datetime.now(timezone.utc).isoformat(), **item}
                                     if item else {'status': 'not_found', 'indicator': indicator,
                                                   'source': 'local simulated IOC fixture',
                                                   'checked_at': datetime.now(timezone.utc).isoformat()})
        return dict(self.cache[indicator])


class AbuseIPDBProvider:
    """Bounded optional APIv2 check. No private/reserved addresses leave the host."""
    def __init__(self, key, ttl=900, max_requests=100, opener=urlopen):
        if not key:
            raise ValueError('ABUSEIPDB_API_KEY is required when live lookups are enabled')
        self.key, self.ttl, self.max_requests, self.opener = key, ttl, max_requests, opener
        self.cache = {}
        self.requests = 0

    def lookup(self, ip):
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return {'status': 'invalid'}
        if not address.is_global:
            return {'status': 'unavailable', 'indicator': str(address),
                    'reason': 'Non-public address is not sent to a third party'}
        indicator = str(address)
        cached = self.cache.get(indicator)
        if cached and time.monotonic() < cached[0]:
            return dict(cached[1], cached=True)
        if self.requests >= self.max_requests:
            return {'status': 'unavailable', 'indicator': indicator, 'reason': 'Local lookup budget reached'}
        self.requests += 1
        url = 'https://api.abuseipdb.com/api/v2/check?' + urlencode({'ipAddress': indicator, 'maxAgeInDays': 90})
        request = Request(url, headers={'Key': self.key, 'Accept': 'application/json'})
        try:
            with self.opener(request, timeout=3) as response:
                data = json.load(response)['data']
            score = int(data['abuseConfidenceScore'])
            reports = int(data.get('totalReports') or 0)
            if not 0 <= score <= 100 or reports < 0:
                raise ValueError('Invalid provider response')
            result = {'status': 'match' if score >= 75 else 'reported' if reports else 'not_found',
                      'indicator': indicator, 'source': 'AbuseIPDB live', 'confidence': score,
                      'reports': reports, 'checked_at': datetime.now(timezone.utc).isoformat(),
                      'cached': False}
            self.cache[indicator] = (time.monotonic() + self.ttl, result)
            return result
        except (OSError, ValueError, KeyError, TypeError) as exc:
            # Never include the API key or provider body in a returned/logged error.
            return {'status': 'error', 'indicator': indicator, 'source': 'AbuseIPDB live',
                    'reason': type(exc).__name__}


class CombinedIntel:
    def __init__(self, local, live):
        self.local, self.live = local, live

    def lookup(self, ip):
        local = self.local.lookup(ip)
        if local['status'] != 'not_found':
            return local
        return self.live.lookup(ip)


def build_intel():
    local = LocalIntel()
    mode = os.environ.get('SIEM_INTEL_PROVIDER', 'local').lower()
    if mode == 'local':
        return local
    if mode == 'abuseipdb':
        return CombinedIntel(local, AbuseIPDBProvider(os.environ.get('ABUSEIPDB_API_KEY')))
    raise ValueError('SIEM_INTEL_PROVIDER must be local or abuseipdb')
