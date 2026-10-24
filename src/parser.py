"""Parse the subset of traditional syslog SSH records used by this demo."""

import ipaddress
import re
from datetime import datetime

SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^:]+):\s+(?P<msg>.*)$"
)
FAILED_RE = re.compile(
    r"^Failed password for (?:invalid user )?(?P<user>\S+) from "
    r"(?P<ip>\S+) port \d+ ssh2(?:\s|$)"
)


def parse_syslog_line(line, year=None):
    match = SYSLOG_RE.match(line.strip())
    if not match or not match.group("proc").startswith("sshd["):
        return None
    try:
        timestamp = datetime.strptime(
            f"{match.group('month')} {match.group('day')} {match.group('time')} "
            f"{year if year is not None else datetime.now().year}",
            "%b %d %H:%M:%S %Y",
        )
    except ValueError:
        return None

    message = match.group("msg")
    failed = FAILED_RE.match(message)
    if failed:
        try:
            ipaddress.IPv4Address(failed.group("ip"))
        except ipaddress.AddressValueError:
            return None
    return {
        "timestamp": timestamp,
        "host": match.group("host"),
        "process": match.group("proc"),
        "msg": message,
        "ip": failed.group("ip") if failed else None,
        "username": failed.group("user") if failed else None,
        "type": "auth_fail" if failed else "other",
    }
