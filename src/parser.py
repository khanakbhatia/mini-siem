import re
from datetime import datetime

# Regex patterns for syslog
SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[^:]+):\s+(?P<msg>.*)$"
)
IP_RE = re.compile(r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3})")
FAILED_USER_RE = re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+)")

def parse_syslog_line(line, year=None):
    m = SYSLOG_RE.match(line.strip())
    if not m:
        return None

    # default to current year
    year = year or datetime.now().year
    full_ts = f"{m.group('month')} {m.group('day')} {m.group('time')} {year}"
    ts = datetime.strptime(full_ts, "%b %d %H:%M:%S %Y")

    msg = m.group("msg")

    # extract ip and username
    ip_m = IP_RE.search(msg)
    ip = ip_m.group("ip") if ip_m else None

    user_m = FAILED_USER_RE.search(msg)
    user = user_m.group("user") if user_m else None

    event = {
        "timestamp": ts,
        "host": m.group("host"),
        "process": m.group("proc"),
        "msg": msg,
        "ip": ip,
        "username": user,
        "type": "auth_fail" if "Failed password" in msg else "other",
    }
    return event
