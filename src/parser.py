"""Parse the subset of traditional syslog SSH records used by this demo."""

import ipaddress
import re
from datetime import datetime, timezone
import json

SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^:]+):\s+(?P<msg>.*)$"
)
FAILED_RE = re.compile(
    r"^Failed password for (?:invalid user )?(?P<user>\S+) from "
    r"(?P<ip>\S+) port \d+ ssh2(?:\s|$)"
)
SUCCESS_RE = re.compile(
    r"^Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port \d+ ssh2(?:\s|$)"
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
    success = SUCCESS_RE.match(message)
    auth = failed or success
    if auth:
        try:
            ipaddress.ip_address(auth.group("ip"))
        except ValueError:
            return None
    return {
        # Traditional syslog omits timezone; this demo interprets it as UTC.
        "timestamp": timestamp.replace(tzinfo=timezone.utc),
        "host": match.group("host"),
        "process": match.group("proc"),
        "msg": message,
        "ip": auth.group("ip") if auth else None,
        "username": auth.group("user") if auth else None,
        "type": "auth_fail" if failed else "auth_success" if success else "other",
    }


def parse_line(line, year=None):
    """Return a normalized SSH or JSON event; reject malformed supported records."""
    raw = line.strip()
    if not raw:
        return None
    if not raw.startswith("{"):
        event = parse_syslog_line(raw, year)
        if event:
            event.update(source="sshd", raw_event=raw)
        return event
    try:
        obj = json.loads(raw)
        if not isinstance(obj, dict) or obj.get("type") not in {"auth_fail", "auth_success", "web_request", "network_connection"}:
            return None
        timestamp = datetime.fromisoformat(obj["timestamp"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            return None
        ip = obj.get("ip")
        if ip is not None:
            ip = str(ipaddress.ip_address(ip))
        if obj["type"] in {"auth_fail", "auth_success", "network_connection"} and not ip:
            return None
        port = obj.get("destination_port")
        if port is not None and (isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535):
            return None
        return {"timestamp": timestamp.astimezone(timezone.utc), "type": obj["type"],
                "ip": ip, "username": str(obj.get("username") or "")[:128] or None,
                "host": str(obj.get("host") or "")[:128] or None,
                "process": None, "msg": str(obj.get("path") or "")[:2048],
                "destination_port": port, "source": str(obj.get("source") or "json")[:64],
                "raw_event": raw, "simulated": obj.get("simulated") is True}
    except (ValueError, TypeError, KeyError, OverflowError):
        return None
