"""Parse SSH lines from a syslog-style auth.log into AuthEvent objects.

Log content is untrusted input: it is only matched against regexes, never
interpreted or executed.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pydantic import ValidationError

from app.models import AuthEvent, EventType

# "Oct 15 10:00:01 web01 sshd[2001]: Failed password for [invalid user ]root from 1.2.3.4 port 22 ssh2"
_LINE_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+"
    r"(?P<kind>Failed|Accepted) password for "
    r"(?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)

_KINDS = {"Failed": EventType.FAILED, "Accepted": EventType.ACCEPTED}


@dataclass
class ParseResult:
    events: list[AuthEvent] = field(default_factory=list)
    lines_total: int = 0
    lines_skipped: int = 0


def _parse_timestamp(raw: str, year: int) -> datetime:
    return datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)


def _parse_line(line: str, line_no: int, year: int) -> AuthEvent | None:
    match = _LINE_RE.match(line)
    if match is None:
        return None
    try:
        return AuthEvent(
            event_id=f"evt-{line_no:06d}",
            line_no=line_no,
            timestamp=_parse_timestamp(match["ts"], year),
            host=match["host"],
            event_type=_KINDS[match["kind"]],
            username=match["user"],
            src_ip=match["ip"],
            port=int(match["port"]),
            invalid_user=match["invalid"] is not None,
        )
    except (ValidationError, ValueError):
        return None


def parse_auth_log(text: str, year: int) -> ParseResult:
    """Parse Failed/Accepted password lines; other lines are counted as skipped."""
    result = ParseResult()
    for line_no, line in enumerate(text.splitlines(), start=1):
        result.lines_total += 1
        event = _parse_line(line, line_no, year)
        if event is None:
            result.lines_skipped += 1
        else:
            result.events.append(event)
    return result
