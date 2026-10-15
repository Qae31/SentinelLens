"""Deterministic detection rules. No I/O, no LLM."""

from datetime import timedelta

from app.models import AuthEvent, EventType, Finding, Severity

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW = timedelta(minutes=5)

SUCCESS_AFTER_FAILURES_THRESHOLD = 3
SUCCESS_AFTER_FAILURES_WINDOW = timedelta(minutes=10)


def _sorted(events: list[AuthEvent]) -> list[AuthEvent]:
    return sorted(events, key=lambda e: (e.timestamp, e.line_no))


def _window_hits(series: list[AuthEvent]) -> list[tuple[int, int]]:
    """Merged index ranges [start, end] of every sliding window holding >= threshold events."""
    ranges: list[list[int]] = []
    start = 0
    for end, event in enumerate(series):
        while event.timestamp - series[start].timestamp > BRUTE_FORCE_WINDOW:
            start += 1
        if end - start + 1 < BRUTE_FORCE_THRESHOLD:
            continue
        if ranges and start <= ranges[-1][1]:
            ranges[-1][1] = end
        else:
            ranges.append([start, end])
    return [(a, b) for a, b in ranges]


def detect_brute_force(events: list[AuthEvent]) -> list[Finding]:
    """>= 5 failed logins from one src_ip on one host within a sliding 5-minute window.

    One finding per continuous series; evidence is every failed event in it.
    """
    groups: dict[tuple[str, str], list[AuthEvent]] = {}
    for event in _sorted(events):
        if event.event_type == EventType.FAILED:
            groups.setdefault((event.host, str(event.src_ip)), []).append(event)

    hits: list[list[AuthEvent]] = []
    for series in groups.values():
        hits.extend(series[a : b + 1] for a, b in _window_hits(series))
    hits.sort(key=lambda h: (h[0].timestamp, h[0].line_no))

    return [
        Finding(
            finding_id=f"fnd-{n:04d}",
            rule_id="brute_force",
            severity=Severity.MEDIUM,
            title=f"SSH brute force: {len(hit)} failed logins from {hit[0].src_ip}",
            host=hit[0].host,
            src_ip=hit[0].src_ip,
            usernames=sorted({e.username for e in hit}),
            first_seen=hit[0].timestamp,
            last_seen=hit[-1].timestamp,
            evidence_event_ids=[e.event_id for e in hit],
        )
        for n, hit in enumerate(hits, start=1)
    ]


def detect_success_after_failures(events: list[AuthEvent]) -> list[Finding]:
    """Accepted login preceded by >= 3 failures with the same host, src_ip and username within 10 minutes.

    Failures must come strictly earlier in (timestamp, line_no) order. One finding per
    accepted login; evidence is the qualifying failures plus the accepted event.
    """
    failed_by_key: dict[tuple[str, str, str], list[AuthEvent]] = {}
    accepted: list[AuthEvent] = []
    for event in _sorted(events):
        if event.event_type == EventType.FAILED:
            key = (event.host, str(event.src_ip), event.username)
            failed_by_key.setdefault(key, []).append(event)
        else:
            accepted.append(event)

    findings: list[Finding] = []
    for login in accepted:
        key = (login.host, str(login.src_ip), login.username)
        login_order = (login.timestamp, login.line_no)
        preceding = [
            f
            for f in failed_by_key.get(key, [])
            if (f.timestamp, f.line_no) < login_order
            and login.timestamp - f.timestamp <= SUCCESS_AFTER_FAILURES_WINDOW
        ]
        if len(preceding) < SUCCESS_AFTER_FAILURES_THRESHOLD:
            continue
        findings.append(
            Finding(
                finding_id=f"fnd-{len(findings) + 1:04d}",
                rule_id="success_after_failures",
                severity=Severity.HIGH,
                title=(
                    f"Successful login for {login.username} from {login.src_ip} "
                    f"after {len(preceding)} failed attempts"
                ),
                host=login.host,
                src_ip=login.src_ip,
                usernames=[login.username],
                first_seen=preceding[0].timestamp,
                last_seen=login.timestamp,
                evidence_event_ids=[f.event_id for f in preceding] + [login.event_id],
            )
        )
    return findings


def run_detections(events: list[AuthEvent]) -> list[Finding]:
    """Run every rule, order findings chronologically and number them fnd-0001, fnd-0002, ..."""
    found = detect_brute_force(events) + detect_success_after_failures(events)
    found.sort(key=lambda f: (f.first_seen, f.rule_id, f.finding_id))
    return [
        f.model_copy(update={"finding_id": f"fnd-{n:04d}"})
        for n, f in enumerate(found, start=1)
    ]
