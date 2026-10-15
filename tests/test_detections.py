from datetime import datetime, timedelta, timezone

from app.detections import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW,
    SUCCESS_AFTER_FAILURES_THRESHOLD,
    SUCCESS_AFTER_FAILURES_WINDOW,
    detect_brute_force,
    detect_success_after_failures,
    run_detections,
)
from app.models import AuthEvent, EventType, Severity

T0 = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)
N = BRUTE_FORCE_THRESHOLD


def ev(
    line_no: int,
    offset: timedelta = timedelta(0),
    *,
    host: str = "web01",
    ip: str = "203.0.113.5",
    user: str = "root",
    kind: EventType = EventType.FAILED,
) -> AuthEvent:
    return AuthEvent(
        event_id=f"evt-{line_no:06d}",
        line_no=line_no,
        timestamp=T0 + offset,
        host=host,
        event_type=kind,
        username=user,
        src_ip=ip,
    )


def burst(count: int, span: timedelta, *, start_line: int = 1, **kw) -> list[AuthEvent]:
    """`count` failed events spread evenly from T0 to T0 + span."""
    step = span / (count - 1) if count > 1 else timedelta(0)
    return [ev(start_line + i, step * i, **kw) for i in range(count)]


def ids(events: list[AuthEvent]) -> list[str]:
    return [e.event_id for e in events]


# --- threshold ----------------------------------------------------------------


def test_below_threshold_is_not_a_finding():
    assert detect_brute_force(burst(N - 1, timedelta(seconds=30))) == []


def test_at_threshold_is_a_finding():
    events = burst(N, timedelta(seconds=30))
    (finding,) = detect_brute_force(events)
    assert finding.rule_id == "brute_force"
    assert finding.evidence_event_ids == ids(events)


def test_finding_fields():
    events = burst(N, timedelta(seconds=40))
    (finding,) = detect_brute_force(events)
    assert finding.finding_id == "fnd-0001"
    assert finding.severity == Severity.MEDIUM
    assert finding.host == "web01"
    assert str(finding.src_ip) == "203.0.113.5"
    assert finding.first_seen == T0
    assert finding.last_seen == T0 + timedelta(seconds=40)


# --- window -------------------------------------------------------------------


def test_window_boundary_is_inclusive():
    assert len(detect_brute_force(burst(N, BRUTE_FORCE_WINDOW))) == 1


def test_just_over_window_is_not_a_finding():
    span = BRUTE_FORCE_WINDOW + timedelta(seconds=1)
    assert detect_brute_force(burst(N, span)) == []


def test_sliding_window_finds_burst_later_in_the_stream():
    slow = [ev(i + 1, timedelta(minutes=10 * i)) for i in range(3)]
    fast = burst(N, timedelta(seconds=20), start_line=10)
    shifted = [
        ev(e.line_no, e.timestamp - T0 + timedelta(hours=1)) for e in fast
    ]
    (finding,) = detect_brute_force(slow + shifted)
    assert finding.evidence_event_ids == ids(shifted)


# --- grouping -----------------------------------------------------------------


def test_different_source_ips_are_not_combined():
    a = burst(N - 1, timedelta(seconds=30), ip="203.0.113.5")
    b = burst(N - 1, timedelta(seconds=30), start_line=100, ip="203.0.113.6")
    assert detect_brute_force(a + b) == []


def test_different_hosts_are_not_combined():
    a = burst(N - 1, timedelta(seconds=30), host="web01")
    b = burst(N - 1, timedelta(seconds=30), start_line=100, host="db01")
    assert detect_brute_force(a + b) == []


def test_accepted_logins_do_not_count():
    events = burst(N - 1, timedelta(seconds=30))
    events.append(ev(100, timedelta(seconds=31), kind=EventType.ACCEPTED))
    assert detect_brute_force(events) == []


def test_usernames_are_collected_sorted_and_unique():
    events = [ev(i + 1, timedelta(seconds=i), user=u) for i, u in enumerate(["root", "admin", "root", "bob", "admin"])]
    events = (events * 2)[: max(N, 5)] if N > 5 else events[:N]
    events = [ev(i + 1, timedelta(seconds=i), user=e.username) for i, e in enumerate(events)]
    (finding,) = detect_brute_force(events)
    assert finding.usernames == sorted(set(finding.usernames))
    assert set(finding.usernames) <= {"root", "admin", "bob"}


# --- series -------------------------------------------------------------------


def test_one_continuous_series_yields_one_finding():
    events = burst(N * 2, timedelta(minutes=4))
    (finding,) = detect_brute_force(events)
    assert finding.evidence_event_ids == ids(events)


def test_two_separate_series_yield_two_findings():
    first = burst(N, timedelta(seconds=30))
    second = [
        ev(e.line_no, e.timestamp - T0 + timedelta(hours=2))
        for e in burst(N, timedelta(seconds=30), start_line=100)
    ]
    findings = detect_brute_force(first + second)
    assert [f.finding_id for f in findings] == ["fnd-0001", "fnd-0002"]
    assert findings[0].evidence_event_ids == ids(first)
    assert findings[1].evidence_event_ids == ids(second)


def test_two_sources_yield_two_findings():
    a = burst(N, timedelta(seconds=30), ip="203.0.113.5")
    b = burst(N, timedelta(seconds=30), start_line=100, ip="203.0.113.6")
    findings = detect_brute_force(a + b)
    assert {str(f.src_ip) for f in findings} == {"203.0.113.5", "203.0.113.6"}


# --- ordering -----------------------------------------------------------------


def test_input_order_does_not_matter():
    events = burst(N, timedelta(seconds=30))
    forward = detect_brute_force(events)
    backward = detect_brute_force(list(reversed(events)))
    assert forward == backward


def test_same_timestamp_events_are_ordered_by_line_number():
    events = [ev(line_no) for line_no in range(N, 0, -1)]
    (finding,) = detect_brute_force(events)
    assert finding.evidence_event_ids == sorted(ids(events))


def test_empty_input():
    assert detect_brute_force([]) == []


# --- fixture ------------------------------------------------------------------


def test_sample_fixture(fixtures_dir):
    from app.parser import parse_auth_log

    text = (fixtures_dir / "auth_sample.log").read_text(encoding="utf-8")
    events = parse_auth_log(text, year=2026).events
    findings = detect_brute_force(events)
    assert [str(f.src_ip) for f in findings] == ["203.0.113.5"]
    assert len(findings[0].evidence_event_ids) == 6


# =============================================================================
# success_after_failures
# =============================================================================

M = SUCCESS_AFTER_FAILURES_THRESHOLD
SAF_WINDOW = SUCCESS_AFTER_FAILURES_WINDOW


def failures(count: int, *, start_line: int = 1, at: timedelta = timedelta(0), **kw) -> list[AuthEvent]:
    """`count` failed events, one second apart, starting at T0 + `at`."""
    return [ev(start_line + i, at + timedelta(seconds=i), **kw) for i in range(count)]


def accepted(line_no: int, offset: timedelta, **kw) -> AuthEvent:
    return ev(line_no, offset, kind=EventType.ACCEPTED, **kw)


def test_saf_at_threshold_is_a_finding():
    fails = failures(M)
    ok = accepted(100, timedelta(minutes=1))
    (finding,) = detect_success_after_failures(fails + [ok])
    assert finding.rule_id == "success_after_failures"
    assert finding.evidence_event_ids == ids(fails) + [ok.event_id]


def test_saf_finding_fields():
    fails = failures(M)
    ok = accepted(100, timedelta(minutes=1))
    (finding,) = detect_success_after_failures(fails + [ok])
    assert finding.finding_id == "fnd-0001"
    assert finding.severity == Severity.HIGH
    assert finding.host == "web01"
    assert str(finding.src_ip) == "203.0.113.5"
    assert finding.usernames == ["root"]
    assert finding.first_seen == fails[0].timestamp
    assert finding.last_seen == ok.timestamp


def test_saf_below_threshold_is_not_a_finding():
    events = failures(M - 1) + [accepted(100, timedelta(minutes=1))]
    assert detect_success_after_failures(events) == []


def test_saf_failures_without_success_are_not_a_finding():
    assert detect_success_after_failures(failures(M * 2)) == []


def test_saf_different_username_is_not_a_finding():
    events = failures(M, user="root") + [accepted(100, timedelta(minutes=1), user="alice")]
    assert detect_success_after_failures(events) == []


def test_saf_different_ip_is_not_a_finding():
    events = failures(M, ip="203.0.113.5") + [accepted(100, timedelta(minutes=1), ip="203.0.113.6")]
    assert detect_success_after_failures(events) == []


def test_saf_different_host_is_not_a_finding():
    events = failures(M, host="web01") + [accepted(100, timedelta(minutes=1), host="db01")]
    assert detect_success_after_failures(events) == []


def test_saf_accepted_before_failures_is_not_a_finding():
    ok = accepted(1, timedelta(0))
    events = [ok] + failures(M, start_line=2, at=timedelta(seconds=1))
    assert detect_success_after_failures(events) == []


def test_saf_same_timestamp_failures_after_accepted_by_line_are_not_earlier():
    ok = accepted(1, timedelta(0))
    fails = [ev(line_no) for line_no in range(2, 2 + M)]
    assert detect_success_after_failures([ok] + fails) == []


def test_saf_same_timestamp_failures_before_accepted_by_line_count():
    fails = [ev(line_no) for line_no in range(1, 1 + M)]
    ok = accepted(100, timedelta(0))
    (finding,) = detect_success_after_failures(fails + [ok])
    assert finding.evidence_event_ids == ids(fails) + [ok.event_id]


def test_saf_window_boundary_is_inclusive():
    oldest_on_edge = ev(1)
    others = failures(M - 1, start_line=2, at=timedelta(minutes=5))
    ok = accepted(100, SAF_WINDOW)
    assert len(detect_success_after_failures([oldest_on_edge, *others, ok])) == 1


def test_saf_failure_just_outside_window_does_not_count():
    too_old = ev(1)
    others = failures(M - 1, start_line=2, at=timedelta(minutes=5))
    ok = accepted(100, SAF_WINDOW + timedelta(seconds=1))
    assert detect_success_after_failures([too_old, *others, ok]) == []


def test_saf_gap_over_window_is_not_a_finding():
    fails = failures(M)
    ok = accepted(100, fails[-1].timestamp - T0 + SAF_WINDOW + timedelta(seconds=1))
    assert detect_success_after_failures(fails + [ok]) == []


def test_saf_stale_failures_outside_window_are_not_evidence():
    stale = failures(2, at=timedelta(0))
    fresh = failures(M, start_line=10, at=timedelta(minutes=30))
    ok = accepted(100, timedelta(minutes=31))
    (finding,) = detect_success_after_failures(stale + fresh + [ok])
    assert finding.evidence_event_ids == ids(fresh) + [ok.event_id]


def test_saf_failures_from_other_users_are_not_evidence():
    mine = failures(M, user="root")
    other = failures(2, start_line=50, at=timedelta(seconds=30), user="admin")
    ok = accepted(100, timedelta(minutes=1), user="root")
    (finding,) = detect_success_after_failures(mine + other + [ok])
    assert finding.evidence_event_ids == ids(mine) + [ok.event_id]


def test_saf_each_accepted_login_gets_its_own_finding():
    fails = failures(M)
    ok1 = accepted(100, timedelta(minutes=1))
    ok2 = accepted(101, timedelta(minutes=2))
    findings = detect_success_after_failures(fails + [ok1, ok2])
    assert [f.finding_id for f in findings] == ["fnd-0001", "fnd-0002"]
    assert findings[0].evidence_event_ids[-1] == ok1.event_id
    assert findings[1].evidence_event_ids[-1] == ok2.event_id


def test_saf_input_order_does_not_matter():
    events = failures(M) + [accepted(100, timedelta(minutes=1))]
    assert detect_success_after_failures(events) == detect_success_after_failures(list(reversed(events)))


def test_saf_empty_input():
    assert detect_success_after_failures([]) == []


def test_saf_sample_fixture(fixtures_dir):
    from app.parser import parse_auth_log

    text = (fixtures_dir / "auth_sample.log").read_text(encoding="utf-8")
    findings = detect_success_after_failures(parse_auth_log(text, year=2026).events)
    (finding,) = findings
    assert finding.usernames == ["alice"]
    assert str(finding.src_ip) == "198.51.100.7"
    assert len(finding.evidence_event_ids) == 4


# =============================================================================
# run_detections
# =============================================================================


def _combined_events() -> list[AuthEvent]:
    """Brute force from .5 at T0, then alice logs in from .7 after M failures."""
    brute = burst(N, timedelta(seconds=30))
    alice_fails = failures(M, start_line=100, at=timedelta(minutes=5), ip="198.51.100.7", user="alice")
    alice_ok = accepted(200, timedelta(minutes=6), ip="198.51.100.7", user="alice")
    return brute + alice_fails + [alice_ok]


def test_run_detections_combines_both_rules():
    findings = run_detections(_combined_events())
    assert [f.rule_id for f in findings] == ["brute_force", "success_after_failures"]


def test_run_detections_numbers_findings_sequentially():
    findings = run_detections(_combined_events())
    assert [f.finding_id for f in findings] == ["fnd-0001", "fnd-0002"]


def test_run_detections_ids_are_unique_when_one_rule_fires_many_times():
    events = _combined_events()
    events += [accepted(201, timedelta(minutes=7), ip="198.51.100.7", user="alice")]
    ids_ = [f.finding_id for f in run_detections(events)]
    assert ids_ == ["fnd-0001", "fnd-0002", "fnd-0003"]


def test_run_detections_orders_chronologically_across_rules():
    findings = run_detections(_combined_events())
    assert [f.first_seen for f in findings] == sorted(f.first_seen for f in findings)


def test_run_detections_input_order_does_not_matter():
    events = _combined_events()
    assert run_detections(events) == run_detections(list(reversed(events)))


def test_run_detections_empty_input():
    assert run_detections([]) == []


def test_run_detections_sample_fixture(fixtures_dir):
    from app.parser import parse_auth_log

    text = (fixtures_dir / "auth_sample.log").read_text(encoding="utf-8")
    findings = run_detections(parse_auth_log(text, year=2026).events)
    assert [(f.finding_id, f.rule_id) for f in findings] == [
        ("fnd-0001", "brute_force"),
        ("fnd-0002", "success_after_failures"),
    ]
