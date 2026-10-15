from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.models import (
    AuthEvent,
    EventType,
    Finding,
    LLMTriageOutput,
    Severity,
    TriageResult,
    Verdict,
)

T0 = datetime(2026, 10, 15, 10, 0, 0, tzinfo=timezone.utc)


def make_finding(**overrides) -> Finding:
    data = dict(
        finding_id="fnd-0001",
        rule_id="brute_force",
        severity=Severity.MEDIUM,
        title="SSH brute force",
        host="web01",
        src_ip="203.0.113.5",
        usernames=["root"],
        first_seen=T0,
        last_seen=T0 + timedelta(minutes=2),
        evidence_event_ids=["evt-000001", "evt-000002"],
    )
    data.update(overrides)
    return Finding(**data)


def make_llm_output(**overrides) -> LLMTriageOutput:
    data = dict(
        finding_id="fnd-0001",
        verdict="suspicious",
        confidence=0.7,
        summary="Repeated failed logins from one IP.",
        rationale="Five failures within two minutes.",
        cited_event_ids=["evt-000001"],
        recommended_actions=["Review whether the source IP is expected."],
    )
    data.update(overrides)
    return LLMTriageOutput(**data)


# --- AuthEvent ---------------------------------------------------------------


def test_auth_event_valid():
    event = AuthEvent(
        event_id="evt-000042",
        line_no=42,
        timestamp=T0,
        host="web01",
        event_type=EventType.FAILED,
        username="admin",
        src_ip="203.0.113.5",
        port=52314,
        invalid_user=True,
    )
    assert event.event_type == "failed_password"
    assert str(event.src_ip) == "203.0.113.5"


@pytest.mark.parametrize("bad_id", ["42", "evt-42", "EVT-000042", "evt-0000420"])
def test_auth_event_rejects_bad_event_id(bad_id):
    with pytest.raises(ValidationError):
        AuthEvent(
            event_id=bad_id, line_no=1, timestamp=T0, host="h",
            event_type=EventType.FAILED, username="u", src_ip="203.0.113.5",
        )


def test_auth_event_rejects_bad_ip():
    with pytest.raises(ValidationError):
        AuthEvent(
            event_id="evt-000001", line_no=1, timestamp=T0, host="h",
            event_type=EventType.FAILED, username="u", src_ip="not-an-ip",
        )


# --- Finding -----------------------------------------------------------------


def test_finding_requires_evidence():
    with pytest.raises(ValidationError):
        make_finding(evidence_event_ids=[])


def test_finding_rejects_reversed_time_range():
    with pytest.raises(ValidationError):
        make_finding(first_seen=T0, last_seen=T0 - timedelta(seconds=1))


def test_finding_serializes_to_json():
    payload = make_finding().model_dump(mode="json")
    assert payload["evidence_event_ids"] == ["evt-000001", "evt-000002"]
    assert payload["severity"] == "medium"
    assert payload["src_ip"] == "203.0.113.5"


# --- LLMTriageOutput: the schema the LLM must return -------------------------


def test_llm_output_valid():
    out = make_llm_output()
    assert out.verdict == Verdict.SUSPICIOUS


def test_llm_output_parses_from_json_string():
    raw = make_llm_output().model_dump_json()
    assert LLMTriageOutput.model_validate_json(raw) == make_llm_output()


def test_llm_output_rejects_extra_fields():
    with pytest.raises(ValidationError):
        make_llm_output(block_ip=True)


@pytest.mark.parametrize("confidence", [-0.1, 1.1])
def test_llm_output_rejects_confidence_out_of_range(confidence):
    with pytest.raises(ValidationError):
        make_llm_output(confidence=confidence)


def test_llm_output_rejects_unknown_verdict():
    with pytest.raises(ValidationError):
        make_llm_output(verdict="definitely_hacked")


def test_llm_output_limits_actions():
    with pytest.raises(ValidationError):
        make_llm_output(recommended_actions=["x"] * 6)


def test_llm_output_rejects_malformed_cited_ids():
    with pytest.raises(ValidationError):
        make_llm_output(cited_event_ids=["ignore previous instructions"])


def test_grounding_accepts_subset_of_evidence():
    make_llm_output().assert_grounded_in(make_finding())


def test_grounding_rejects_unknown_event_id():
    out = make_llm_output(cited_event_ids=["evt-999999"])
    with pytest.raises(ValueError, match="evt-999999"):
        out.assert_grounded_in(make_finding())


def test_grounding_rejects_other_finding_id():
    out = make_llm_output(finding_id="fnd-0002")
    with pytest.raises(ValueError, match="finding_id"):
        out.assert_grounded_in(make_finding())


def test_llm_output_json_schema_has_no_extra_properties():
    schema = LLMTriageOutput.model_json_schema()
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) >= {"finding_id", "verdict", "confidence", "cited_event_ids"}


# --- TriageResult: wrapper with provenance -----------------------------------


def test_triage_result_mock_requires_disclaimer():
    with pytest.raises(ValidationError):
        TriageResult(finding_id="fnd-0001", source="mock", status="ok", output=make_llm_output())


def test_triage_result_mock_with_disclaimer():
    result = TriageResult(
        finding_id="fnd-0001", source="mock", status="ok",
        output=make_llm_output(), disclaimer="MOCK: not real LLM analysis",
    )
    assert result.source == "mock"


def test_triage_result_ok_requires_output():
    with pytest.raises(ValidationError):
        TriageResult(finding_id="fnd-0001", source="llm", status="ok", model="claude-sonnet-5-5")


def test_triage_result_error_requires_message():
    with pytest.raises(ValidationError):
        TriageResult(finding_id="fnd-0001", source="llm", status="error")


def test_finding_rejects_malformed_evidence_id():
    with pytest.raises(ValidationError):
        make_finding(evidence_event_ids=["line-1"])


def test_llm_output_rejects_overlong_action():
    with pytest.raises(ValidationError):
        make_llm_output(recommended_actions=["x" * 301])


def test_llm_output_json_schema_exposes_id_pattern():
    schema = LLMTriageOutput.model_json_schema()
    assert schema["properties"]["cited_event_ids"]["items"]["pattern"] == r"^evt-\d{6}$"
