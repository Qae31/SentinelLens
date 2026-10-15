import json

import pytest
from fastapi.testclient import TestClient

import app.main as main
from app.main import app, get_llm_client
from app.models import AnalysisReport

client = TestClient(app)

BRUTE_FORCE_LOG = "\n".join(
    f"Oct 15 10:00:{i:02d} web01 sshd[{2000 + i}]: Failed password for root from 203.0.113.5 port {52000 + i} ssh2"
    for i in range(1, 6)
)


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def sample_log(fixtures_dir) -> bytes:
    return (fixtures_dir / "auth_sample.log").read_bytes()


def analyze(content: bytes, **data):
    return client.post("/analyze", files={"file": ("auth.log", content, "text/plain")}, data=data)


class FakeClient:
    def __init__(self, reply: str):
        self.reply = reply
        self.calls = 0

    def complete(self, *, system: str, user: str, model: str) -> str:
        self.calls += 1
        return self.reply


# --- basics -------------------------------------------------------------------


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_docs_available():
    assert client.get("/docs").status_code == 200


def test_analyze_is_documented_in_openapi():
    assert "/analyze" in client.get("/openapi.json").json()["paths"]


# --- rule-only (default) ------------------------------------------------------


def test_analyze_defaults_to_rules_only(sample_log):
    response = analyze(sample_log)
    assert response.status_code == 200
    report = AnalysisReport.model_validate(response.json())
    assert report.triage_mode == "none"
    assert report.triage == []
    assert [(f.finding_id, f.rule_id) for f in report.findings] == [
        ("fnd-0001", "brute_force"),
        ("fnd-0002", "success_after_failures"),
    ]


def test_analyze_reports_line_counts(sample_log):
    body = analyze(sample_log).json()
    assert body["lines_total"] == 23
    assert body["events_parsed"] == 20
    assert body["lines_skipped"] == 3


def test_findings_carry_evidence_event_ids(sample_log):
    findings = analyze(sample_log).json()["findings"]
    assert findings[0]["evidence_event_ids"] == [f"evt-{n:06d}" for n in range(1, 7)]


def test_log_text_is_not_echoed_back(sample_log):
    assert "ignore previous instructions" not in analyze(sample_log).text


def test_year_parameter_sets_timestamps():
    body = analyze(BRUTE_FORCE_LOG.encode(), year="2024").json()
    assert body["findings"][0]["first_seen"].startswith("2024-10-15T10:00:01")


def test_empty_file_gives_empty_report():
    body = analyze(b"").json()
    assert body["findings"] == []
    assert body["lines_total"] == 0


def test_non_utf8_bytes_do_not_crash():
    response = analyze(b"\xff\xfe\x00garbage\n" + BRUTE_FORCE_LOG.encode())
    assert response.status_code == 200
    assert len(response.json()["findings"]) == 1


# --- triage modes -------------------------------------------------------------


def test_mock_triage_is_marked_as_mock(sample_log):
    body = analyze(sample_log, triage="mock").json()
    assert body["triage_mode"] == "mock"
    assert len(body["triage"]) == len(body["findings"]) == 2
    for result in body["triage"]:
        assert result["source"] == "mock"
        assert "MOCK" in result["disclaimer"]


def test_claude_without_api_key_still_returns_findings(monkeypatch, sample_log):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    response = analyze(sample_log, triage="claude")
    assert response.status_code == 200
    body = response.json()
    assert len(body["findings"]) == 2
    assert [t["status"] for t in body["triage"]] == ["error", "error"]
    assert "ANTHROPIC_API_KEY" in body["triage"][0]["error"]


def test_claude_with_injected_client_returns_llm_result():
    answer = {
        "finding_id": "fnd-0001",
        "verdict": "likely_malicious",
        "confidence": 0.9,
        "summary": "Repeated failed root logins.",
        "rationale": "Five failures in five seconds.",
        "cited_event_ids": ["evt-000001", "evt-000002"],
        "recommended_actions": ["Review whether the source IP is expected."],
    }
    fake = FakeClient(json.dumps(answer))
    app.dependency_overrides[get_llm_client] = lambda: fake
    body = analyze(BRUTE_FORCE_LOG.encode(), triage="claude").json()
    (result,) = body["triage"]
    assert fake.calls == 1
    assert result["source"] == "llm"
    assert result["status"] == "ok"
    assert result["output"]["verdict"] == "likely_malicious"


def test_claude_invalid_llm_answer_is_reported_not_raised():
    app.dependency_overrides[get_llm_client] = lambda: FakeClient("definitely not json")
    response = analyze(BRUTE_FORCE_LOG.encode(), triage="claude")
    assert response.status_code == 200
    body = response.json()
    assert len(body["findings"]) == 1
    assert body["triage"][0]["status"] == "error"


def test_none_and_mock_never_touch_the_llm_client():
    fake = FakeClient("{}")
    app.dependency_overrides[get_llm_client] = lambda: fake
    analyze(BRUTE_FORCE_LOG.encode(), triage="none")
    analyze(BRUTE_FORCE_LOG.encode(), triage="mock")
    assert fake.calls == 0


# --- input validation ---------------------------------------------------------


def test_unknown_triage_mode_is_rejected():
    assert analyze(BRUTE_FORCE_LOG.encode(), triage="gpt").status_code == 422


def test_missing_file_is_rejected():
    assert client.post("/analyze").status_code == 422


@pytest.mark.parametrize("year", ["1969", "abc", "10000"])
def test_bad_year_is_rejected(year):
    assert analyze(BRUTE_FORCE_LOG.encode(), year=year).status_code == 422


# --- size limit ---------------------------------------------------------------


def test_file_over_the_limit_is_rejected(monkeypatch):
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 100)
    response = analyze(b"x" * 101)
    assert response.status_code == 413


def test_file_exactly_at_the_limit_is_accepted(monkeypatch):
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 100)
    assert analyze(b"x" * 100).status_code == 200


def test_default_limit_is_one_mebibyte():
    assert main.MAX_UPLOAD_BYTES == 1024 * 1024
