"""Pydantic models for the whole pipeline.

LLMTriageOutput is the only schema an LLM is allowed to fill. Everything the
LLM returns is validated against it, and then checked against the finding it
claims to describe (assert_grounded_in) before it reaches the report.
"""

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    StringConstraints,
    model_validator,
)

EVENT_ID_PATTERN = r"^evt-\d{6}$"
FINDING_ID_PATTERN = r"^fnd-\d{4}$"

EventId = Annotated[str, StringConstraints(pattern=EVENT_ID_PATTERN)]
ActionText = Annotated[str, StringConstraints(min_length=1, max_length=300)]


class EventType(StrEnum):
    FAILED = "failed_password"
    ACCEPTED = "accepted_password"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Verdict(StrEnum):
    LIKELY_MALICIOUS = "likely_malicious"
    SUSPICIOUS = "suspicious"
    LIKELY_BENIGN = "likely_benign"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


RuleId = Literal["brute_force", "success_after_failures"]
TriageMode = Literal["none", "mock", "claude"]


class AuthEvent(BaseModel):
    """One parsed SSH auth line. Timestamps are UTC."""

    model_config = ConfigDict(frozen=True)

    event_id: EventId
    line_no: int = Field(ge=1)
    timestamp: datetime
    host: str = Field(min_length=1, max_length=255)
    event_type: EventType
    username: str = Field(min_length=1, max_length=255)
    src_ip: IPvAnyAddress
    port: int | None = Field(default=None, ge=0, le=65535)
    invalid_user: bool = False


class Finding(BaseModel):
    """A rule hit, always backed by the event IDs that triggered it."""

    finding_id: str = Field(pattern=FINDING_ID_PATTERN)
    rule_id: RuleId
    severity: Severity
    title: str
    host: str
    src_ip: IPvAnyAddress
    usernames: list[str] = Field(min_length=1)
    first_seen: datetime
    last_seen: datetime
    evidence_event_ids: list[EventId] = Field(min_length=1)

    @model_validator(mode="after")
    def _check_time_range(self) -> "Finding":
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must not be earlier than first_seen")
        return self


class LLMTriageOutput(BaseModel):
    """Structured output the LLM must return for exactly one finding.

    extra="forbid" makes unexpected keys (e.g. an injected "block_ip") a hard
    validation error instead of being silently dropped.
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(pattern=FINDING_ID_PATTERN)
    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    summary: str = Field(min_length=1, max_length=1000)
    rationale: str = Field(min_length=1, max_length=2000)
    cited_event_ids: list[EventId] = Field(
        min_length=1,
        max_length=50,
        description="Event IDs from the finding's evidence that support the verdict.",
    )
    recommended_actions: list[ActionText] = Field(
        default_factory=list,
        max_length=5,
        description="Advisory text for a human analyst. Never executed.",
    )


    def assert_grounded_in(self, finding: Finding) -> None:
        """Raise ValueError unless this output refers to `finding` and cites only its evidence."""
        if self.finding_id != finding.finding_id:
            raise ValueError(
                f"finding_id mismatch: got {self.finding_id}, expected {finding.finding_id}"
            )
        unknown = sorted(set(self.cited_event_ids) - set(finding.evidence_event_ids))
        if unknown:
            raise ValueError(f"cited event IDs not in finding evidence: {unknown}")


class TriageResult(BaseModel):
    """Triage outcome for one finding, with provenance.

    source="mock" is placeholder output and must carry a disclaimer so it is
    never mistaken for real LLM analysis.
    """

    finding_id: str = Field(pattern=FINDING_ID_PATTERN)
    source: Literal["llm", "mock"]
    status: Literal["ok", "error"]
    model: str | None = None
    disclaimer: str | None = None
    output: LLMTriageOutput | None = None
    error: str | None = None

    @model_validator(mode="after")
    def _check_consistency(self) -> "TriageResult":
        if self.source == "mock" and not self.disclaimer:
            raise ValueError("mock triage results must carry a disclaimer")
        if self.status == "ok" and self.output is None:
            raise ValueError("status 'ok' requires output")
        if self.status == "error" and not self.error:
            raise ValueError("status 'error' requires an error message")
        return self


class AnalysisReport(BaseModel):
    """Top-level response of POST /analyze."""

    triage_mode: TriageMode
    lines_total: int = Field(ge=0)
    events_parsed: int = Field(ge=0)
    lines_skipped: int = Field(ge=0)
    findings: list[Finding]
    triage: list[TriageResult] = Field(default_factory=list)
