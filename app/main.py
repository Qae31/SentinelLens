"""FastAPI entry point. UI is the built-in /docs."""

from datetime import datetime, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile

from app.detections import run_detections
from app.models import AnalysisReport, TriageMode
from app.parser import parse_auth_log
from app.triage import LLMClient, triage_findings

MAX_UPLOAD_BYTES = 1024 * 1024

app = FastAPI(
    title="SentinelLens",
    description="Educational AI-assisted SOC triage for SSH auth.log. Not a production SIEM.",
    version="0.1.0",
)


def get_llm_client() -> LLMClient | None:
    """None means triage builds the real Anthropic client from ANTHROPIC_API_KEY. Tests override this."""
    return None


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze", response_model=AnalysisReport)
def analyze(
    file: Annotated[UploadFile, File(description="Synthetic SSH auth.log (syslog format, UTF-8).")],
    llm_client: Annotated[LLMClient | None, Depends(get_llm_client)],
    triage: Annotated[TriageMode, Form(description="none = rules only, mock = placeholder, claude = LLM.")] = "none",
    year: Annotated[
        int | None,
        Form(ge=2000, le=2100, description="Year for syslog timestamps (default: current UTC year)."),
    ] = None,
) -> AnalysisReport:
    content = file.file.read(MAX_UPLOAD_BYTES + 1)
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"File is larger than {MAX_UPLOAD_BYTES} bytes.")

    text = content.decode("utf-8", errors="replace")
    parsed = parse_auth_log(text, year=year or datetime.now(timezone.utc).year)
    findings = run_detections(parsed.events)
    return AnalysisReport(
        triage_mode=triage,
        lines_total=parsed.lines_total,
        events_parsed=len(parsed.events),
        lines_skipped=parsed.lines_skipped,
        findings=findings,
        triage=triage_findings(findings, parsed.events, triage, client=llm_client),
    )
