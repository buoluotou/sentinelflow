"""Structured-output protocol: model text -> frozen protocol (Step 9/11).

Providers are instructed to answer with JSON only, but real models wrap it
in fences or prose; extract_json tolerates that while the parse_* functions
keep the schema boundary strict. Anything that fails raises
AIResponseParseError.
"""
import json
import re

from pydantic import ValidationError

from app.services.ai.exceptions import AIResponseParseError
from app.services.ai.models import (
    RISK_DRIVERS,
    TASK_ALERT_EXPLANATION,
    TASK_RISK_SUMMARY,
    AIAnalysis,
    RiskSummary,
)

_FENCED = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def extract_json(raw: str) -> str:
    """Pull the JSON object out of a model response (fenced or embedded)."""
    text = raw.strip()
    fenced = _FENCED.search(text)
    if fenced:
        return fenced.group(1).strip()
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        return text[start : end + 1]
    return text


def parse_analysis(raw: str) -> AIAnalysis:
    """Parse and validate a provider's raw text into the frozen protocol."""
    try:
        payload = json.loads(extract_json(raw))
    except (json.JSONDecodeError, ValueError) as exc:
        raise AIResponseParseError(f"Provider output is not valid JSON: {exc}") from exc
    try:
        return AIAnalysis.model_validate(payload)
    except ValidationError as exc:
        raise AIResponseParseError(f"Provider output violates the analysis schema: {exc}") from exc


def parse_risk_summary(raw: str) -> RiskSummary:
    """Parse and validate a risk-summary output (Step 11).

    Same strictness as parse_analysis: fenced/prose wrapping is tolerated,
    everything semantic is enforced — schema, analyst_priority enum and the
    frozen risk-driver vocabulary (drivers are factor names, not free text).
    """
    try:
        payload = json.loads(extract_json(raw))
    except (json.JSONDecodeError, ValueError) as exc:
        raise AIResponseParseError(f"Provider output is not valid JSON: {exc}") from exc
    try:
        summary = RiskSummary.model_validate(payload)
    except ValidationError as exc:
        raise AIResponseParseError(
            f"Provider output violates the risk-summary schema: {exc}"
        ) from exc
    unknown = sorted(set(summary.risk_drivers) - RISK_DRIVERS)
    if unknown:
        raise AIResponseParseError(
            f"Provider output contains unknown risk drivers: {', '.join(unknown)}"
        )
    return summary


def parse_task_output(task: str, raw: str) -> AIAnalysis | RiskSummary:
    """Dispatch raw provider output to the frozen parser of its task."""
    if task == TASK_ALERT_EXPLANATION:
        return parse_analysis(raw)
    if task == TASK_RISK_SUMMARY:
        return parse_risk_summary(raw)
    raise AIResponseParseError(f"Unknown AI task: {task}")
