"""Structured-output protocol: model text -> AIAnalysis (Phase 2 Step 9).

Providers are instructed to answer with JSON only, but real models wrap it
in fences or prose; extract_json tolerates that while parse_analysis keeps
the schema boundary strict. Anything that fails raises AIResponseParseError.
"""
import json
import re

from pydantic import ValidationError

from app.services.ai.exceptions import AIResponseParseError
from app.services.ai.models import AIAnalysis

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
