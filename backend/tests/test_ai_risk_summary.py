"""Step 11.1: risk_summary protocol + task-unified provider contract.

No real model and no network: provider tests run against an injected fake
transport, mock tests against MockProvider. Frozen semantics under test:

- strict schema (extra=forbid), analyst_priority enum, driver vocabulary
- key_findings bounded 1..5, confidence in [0, 1]
- explain() stays the Step 10-compatible alias; generate() dispatches by task
- the alert_explanation user prompt is byte-identical to the Step 10 freeze
"""
import json

import pytest

from app.services.ai import (
    RISK_DRIVERS,
    AIAnalysis,
    AIProviderUnavailable,
    AIRequest,
    AIResponseParseError,
    MockProvider,
    OllamaProvider,
    RiskSummary,
    parse_analysis,
    parse_risk_summary,
    parse_task_output,
)
from app.services.ai.base import (
    SYSTEM_PROMPT,
    SYSTEM_PROMPT_RISK_SUMMARY,
    build_system_prompt,
    build_user_prompt,
)


def _request(**overrides) -> AIRequest:
    base = dict(
        task="risk_summary",
        event_title="Suspicious process execution detected",
        event_category="process",
        severity="high",
        risk_score=70,
        risk_level="medium",
        risk_factors=[
            {"name": "severity", "score": 50, "reason": "Alert severity is high"},
            {"name": "frequency", "score": 20, "reason": "21-50 alerts observed"},
        ],
        evidence=["evidence item one", "evidence item two"],
    )
    base.update(overrides)
    return AIRequest(**base)


def _summary_dict(**overrides) -> dict:
    base = {
        "summary": "Repeated suspicious process execution within one window.",
        "key_findings": ["5 alerts aggregated", "risk score 70 hits the case threshold"],
        "risk_drivers": ["high_frequency", "suspicious_process", "high_risk_score"],
        "analyst_priority": "high",
        "confidence": 0.92,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------- protocol


class TestRiskSummaryProtocol:
    def test_valid_payload_parses(self):
        summary = parse_risk_summary(json.dumps(_summary_dict()))
        assert isinstance(summary, RiskSummary)
        assert summary.analyst_priority == "high"
        assert summary.risk_drivers == ["high_frequency", "suspicious_process", "high_risk_score"]
        assert summary.confidence == 0.92

    def test_fenced_and_prose_wrapping_is_tolerated(self):
        fenced = "```json\n" + json.dumps(_summary_dict()) + "\n```"
        assert parse_risk_summary(fenced).confidence == 0.92
        noisy = "Summary follows:\n" + json.dumps(_summary_dict()) + "\nHope this helps."
        assert parse_risk_summary(noisy).analyst_priority == "high"

    def test_invalid_json_raises_parse_error(self):
        with pytest.raises(AIResponseParseError):
            parse_risk_summary("I refuse to summarise.")

    def test_unknown_field_rejected(self):
        with pytest.raises(AIResponseParseError):
            parse_risk_summary(json.dumps(_summary_dict(risk_score=93)))

    def test_invalid_analyst_priority_rejected(self):
        with pytest.raises(AIResponseParseError):
            parse_risk_summary(json.dumps(_summary_dict(analyst_priority="urgent")))

    def test_unknown_risk_driver_rejected(self):
        with pytest.raises(AIResponseParseError, match="unknown risk drivers"):
            parse_risk_summary(json.dumps(_summary_dict(risk_drivers=["quantum_attack"])))

    def test_every_frozen_driver_is_accepted(self):
        drivers = sorted(RISK_DRIVERS)
        summary = parse_risk_summary(json.dumps(_summary_dict(risk_drivers=drivers)))
        assert summary.risk_drivers == drivers

    @pytest.mark.parametrize("findings", [[], [str(i) for i in range(6)]])
    def test_key_findings_bounded_1_to_5(self, findings):
        with pytest.raises(AIResponseParseError):
            parse_risk_summary(json.dumps(_summary_dict(key_findings=findings)))

    def test_empty_risk_drivers_rejected(self):
        with pytest.raises(AIResponseParseError):
            parse_risk_summary(json.dumps(_summary_dict(risk_drivers=[])))

    def test_confidence_bounds_enforced(self):
        for bad in (-0.1, 1.5):
            with pytest.raises(AIResponseParseError):
                parse_risk_summary(json.dumps(_summary_dict(confidence=bad)))

    def test_parse_task_output_dispatches(self):
        analysis = parse_task_output("alert_explanation", json.dumps({
            "summary": "s", "attack_type": "t", "why_risky": ["w"], "confidence": 0.5,
        }))
        assert isinstance(analysis, AIAnalysis)
        summary = parse_task_output("risk_summary", json.dumps(_summary_dict()))
        assert isinstance(summary, RiskSummary)
        with pytest.raises(AIResponseParseError, match="Unknown AI task"):
            parse_task_output("auto_block_ip", "{}")

    def test_analysis_protocol_untouched(self):
        # Step 10 parser still enforces its own schema independently.
        with pytest.raises(AIResponseParseError):
            parse_analysis(json.dumps(_summary_dict()))


# ------------------------------------------------------------------- prompts


class TestTaskPrompts:
    def test_system_prompts_per_task(self):
        assert build_system_prompt("alert_explanation") is SYSTEM_PROMPT
        prompt = build_system_prompt("risk_summary")
        assert prompt is SYSTEM_PROMPT_RISK_SUMMARY
        # The model can only comply if the vocabulary is enumerated inline.
        for driver in RISK_DRIVERS:
            assert driver in prompt
        assert "analyst_priority" in prompt

    def test_unknown_task_fails_loudly(self):
        with pytest.raises(ValueError, match="Unknown AI task"):
            build_system_prompt("auto_block_ip")

    def test_alert_explanation_user_prompt_is_frozen(self):
        # prior_explanation=None must not leak into the Step 10 prompt.
        text = build_user_prompt(_request(task="alert_explanation"))
        assert "prior_explanation" not in text
        assert "Suspicious process execution detected" in text

    def test_prior_explanation_included_only_when_present(self):
        assert "prior_explanation" not in build_user_prompt(_request())
        text = build_user_prompt(_request(prior_explanation="reverse shell activity"))
        assert "reverse shell activity" in text


# ------------------------------------------------------------- mock provider


class TestMockProviderRiskSummary:
    def test_deterministic_shape(self):
        summary = MockProvider().generate(_request())
        assert isinstance(summary, RiskSummary)
        assert 0.0 <= summary.confidence <= 1.0
        assert 1 <= len(summary.key_findings) <= 5
        assert set(summary.risk_drivers) <= RISK_DRIVERS
        assert summary == MockProvider().generate(_request())

    def test_factor_names_map_to_driver_vocabulary(self):
        summary = MockProvider().generate(_request())
        assert "severity" in summary.risk_drivers
        assert "high_frequency" in summary.risk_drivers
        # score 70 triggers the high_risk_score driver
        assert "high_risk_score" in summary.risk_drivers

    def test_low_score_drops_high_risk_score_driver(self):
        summary = MockProvider().generate(_request(risk_score=30))
        assert "high_risk_score" not in summary.risk_drivers
        assert summary.risk_drivers  # never empty

    def test_priority_falls_back_for_unassessed(self):
        summary = MockProvider().generate(_request(risk_level="unassessed", risk_score=0))
        assert summary.analyst_priority == "low"

    def test_scripted_failure_hits_both_tasks(self):
        provider = MockProvider(fail_with=AIProviderUnavailable("simulated outage"))
        with pytest.raises(AIProviderUnavailable):
            provider.generate(_request())

    def test_explain_alias_rejects_risk_summary_task(self):
        with pytest.raises(ValueError, match="explain\\(\\) only accepts"):
            MockProvider().explain(_request())

    def test_explain_alias_still_serves_step10(self):
        analysis = MockProvider().explain(_request(task="alert_explanation"))
        assert isinstance(analysis, AIAnalysis)


# ----------------------------------------------------------- ollama provider


class FakeTransport:
    """Injected stand-in for the HTTP layer: captures the request, returns
    a canned body. Contract: (url, payload, headers, **kwargs) -> body str."""

    def __init__(self, body: str):
        self.body = body
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url: str, payload: dict, headers=None, **kwargs) -> str:
        self.calls.append((url, payload))
        return self.body


class TestOllamaProviderRiskSummary:
    def test_risk_summary_prompt_and_parse(self):
        transport = FakeTransport(
            body=json.dumps({"message": {"content": json.dumps(_summary_dict())}})
        )
        provider = OllamaProvider(model="qwen3:4b", transport=transport)
        summary = provider.generate(_request())

        assert isinstance(summary, RiskSummary)
        assert summary.analyst_priority == "high"
        _, payload = transport.calls[0]
        system_text = payload["messages"][0]["content"]
        assert system_text == SYSTEM_PROMPT_RISK_SUMMARY
        assert payload["format"] == "json"

    def test_bad_model_output_maps_to_parse_error(self):
        transport = FakeTransport(body=json.dumps({"message": {"content": "no json here"}}))
        provider = OllamaProvider(model="qwen3:4b", transport=transport)
        with pytest.raises(AIResponseParseError):
            provider.generate(_request())

    def test_alert_explanation_still_uses_frozen_prompt(self):
        transport = FakeTransport(
            body=json.dumps({"message": {"content": json.dumps({
                "summary": "s", "attack_type": "t", "why_risky": ["w"], "confidence": 0.5,
            })}})
        )
        provider = OllamaProvider(model="qwen3:4b", transport=transport)
        analysis = provider.explain(_request(task="alert_explanation"))
        assert isinstance(analysis, AIAnalysis)
        _, payload = transport.calls[0]
        assert payload["messages"][0]["content"] == SYSTEM_PROMPT


# --------------------------------------------------------------- orm model


class TestAIRiskSummaryModel:
    def test_table_shape(self):
        from app.models import AIRiskSummary

        assert AIRiskSummary.__tablename__ == "ai_risk_summaries"
        columns = {c.name for c in AIRiskSummary.__table__.columns}
        assert columns == {
            "id", "alert_group_id", "provider", "model", "summary",
            "key_findings", "risk_drivers", "analyst_priority", "confidence",
            "created_at", "updated_at",
        }
        # History semantics like ai_analyses: indexed, NOT unique.
        index_columns = [
            tuple(col.name for col in idx.columns)
            for idx in AIRiskSummary.__table__.indexes
        ]
        assert ("alert_group_id",) in index_columns
        assert not any(
            constraint.columns.keys() == ["alert_group_id"]
            for constraint in AIRiskSummary.__table__.constraints
            if type(constraint).__name__ == "UniqueConstraint"
        )
