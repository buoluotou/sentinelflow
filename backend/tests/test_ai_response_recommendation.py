"""Step 12.1: response_recommendation protocol + data-model freeze.

No real model and no network: provider tests run against an injected fake
transport, mock tests against MockProvider. Frozen semantics under test:

- strict schema (extra=forbid) on the envelope AND on every item
- the frozen response-action vocabulary (unknown actions rejected)
- an EMPTY recommendations list is a first-class "no action" answer
- recommendations bounded 0..5, non-empty rationales, confidence in [0, 1]
- advisory-only: no field can carry an executable payload
- generate() dispatches by task; the builder degrades without EventRisk
"""
import json

import pytest

from app.services.ai import (
    RESPONSE_ACTIONS,
    AIProviderUnavailable,
    AIRequest,
    AIResponseParseError,
    MockProvider,
    OllamaProvider,
    ResponseRecommendation,
    build_response_recommendation_request,
    parse_response_recommendation,
    parse_task_output,
)
from app.services.ai.base import (
    SYSTEM_PROMPT_RESPONSE_RECOMMENDATION,
    build_system_prompt,
    build_user_prompt,
)


def _request(**overrides) -> AIRequest:
    base = dict(
        task="response_recommendation",
        event_title="SSH Brute Force on edge-gateway",
        event_category="authentication",
        severity="high",
        risk_score=85,
        risk_level="high",
        risk_factors=[
            {"name": "severity", "score": 30, "reason": "High-severity alerts in the group"},
            {"name": "frequency", "score": 20, "reason": "Repeated alerts within a short window"},
        ],
        evidence=[json.dumps({"event_type": "ssh_failed_login", "source_ip": "203.0.113.9"})],
    )
    base.update(overrides)
    return AIRequest(**base)


def _item(**overrides) -> dict:
    base = {
        "action": "block_source_ip",
        "target": "203.0.113.9",
        "rationale": "Stop the observed brute-force source from reaching the gateway.",
    }
    base.update(overrides)
    return base


def _recommendation_dict(**overrides) -> dict:
    base = {
        "overall_rationale": "Contain the source and open a tracked case.",
        "recommendations": [
            _item(),
            _item(action="escalate_to_incident", target="", rationale="Warrants a SOC case."),
        ],
        "confidence": 0.9,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------- protocol


class TestResponseRecommendationProtocol:
    def test_valid_payload_parses(self):
        recommendation = parse_response_recommendation(json.dumps(_recommendation_dict()))
        assert isinstance(recommendation, ResponseRecommendation)
        assert [item.action for item in recommendation.recommendations] == [
            "block_source_ip", "escalate_to_incident",
        ]
        assert recommendation.confidence == 0.9

    def test_fenced_and_prose_wrapping_is_tolerated(self):
        fenced = "```json\n" + json.dumps(_recommendation_dict()) + "\n```"
        assert parse_response_recommendation(fenced).confidence == 0.9
        noisy = "Here is my advice:\n" + json.dumps(_recommendation_dict())
        assert len(parse_response_recommendation(noisy).recommendations) == 2

    def test_invalid_json_raises_parse_error(self):
        with pytest.raises(AIResponseParseError):
            parse_response_recommendation("I refuse to recommend anything.")

    @pytest.mark.parametrize("extra_field", ["risk_score", "execute", "commands"])
    def test_unknown_envelope_field_rejected(self, extra_field):
        with pytest.raises(AIResponseParseError):
            parse_response_recommendation(
                json.dumps(_recommendation_dict(**{extra_field: True}))
            )

    def test_unknown_item_field_rejected(self):
        payload = _recommendation_dict(recommendations=[_item(script="iptables -A INPUT ...")])
        with pytest.raises(AIResponseParseError):
            parse_response_recommendation(json.dumps(payload))

    def test_unknown_action_rejected(self):
        payload = _recommendation_dict(recommendations=[_item(action="block_ip_everywhere")])
        with pytest.raises(AIResponseParseError, match="unknown response actions"):
            parse_response_recommendation(json.dumps(payload))

    def test_every_frozen_action_is_accepted(self):
        # One payload per action: the full vocabulary (6) exceeds the 0..5 cap.
        for action in sorted(RESPONSE_ACTIONS):
            payload = _recommendation_dict(recommendations=[_item(action=action)])
            recommendation = parse_response_recommendation(json.dumps(payload))
            assert recommendation.recommendations[0].action == action

    def test_empty_recommendations_is_a_valid_answer(self):
        payload = _recommendation_dict(
            recommendations=[],
            overall_rationale="No response action warranted; keep monitoring.",
        )
        recommendation = parse_response_recommendation(json.dumps(payload))
        assert recommendation.recommendations == []

    def test_more_than_five_recommendations_rejected(self):
        payload = _recommendation_dict(recommendations=[_item() for _ in range(6)])
        with pytest.raises(AIResponseParseError):
            parse_response_recommendation(json.dumps(payload))

    @pytest.mark.parametrize("field", ["overall_rationale", "rationale"])
    def test_empty_rationale_rejected(self, field):
        if field == "overall_rationale":
            payload = _recommendation_dict(overall_rationale="")
        else:
            payload = _recommendation_dict(recommendations=[_item(rationale="")])
        with pytest.raises(AIResponseParseError):
            parse_response_recommendation(json.dumps(payload))

    def test_empty_action_rejected(self):
        payload = _recommendation_dict(recommendations=[_item(action="")])
        with pytest.raises(AIResponseParseError):
            parse_response_recommendation(json.dumps(payload))

    def test_confidence_bounds_enforced(self):
        for bad in (-0.1, 1.5):
            with pytest.raises(AIResponseParseError):
                parse_response_recommendation(json.dumps(_recommendation_dict(confidence=bad)))

    def test_parse_task_output_dispatches(self):
        recommendation = parse_task_output(
            "response_recommendation", json.dumps(_recommendation_dict())
        )
        assert isinstance(recommendation, ResponseRecommendation)


# ------------------------------------------------------------------- prompts


class TestResponseRecommendationPrompts:
    def test_system_prompt_enumerates_vocabulary_and_boundary(self):
        prompt = build_system_prompt("response_recommendation")
        assert prompt is SYSTEM_PROMPT_RESPONSE_RECOMMENDATION
        # The model can only comply if the vocabulary is enumerated inline.
        for action in RESPONSE_ACTIONS:
            assert action in prompt
        # Advisory-only boundary baked into the frozen prompt.
        assert "never" in prompt and "approve" in prompt

    def test_prior_summary_included_only_when_present(self):
        assert "prior_summary" not in build_user_prompt(_request())
        text = build_user_prompt(
            _request(prior_summary={"summary": "brute force from a public IP",
                                      "analyst_priority": "high"})
        )
        assert "brute force from a public IP" in text
        # Other tasks never see the Step 11 projection.
        assert "prior_summary" not in build_user_prompt(_request(task="alert_explanation"))
        assert "prior_summary" not in build_user_prompt(_request(task="risk_summary"))


# ------------------------------------------------------------- mock provider


class TestMockProviderResponseRecommendation:
    def test_deterministic_shape(self):
        recommendation = MockProvider().generate(_request())
        assert isinstance(recommendation, ResponseRecommendation)
        assert 0.0 <= recommendation.confidence <= 1.0
        assert 0 <= len(recommendation.recommendations) <= 5
        assert all(item.action in RESPONSE_ACTIONS for item in recommendation.recommendations)
        assert recommendation == MockProvider().generate(_request())

    def test_high_score_contains_and_escalates(self):
        recommendation = MockProvider().generate(_request(risk_score=85))
        actions = [item.action for item in recommendation.recommendations]
        assert actions == ["block_source_ip", "escalate_to_incident"]
        # Structured target comes from the evidence projection.
        assert recommendation.recommendations[0].target == "203.0.113.9"

    def test_mid_score_investigates_only(self):
        recommendation = MockProvider().generate(_request(risk_score=55))
        actions = [item.action for item in recommendation.recommendations]
        assert actions == ["hunt_related_activity"]

    def test_low_score_returns_first_class_no_action(self):
        recommendation = MockProvider().generate(_request(risk_score=20, risk_level="low"))
        assert recommendation.recommendations == []
        assert "No response action warranted" in recommendation.overall_rationale

    def test_missing_source_ip_yields_empty_target(self):
        recommendation = MockProvider().generate(_request(evidence=["no json here"]))
        assert recommendation.recommendations[0].target == ""

    def test_scripted_failure_hits_this_task(self):
        provider = MockProvider(fail_with=AIProviderUnavailable("simulated outage"))
        with pytest.raises(AIProviderUnavailable):
            provider.generate(_request())


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


class TestOllamaProviderResponseRecommendation:
    def test_recommendation_prompt_and_parse(self):
        transport = FakeTransport(
            body=json.dumps({"message": {"content": json.dumps(_recommendation_dict())}})
        )
        provider = OllamaProvider(model="qwen3:4b", transport=transport)
        recommendation = provider.generate(_request())

        assert isinstance(recommendation, ResponseRecommendation)
        _, payload = transport.calls[0]
        system_text = payload["messages"][0]["content"]
        assert system_text == SYSTEM_PROMPT_RESPONSE_RECOMMENDATION
        assert payload["format"] == "json"

    def test_bad_model_output_maps_to_parse_error(self):
        transport = FakeTransport(body=json.dumps({"message": {"content": "no json here"}}))
        provider = OllamaProvider(model="qwen3:4b", transport=transport)
        with pytest.raises(AIResponseParseError):
            provider.generate(_request())


# ------------------------------------------------------------- request builder


class _Group:
    """Minimal AlertGroup stand-in: the builder only reads plain fields."""

    title = "SSH Brute Force on edge-gateway"
    category = "authentication"
    severity = "high"


class _Risk:
    def __init__(self, score: int, level: str):
        self.score = score
        self.level = level
        self.factors = [{"name": "severity", "score": 30, "reason": "High severity"}]


class _Alert:
    event_type = "ssh_failed_login"
    severity = "high"
    source_ip = "203.0.113.9"
    destination_ip = "10.0.0.5"
    user_name = "root"
    host_name = None
    host_ip = None
    message = "SSH login failure"
    event_count = 1
    first_seen_at = None


class _Summary:
    """Minimal AIRiskSummary stand-in for the optional prior_summary projection."""

    summary = "Brute force from a public IP."
    key_findings = ["30 failed logins"]
    risk_drivers = ["high_frequency"]
    analyst_priority = "high"
    confidence = 0.95
    provider = "mock"
    model = "mock-deterministic"


class TestBuildResponseRecommendationRequest:
    def test_task_is_fixed_and_event_projected(self):
        request = build_response_recommendation_request(
            _Group(), _Risk(85, "high"), [_Alert()]  # type: ignore[arg-type]
        )
        assert request.task == "response_recommendation"
        assert request.event_title == _Group.title
        assert request.risk_score == 85
        assert request.prior_summary is None

    def test_degrades_without_event_risk(self):
        request = build_response_recommendation_request(_Group(), None, [])
        assert request.risk_score == 0
        assert request.risk_level == "unassessed"
        assert request.risk_factors == []

    def test_prior_summary_is_protocol_projection_only(self):
        request = build_response_recommendation_request(
            _Group(), _Risk(85, "high"), [], latest_summary=_Summary()  # type: ignore[arg-type]
        )
        assert request.prior_summary == {
            "summary": _Summary.summary,
            "key_findings": ["30 failed logins"],
            "risk_drivers": ["high_frequency"],
            "analyst_priority": "high",
            "confidence": 0.95,
        }
        # Never forwards ids, provider metadata or timestamps.
        assert request.prior_summary.keys() == {
            "summary", "key_findings", "risk_drivers", "analyst_priority", "confidence",
        }


# --------------------------------------------------------------- orm model


class TestAIResponseRecommendationModel:
    def test_table_shape(self):
        from app.models import AIResponseRecommendation

        assert AIResponseRecommendation.__tablename__ == "ai_response_recommendations"
        columns = {c.name for c in AIResponseRecommendation.__table__.columns}
        assert columns == {
            "id", "alert_group_id", "provider", "model", "overall_rationale",
            "recommendations", "confidence", "created_at", "updated_at",
        }
        # History semantics like ai_analyses / ai_risk_summaries: indexed, NOT unique.
        index_columns = [
            tuple(col.name for col in idx.columns)
            for idx in AIResponseRecommendation.__table__.indexes
        ]
        assert ("alert_group_id",) in index_columns
        assert not any(
            constraint.columns.keys() == ["alert_group_id"]
            for constraint in AIResponseRecommendation.__table__.constraints
            if type(constraint).__name__ == "UniqueConstraint"
        )

    def test_alert_group_relationship_registered(self):
        from app.models import AlertGroup

        assert "ai_response_recommendations" in AlertGroup.__mapper__.relationships
