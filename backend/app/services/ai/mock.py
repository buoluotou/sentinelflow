"""Deterministic mock provider (Phase 2 Step 9; task-aware since Step 11).

Default provider for tests, demos and air-gapped development: it satisfies
every frozen protocol with zero external dependencies and reproducible
output (same input -> identical result). It never pretends to be a model
— the name stays "mock" everywhere it surfaces.
"""
import json

from app.services.ai.base import AIProvider
from app.services.ai.exceptions import AIProviderError
from app.services.ai.models import (
    TASK_RESPONSE_RECOMMENDATION,
    TASK_RISK_SUMMARY,
    AIAnalysis,
    AIRequest,
    ResponseRecommendation,
    RecommendationItem,
    RiskSummary,
)

#: Frozen Risk Engine factor name -> risk-driver vocabulary (Step 11).
_FACTOR_TO_DRIVER = {
    "severity": "severity",
    "frequency": "high_frequency",
    "public_source": "public_source",
}


class MockProvider(AIProvider):
    name = "mock"

    def __init__(self, model: str = "mock-deterministic", fail_with: AIProviderError | None = None):
        super().__init__(model)
        self._fail_with = fail_with

    def generate(self, request: AIRequest) -> AIAnalysis | RiskSummary | ResponseRecommendation:
        if self._fail_with is not None:
            raise self._fail_with
        if request.task == TASK_RISK_SUMMARY:
            return self._risk_summary(request)
        if request.task == TASK_RESPONSE_RECOMMENDATION:
            return self._response_recommendation(request)
        return self._explanation(request)

    def _explanation(self, request: AIRequest) -> AIAnalysis:
        why_risky = [factor["reason"] for factor in request.risk_factors if factor.get("reason")]
        return AIAnalysis(
            summary=(
                f"[mock] {request.event_title}: {request.risk_level} risk "
                f"(score {request.risk_score}) based on {len(request.evidence)} evidence items."
            ),
            attack_type=request.event_category,
            why_risky=why_risky or ["[mock] no risk factors recorded"],
            confidence=round(min(request.risk_score, 100) / 100, 2),
        )

    def _risk_summary(self, request: AIRequest) -> RiskSummary:
        findings = [factor["reason"] for factor in request.risk_factors if factor.get("reason")]
        drivers = [
            _FACTOR_TO_DRIVER[factor["name"]]
            for factor in request.risk_factors
            if factor.get("name") in _FACTOR_TO_DRIVER
        ]
        if request.risk_score >= 70:
            drivers.append("high_risk_score")
        priority = request.risk_level if request.risk_level in (
            "low", "medium", "high", "critical") else "low"
        return RiskSummary(
            summary=(
                f"[mock] Risk summary for {request.event_title}: {request.risk_level} risk "
                f"(score {request.risk_score}) based on {len(request.evidence)} evidence items."
            ),
            key_findings=(findings or ["[mock] no risk factors recorded"])[:5],
            risk_drivers=drivers or ["severity"],
            analyst_priority=priority,
            confidence=round(min(request.risk_score, 100) / 100, 2),
        )

    def _response_recommendation(self, request: AIRequest) -> ResponseRecommendation:
        """Frozen deterministic advice (Step 12): advisory only, never executed.

        Score-banded actions so every protocol shape is reachable from tests:
        score >= 70 -> contain + escalate; 40..69 -> investigate; < 40 -> the
        first-class "no action warranted" answer (empty recommendations).
        """
        target = self._first_source_ip(request)
        items: list[RecommendationItem] = []
        if request.risk_score >= 70:
            items.append(
                RecommendationItem(
                    action="block_source_ip",
                    target=target,
                    rationale=(
                        f"[mock] High risk (score {request.risk_score}): stop the "
                        "observed source from reaching the asset."
                    ),
                )
            )
            items.append(
                RecommendationItem(
                    action="escalate_to_incident",
                    target="",
                    rationale="[mock] The risk posture warrants a tracked SOC case.",
                )
            )
        elif request.risk_score >= 40:
            items.append(
                RecommendationItem(
                    action="hunt_related_activity",
                    target=target,
                    rationale=(
                        f"[mock] Elevated risk (score {request.risk_score}): look for "
                        "related activity before acting."
                    ),
                )
            )
        return ResponseRecommendation(
            overall_rationale=(
                f"[mock] Response guidance for {request.event_title}: "
                f"{request.risk_level} risk (score {request.risk_score}) based on "
                f"{len(request.evidence)} evidence items."
                if items
                else f"[mock] No response action warranted for {request.event_title}: "
                f"{request.risk_level} risk (score {request.risk_score}); keep monitoring."
            ),
            recommendations=items,
            confidence=round(min(request.risk_score, 100) / 100, 2),
        )

    @staticmethod
    def _first_source_ip(request: AIRequest) -> str:
        """First source_ip across the evidence projection, '' when absent."""
        for raw in request.evidence:
            try:
                item = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                continue
            if isinstance(item, dict) and item.get("source_ip"):
                return str(item["source_ip"])
        return ""
