"""Deterministic mock provider (Phase 2 Step 9; task-aware in Step 11).

Default provider for tests, demos and air-gapped development: it satisfies
every frozen protocol with zero external dependencies and reproducible
output (same input -> identical result). It never pretends to be a model
— the name stays "mock" everywhere it surfaces.
"""
from app.services.ai.base import AIProvider
from app.services.ai.exceptions import AIProviderError
from app.services.ai.models import (
    TASK_RISK_SUMMARY,
    AIAnalysis,
    AIRequest,
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

    def generate(self, request: AIRequest) -> AIAnalysis | RiskSummary:
        if self._fail_with is not None:
            raise self._fail_with
        if request.task == TASK_RISK_SUMMARY:
            return self._risk_summary(request)
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
