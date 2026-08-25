"""Deterministic mock provider (Phase 2 Step 9).

Default provider for tests, demos and air-gapped development: it satisfies
the frozen protocol with zero external dependencies and reproducible output
(same input -> identical analysis). It never pretends to be a model — the
name stays "mock" everywhere it surfaces.
"""
from app.services.ai.base import AIProvider
from app.services.ai.exceptions import AIProviderError
from app.services.ai.models import AIAnalysis, AIRequest


class MockProvider(AIProvider):
    name = "mock"

    def __init__(self, model: str = "mock-deterministic", fail_with: AIProviderError | None = None):
        super().__init__(model)
        self._fail_with = fail_with

    def explain(self, request: AIRequest) -> AIAnalysis:
        if self._fail_with is not None:
            raise self._fail_with
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
