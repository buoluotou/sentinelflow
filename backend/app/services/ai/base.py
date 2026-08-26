"""AIProvider contract (Phase 2 Step 9; task-unified in Step 11).

One method — generate(request) -> frozen protocol object — shared by every
provider and every task, so swapping Ollama for a cloud model (or adding a
task) never touches Incident or Risk Engine code. explain() remains as the
Step 10-compatible alias for task=alert_explanation. Prompts are built HERE
once and shared by all real providers: one frozen prompt contract per task,
one frozen output protocol per task.
"""
import json
from abc import ABC, abstractmethod

from app.services.ai.models import (
    RESPONSE_ACTIONS,
    RISK_DRIVERS,
    TASK_ALERT_EXPLANATION,
    TASK_RESPONSE_RECOMMENDATION,
    TASK_RISK_SUMMARY,
    AIAnalysis,
    AIRequest,
    ResponseRecommendation,
    RiskSummary,
)

#: Frozen system prompt (alert_explanation): identity + the structured-output
#: contract. Real providers must answer with JSON only; parsing stays strict
#: regardless.
SYSTEM_PROMPT = (
    "You are a security operations analyst assistant. Analyse the provided "
    "security event and answer ONLY with a JSON object — no markdown, no "
    "prose — using exactly these fields:\n"
    '{"summary": string, "attack_type": string, "why_risky": array of '
    'strings, "confidence": number between 0 and 1}.'
)

#: Frozen system prompt (risk_summary, Step 11): SOC-level synthesis. The
#: driver vocabulary is enumerated inline so the model can only pick frozen
#: names; parsing enforces it anyway. analyst_priority is advisory only —
#: the model must NOT invent a new risk score.
SYSTEM_PROMPT_RISK_SUMMARY = (
    "You are a security operations analyst assistant. Compress the provided "
    "security event, its risk factors and evidence into a concise risk "
    "summary for a SOC analyst. Answer ONLY with a JSON object — no "
    "markdown, no prose — using exactly these fields:\n"
    '{"summary": string (one short paragraph), "key_findings": array of 1 '
    "to 5 strings (the most important facts), \"risk_drivers\": array of "
    "strings chosen ONLY from this list: "
    f"{', '.join(sorted(RISK_DRIVERS))}, \"analyst_priority\": one of "
    '"low", "medium", "high", "critical", "confidence": number between 0 '
    "and 1}. Do not recompute the risk score; analyst_priority only "
    "expresses how urgently an analyst should review this event. If a "
    "prior_explanation from an earlier analysis is included, build on it "
    "instead of re-deriving everything."
)

#: Frozen system prompt (response_recommendation, Step 12): advisory-only
#: response guidance. The action vocabulary is enumerated inline; parsing
#: enforces it. Hard boundary baked into the prompt: the assistant only
#: RECOMMENDS — a human approves (Step 13) before anything is ever
#: executed, so the model must never phrase recommendations as commands or
#: claim any action was taken.
SYSTEM_PROMPT_RESPONSE_RECOMMENDATION = (
    "You are a security operations analyst assistant. Based on the provided "
    "security event, its risk assessment and evidence, propose response "
    "RECOMMENDATIONS for a human SOC analyst. You only advise: you never "
    "execute, block, isolate, disable or change anything yourself, and a "
    "human must approve every action before it can ever happen. Answer "
    "ONLY with a JSON object — no markdown, no prose — using exactly these "
    "fields:\n"
    '{"overall_rationale": string (one short paragraph on the recommended '
    'posture), "recommendations": array of 0 to 5 objects, each exactly '
    '{"action": string chosen ONLY from this list: '
    f"{', '.join(sorted(RESPONSE_ACTIONS))}, \"target\": string (the "
    "specific analyst-facing subject such as an IP, hostname or account; "
    "empty string when nothing specific applies), \"rationale\": string "
    "(why this action helps)}, \"confidence\": number between 0 and 1}. "
    "If no response action is warranted, return an empty recommendations "
    "array — never invent actions to fill space. Do not recompute the risk "
    "score and never phrase a recommendation as an already-performed "
    "action. If a prior_summary from an earlier risk summary is included, "
    "build on it instead of re-deriving everything."
)

#: Task -> frozen system prompt. Adding a task means adding one entry here
#: plus one protocol model/parser — never a provider-specific code path.
SYSTEM_PROMPTS: dict[str, str] = {
    TASK_ALERT_EXPLANATION: SYSTEM_PROMPT,
    TASK_RISK_SUMMARY: SYSTEM_PROMPT_RISK_SUMMARY,
    TASK_RESPONSE_RECOMMENDATION: SYSTEM_PROMPT_RESPONSE_RECOMMENDATION,
}


def build_system_prompt(task: str) -> str:
    """Frozen system prompt of a task; unknown tasks fail loudly."""
    try:
        return SYSTEM_PROMPTS[task]
    except KeyError as exc:
        raise ValueError(f"Unknown AI task: {task}") from exc


def build_user_prompt(request: AIRequest) -> str:
    """Serialise the analysis job as JSON context for the model.

    exclude_none keeps the alert_explanation prompt byte-identical to the
    Step 10 freeze while letting optional fields (prior_explanation) appear
    only when present.
    """
    return json.dumps(request.model_dump(exclude_none=True), ensure_ascii=False, indent=2)


class AIProvider(ABC):
    """Uniform contract: name/model for observability + generate()."""

    name: str = "base"

    def __init__(self, model: str):
        self.model = model

    @abstractmethod
    def generate(self, request: AIRequest) -> AIAnalysis | RiskSummary | ResponseRecommendation:
        """Run one task; raises AIProviderError subclasses on failure.

        The output type follows request.task (alert_explanation -> AIAnalysis,
        risk_summary -> RiskSummary, response_recommendation ->
        ResponseRecommendation). Never returns a fabricated result for a
        broken provider output."""

    def explain(self, request: AIRequest) -> AIAnalysis:
        """Step 10-compatible alias: generate() for alert_explanation only."""
        if request.task != TASK_ALERT_EXPLANATION:
            raise ValueError(
                f"explain() only accepts task={TASK_ALERT_EXPLANATION!r}, got {request.task!r}"
            )
        result = self.generate(request)
        assert isinstance(result, AIAnalysis)
        return result
