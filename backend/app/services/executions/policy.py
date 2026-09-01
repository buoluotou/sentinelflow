"""Execution Policy (Phase 3.3.2, design B-3).

The Policy answers exactly one question the Guard does not ask:

    Guard  = "Is this execution structurally and permission-wise legal?"
    Policy = "Even though it is legal, is it ALLOWED right now?"

Position in the frozen chain (B-3):

    Execute Intent -> Approval -> Guard -> Execution Policy -> Executor

State semantics stay frozen: a Policy refusal produces NO new state —
the verdict lands as ``requested -> guard_rejected`` exactly like a
Guard refusal, distinguished only by the audit detail's provenance:

    Guard refusal    detail.source = "guard"
    Policy refusal   detail.source = "policy"   (this module)

Frozen discipline (mirrors guard.py):

- Pure decision: the Policy NEVER touches the database — no add, no
  flush, no commit, no rollback. Appending the guard_rejected row is
  the Execute Service's job (same transaction, D13 lineage).
- Read-only on risk: the Policy consumes the server-side risk fact
  (EventRisk.score, loaded by the Service) and NEVER recomputes risk,
  never writes EventRisk / Incident / Recommendation / Approval.
- Server-side facts only: PolicyContext carries no client-controlled
  field. The request schema accepts no risk / severity / timestamp,
  so a forged client value has no channel into this module.
- Deterministic: the verdict is a pure function of (context, config,
  now). ``now`` is always the SERVER clock (the Service stamps it via
  datetime.now(timezone.utc)); naive datetimes are treated as UTC.
  The Policy time basis is UTC — never the deployment host's local
  timezone, so one policy gives one verdict on every machine.
- Disabled means ALLOW: EXECUTION_POLICY_ENABLED=false short-circuits
  to an allow decision. It never disables the Guard, RBAC or approval
  checks — Policy off is not a security bypass.
- The Executor is NEVER called from here; a refusal must reach the
  caller before dispatch so Executor.execute() stays at zero calls.

First-version rule set (frozen, configuration-driven from .env ->
Settings; no database rules, no DSL, no online editor, no AI):

    A. Time window — execute only inside [start, end) UTC.
    B. Risk threshold — each action needs a minimum server-side risk
       score; a missing risk fact is fail-closed (refuse).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, time, timezone
from types import MappingProxyType
from typing import Mapping

from app.services.executions.guard import EXECUTABLE_ACTIONS

#: Frozen policy rejection-code vocabulary. A rejected PolicyDecision
#: carries exactly one; the guard_rejected row's detail records it
#: verbatim alongside source="policy" (3.3.2.4 service integration).
POLICY_REJECTION_CODES = frozenset(
    {"outside_execution_window", "risk_threshold_not_met"}
)

#: detail.source discriminator — lets the audit trail split
#: guard_rejected rows into source=guard vs source=policy without any
#: state-machine change (B-3 compatibility requirement).
POLICY_SOURCE = "policy"

_HHMM_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


class PolicyViolation(Exception):
    """A malformed policy CONFIGURATION — a deployment fault, never a
    business rejection. Raised at policy construction; the Service
    layer maps it fail-closed (a broken policy never silently becomes
    an allow). Business refusals are PolicyDecision objects, never
    exceptions."""


@dataclass(frozen=True)
class PolicyDecision:
    """The verdict of one policy evaluation — allow or refuse.

    The Policy returns this object; it NEVER writes a log row itself.
    On refusal the Execute Service appends the guard_rejected row with
    ``detail = decision.detail()`` (source / code / reason)."""

    allowed: bool
    code: str = ""
    reason: str = ""
    #: Every policy decision is provenance-tagged "policy"; the audit
    #: query splits guard_rejected on this value. init=False makes it a
    #: frozen constant — no constructor can ever forge another source.
    source: str = field(init=False, default=POLICY_SOURCE)

    @classmethod
    def allow(cls) -> "PolicyDecision":
        """The single allow verdict (no code, no reason)."""
        return cls(allowed=True)

    @classmethod
    def reject(cls, code: str, reason: str) -> "PolicyDecision":
        """A refusal; the code must belong to the frozen vocabulary."""
        if code not in POLICY_REJECTION_CODES:
            raise PolicyViolation(f"Unknown policy rejection code: {code!r}")
        return cls(allowed=False, code=code, reason=reason)

    def detail(self) -> dict:
        """The audit-detail projection the Execute Service persists on
        refusal: {source, code, reason}. For an allow decision there is
        nothing to record — returns an empty dict."""
        if self.allowed:
            return {}
        return {"source": self.source, "code": self.code, "reason": self.reason}


#: The always-allow verdict for the disabled-policy short-circuit.
ALLOW = PolicyDecision.allow()


@dataclass(frozen=True)
class PolicyContext:
    """The server-side facts one policy evaluation judges (read-only).

    Built by the Execute Service from entities it already loaded:
    the approved recommendation's action snapshot and the event's
    EventRisk. Contains NO client-controlled field — the request
    schema (extra="forbid") accepts no risk / severity / timestamp,
    so forged client values have no channel in.

    ``risk_score`` is the authoritative live value (EventRisk.score);
    Incident.risk_score is only a creation-time snapshot and is never
    consulted. None means the event has NO risk fact yet — that is
    fail-closed (refuse), never treated as a passing zero."""

    action: str
    risk_score: int | None = None


#: Frozen first-version risk thresholds — the minimum server-side risk
#: score each executable action requires (design §3.3.2 rule B).
DEFAULT_MIN_RISK_BY_ACTION = MappingProxyType(
    {
        "block_source_ip": 70,
        "isolate_host": 70,
        "disable_account": 80,
        "escalate_to_incident": 50,
    }
)


def parse_hhmm(value: str, field_name: str) -> time:
    """Parse a strict ``HH:MM`` 24h window bound. Malformed values are
    a PolicyViolation (deployment fault, fail-closed at startup) — the
    error names the field, never echoes anything secret."""
    match = _HHMM_RE.match(value.strip() if isinstance(value, str) else "")
    if not match:
        raise PolicyViolation(
            f"{field_name} must be HH:MM (24h, zero-padded); "
            f"the configured value is invalid"
        )
    return time(int(match.group(1)), int(match.group(2)))


@dataclass(frozen=True)
class ExecutionPolicy:
    """Deterministic, configuration-driven execution policy.

    First version freezes exactly two rules (evaluated in order, first
    refusal wins):

        A. Time window   — server-time-of-day in [window_start,
                           window_end), UTC. Start bound is inclusive,
                           end bound is exclusive.
        B. Risk threshold — the event's server-side risk score must
                           reach the action's minimum; a missing risk
                           fact refuses (fail-closed).

    Construction validates the whole configuration eagerly: a
    PolicyViolation at build time means the deployment never runs with
    a half-understood policy."""

    #: Policy off = every evaluation returns ALLOW (never a bypass of
    #: Guard / RBAC / approval — those live outside this module).
    enabled: bool = False
    #: Window bounds, UTC. Defaults encode business hours 09:00-18:00.
    window_start: str = "09:00"
    window_end: str = "18:00"
    #: action -> minimum required risk score; keys must be executable
    #: actions, values integers in [0, 100]. Actions absent from the
    #: mapping carry no risk requirement.
    min_risk_by_action: Mapping[str, int] = field(
        default_factory=lambda: DEFAULT_MIN_RISK_BY_ACTION
    )

    def __post_init__(self) -> None:
        # Eager validation — parsed bounds and the frozen threshold map
        # become instance state; every error is a PolicyViolation.
        object.__setattr__(
            self, "_window_start_time", parse_hhmm(self.window_start, "window_start")
        )
        object.__setattr__(
            self, "_window_end_time", parse_hhmm(self.window_end, "window_end")
        )
        if not isinstance(self.min_risk_by_action, Mapping):
            raise PolicyViolation("min_risk_by_action must be a mapping")
        thresholds: dict[str, int] = {}
        for action, threshold in self.min_risk_by_action.items():
            if action not in EXECUTABLE_ACTIONS:
                raise PolicyViolation(
                    f"min_risk_by_action key {action!r} is not an "
                    f"executable action"
                )
            if isinstance(threshold, bool) or not isinstance(threshold, int):
                raise PolicyViolation(
                    f"min_risk_by_action[{action!r}] must be an integer"
                )
            if not 0 <= threshold <= 100:
                raise PolicyViolation(
                    f"min_risk_by_action[{action!r}] must be within 0..100"
                )
            thresholds[action] = threshold
        object.__setattr__(
            self, "_min_risk", MappingProxyType(dict(thresholds))
        )

    # -- evaluated bounds (parsed once at construction) -----------------

    @property
    def window_start_time(self) -> time:
        return self._window_start_time

    @property
    def window_end_time(self) -> time:
        return self._window_end_time

    # -- evaluation ------------------------------------------------------

    def evaluate(
        self, context: PolicyContext, now: datetime
    ) -> PolicyDecision:
        """Pure verdict: (context, config, now) -> allow / refuse.

        ``now`` is the SERVER time supplied by the Execute Service
        (datetime.now(timezone.utc)); a naive datetime is treated as
        UTC. Client-supplied timestamps have no path here — the time
        basis is always the server clock converted to UTC."""
        if not self.enabled:
            return ALLOW
        decision = self._check_time_window(now)
        if not decision.allowed:
            return decision
        return self._check_risk_threshold(context)

    def _check_time_window(self, now: datetime) -> PolicyDecision:
        utc_now = _to_utc(now)
        wall = utc_now.time()
        if self.window_start_time <= wall < self.window_end_time:
            return ALLOW
        return PolicyDecision.reject(
            "outside_execution_window",
            f"Server time {utc_now.strftime('%H:%M')} UTC is outside the "
            f"allowed execution window "
            f"{self.window_start}-{self.window_end} UTC",
        )

    def _check_risk_threshold(self, context: PolicyContext) -> PolicyDecision:
        minimum = self._min_risk.get(context.action)
        if minimum is None:
            return ALLOW
        if context.risk_score is None:
            return PolicyDecision.reject(
                "risk_threshold_not_met",
                f"Action '{context.action}' requires a server-side risk "
                f"score of at least {minimum}, but the event has no risk "
                f"assessment; refusing fail-closed",
            )
        if context.risk_score < minimum:
            return PolicyDecision.reject(
                "risk_threshold_not_met",
                f"Action '{context.action}' requires a server-side risk "
                f"score of at least {minimum}; the event's risk score is "
                f"{context.risk_score}",
            )
        return ALLOW


def evaluate_execution_policy(
    context: PolicyContext, policy: ExecutionPolicy, now: datetime
) -> PolicyDecision:
    """Functional entry point over ExecutionPolicy.evaluate — same
    verdict, both shapes kept so the Service integration picks the
    style that matches the surrounding code."""
    return policy.evaluate(context, now)


def policy_from_settings(settings) -> ExecutionPolicy:
    """Build the deployment's ExecutionPolicy from application settings
    (Phase 3.3.2.4 — .env -> Settings -> Policy Config; no database
    rules, no DSL).

    Structural typing on purpose: this module never imports the config
    layer — any object exposing the EXECUTION_POLICY_* attributes
    works, which keeps the decision model pure and directly testable.
    Malformed values raise PolicyViolation EAGERLY (fail-closed: a
    broken policy never silently becomes an allow), even when the
    policy is disabled — the configuration is validated the moment it
    is read."""
    return ExecutionPolicy(
        enabled=bool(settings.EXECUTION_POLICY_ENABLED),
        window_start=str(settings.EXECUTION_POLICY_WINDOW_START),
        window_end=str(settings.EXECUTION_POLICY_WINDOW_END),
        min_risk_by_action={
            "block_source_ip": int(
                settings.EXECUTION_POLICY_MIN_RISK_BLOCK_SOURCE_IP
            ),
            "isolate_host": int(settings.EXECUTION_POLICY_MIN_RISK_ISOLATE_HOST),
            "disable_account": int(
                settings.EXECUTION_POLICY_MIN_RISK_DISABLE_ACCOUNT
            ),
            "escalate_to_incident": int(
                settings.EXECUTION_POLICY_MIN_RISK_ESCALATE_TO_INCIDENT
            ),
        },
    )


def _to_utc(moment: datetime) -> datetime:
    """Normalize the server clock to UTC. Aware datetimes convert;
    naive ones are treated as UTC (frozen time basis — never the host's
    local timezone)."""
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


__all__ = [
    "ALLOW",
    "DEFAULT_MIN_RISK_BY_ACTION",
    "POLICY_REJECTION_CODES",
    "POLICY_SOURCE",
    "ExecutionPolicy",
    "PolicyContext",
    "PolicyDecision",
    "PolicyViolation",
    "evaluate_execution_policy",
    "parse_hhmm",
    "policy_from_settings",
]
