"""Phase 3.3.2.1 — Execution Policy decision model tests.

Locks the PURE decision layer (no DB, no Executor, no API):

    ExecutionPolicy.evaluate(PolicyContext, now) -> PolicyDecision

Coverage map (acceptance gate):

Policy Core
- time window allow / deny / boundary start (inclusive) / boundary end
  (exclusive) / UTC handling (aware conversions + naive = UTC)
- risk allow / deny / per-action thresholds / action without threshold
  / missing risk fact -> fail-closed
- combined policies (first refusal wins: window before risk)
- policy disabled -> ALLOW (never a Guard bypass — structural)
- malformed config -> PolicyViolation (fail-closed at construction)
- deterministic decision (same inputs -> same verdict, always)

Attack suite
- fake risk: a forged high value cannot enter — only the server fact
  in PolicyContext is judged
- fake severity: no severity channel exists on PolicyContext
- fake timestamp: no timestamp channel exists; the decision follows the
  server ``now`` argument only
- fake operator: no operator channel exists
- policy bypass: disabled policy returns ALLOW, not a chain skip
- executor zero-call: the module never references an executor (source
  lock) and evaluate() takes none

Fact immunity
- PolicyContext / ExecutionPolicy are immutable; Policy NEVER writes
  (source lock: no add / flush / commit / rollback in policy.py)

No Service change, no state-machine change, no React.
"""
import inspect
from datetime import datetime, time, timedelta, timezone

import pytest

from app.services.executions import policy as policy_module
from app.services.executions.policy import (
    ALLOW,
    DEFAULT_MIN_RISK_BY_ACTION,
    POLICY_REJECTION_CODES,
    POLICY_SOURCE,
    ExecutionPolicy,
    PolicyContext,
    PolicyDecision,
    PolicyViolation,
    evaluate_execution_policy,
    parse_hhmm,
)

JST = timezone(timedelta(hours=9))  # non-UTC zone for conversion proofs


def enabled_policy(**overrides) -> ExecutionPolicy:
    return ExecutionPolicy(enabled=True, **overrides)


def at(hour: int, minute: int = 0, tz=timezone.utc) -> datetime:
    """A fixed wall-clock moment on 2026-09-01 (deterministic)."""
    return datetime(2026, 9, 1, hour, minute, tzinfo=tz)


# --------------------------------------------------------------------------
# PolicyDecision — the verdict object
# --------------------------------------------------------------------------
class TestPolicyDecision:
    def test_allow_is_allowed_no_code(self):
        d = PolicyDecision.allow()
        assert d.allowed is True
        assert d.code == ""
        assert d.reason == ""

    def test_reject_carries_code_and_reason(self):
        d = PolicyDecision.reject("outside_execution_window", "after hours")
        assert d.allowed is False
        assert d.code == "outside_execution_window"
        assert d.reason == "after hours"

    def test_reject_unknown_code_is_policy_violation(self):
        with pytest.raises(PolicyViolation, match="Unknown policy rejection code"):
            PolicyDecision.reject("policy_rejected", "no such word")

    def test_rejection_codes_frozen_vocabulary(self):
        assert POLICY_REJECTION_CODES == {
            "outside_execution_window",
            "risk_threshold_not_met",
        }
        # B-3 compatibility: NO new execution state is ever introduced.
        assert "policy_rejected" not in POLICY_REJECTION_CODES

    def test_source_is_always_policy(self):
        assert PolicyDecision.allow().source == "policy"
        assert (
            PolicyDecision.reject("risk_threshold_not_met", "x").source
            == "policy"
        )
        assert POLICY_SOURCE == "policy"

    def test_detail_projection_for_refusal(self):
        d = PolicyDecision.reject("outside_execution_window", "too late")
        assert d.detail() == {
            "source": "policy",
            "code": "outside_execution_window",
            "reason": "too late",
        }

    def test_detail_projection_for_allow_is_empty(self):
        assert PolicyDecision.allow().detail() == {}

    def test_decision_is_immutable(self):
        d = PolicyDecision.reject("risk_threshold_not_met", "low")
        with pytest.raises(Exception):
            d.allowed = True  # type: ignore[misc]

    def test_source_cannot_be_forged_at_construction(self):
        """init=False lock: no caller can mint a decision claiming a
        different provenance (e.g. 'guard')."""
        with pytest.raises(TypeError):
            PolicyDecision(allowed=True, source="guard")  # type: ignore[call-arg]


# --------------------------------------------------------------------------
# Policy Core — time window
# --------------------------------------------------------------------------
class TestTimeWindowPolicy:
    def test_inside_window_allows(self):
        policy = enabled_policy()
        ctx = PolicyContext(action="block_source_ip", risk_score=90)
        decision = policy.evaluate(ctx, at(10, 30))
        assert decision.allowed is True

    def test_outside_window_denies(self):
        policy = enabled_policy()
        ctx = PolicyContext(action="block_source_ip", risk_score=90)
        decision = policy.evaluate(ctx, at(23, 0))
        assert decision.allowed is False
        assert decision.code == "outside_execution_window"
        assert decision.source == "policy"
        assert "23:00" in decision.reason

    def test_boundary_start_is_inclusive(self):
        policy = enabled_policy()
        ctx = PolicyContext(action="block_source_ip", risk_score=90)
        assert policy.evaluate(ctx, at(9, 0)).allowed is True

    def test_boundary_end_is_exclusive(self):
        policy = enabled_policy()
        ctx = PolicyContext(action="block_source_ip", risk_score=90)
        assert policy.evaluate(ctx, at(18, 0)).allowed is False

    def test_one_minute_before_end_allows(self):
        policy = enabled_policy()
        ctx = PolicyContext(action="block_source_ip", risk_score=90)
        assert policy.evaluate(ctx, at(17, 59)).allowed is True

    def test_one_second_before_start_denies(self):
        policy = enabled_policy()
        ctx = PolicyContext(action="block_source_ip", risk_score=90)
        moment = at(8, 59) + timedelta(seconds=59)
        assert policy.evaluate(ctx, moment).allowed is False

    def test_custom_window_respected(self):
        policy = enabled_policy(window_start="00:00", window_end="06:00")
        ctx = PolicyContext(action="block_source_ip", risk_score=90)
        assert policy.evaluate(ctx, at(3, 0)).allowed is True
        assert policy.evaluate(ctx, at(12, 0)).allowed is False

    def test_naive_datetime_treated_as_utc(self):
        """Frozen time basis: a naive server clock is UTC — never the
        host's local timezone."""
        policy = enabled_policy()
        ctx = PolicyContext(action="block_source_ip", risk_score=90)
        naive_inside = datetime(2026, 9, 1, 10, 0)  # naive
        naive_outside = datetime(2026, 9, 1, 23, 0)  # naive
        assert policy.evaluate(ctx, naive_inside).allowed is True
        assert policy.evaluate(ctx, naive_outside).allowed is False

    def test_aware_non_utc_converted_to_utc(self):
        """A +09:00 server clock at 18:00 local is 09:00 UTC — inside
        the window; the verdict follows UTC, never the wall clock."""
        policy = enabled_policy()
        ctx = PolicyContext(action="block_source_ip", risk_score=90)
        assert policy.evaluate(ctx, at(18, 0, tz=JST)).allowed is True
        # 08:00 JST == 23:00 UTC — outside.
        assert policy.evaluate(ctx, at(8, 0, tz=JST)).allowed is False

    def test_reason_names_utc(self):
        policy = enabled_policy()
        ctx = PolicyContext(action="block_source_ip", risk_score=90)
        decision = policy.evaluate(ctx, at(2, 15, tz=JST))  # 17:15 UTC -> inside
        assert decision.allowed is True
        decision = policy.evaluate(ctx, at(4, 0, tz=JST))  # 19:00 UTC -> outside
        assert decision.allowed is False
        assert "UTC" in decision.reason
        assert "19:00" in decision.reason


# --------------------------------------------------------------------------
# Policy Core — risk threshold
# --------------------------------------------------------------------------
class TestRiskThresholdPolicy:
    def test_risk_at_threshold_allows(self):
        policy = enabled_policy()
        ctx = PolicyContext(action="block_source_ip", risk_score=70)
        assert policy.evaluate(ctx, at(10, 0)).allowed is True

    def test_risk_below_threshold_denies(self):
        policy = enabled_policy()
        ctx = PolicyContext(action="block_source_ip", risk_score=40)
        decision = policy.evaluate(ctx, at(10, 0))
        assert decision.allowed is False
        assert decision.code == "risk_threshold_not_met"
        assert decision.source == "policy"
        assert "40" in decision.reason and "70" in decision.reason

    def test_per_action_thresholds(self):
        """The frozen first-version table: block/isolate 70, disable 80,
        escalate 50. One score can pass one action and fail another."""
        policy = enabled_policy()
        moment = at(10, 0)
        assert (
            policy.evaluate(
                PolicyContext(action="block_source_ip", risk_score=75), moment
            ).allowed
            is True
        )
        assert (
            policy.evaluate(
                PolicyContext(action="disable_account", risk_score=75), moment
            ).allowed
            is False
        )
        assert (
            policy.evaluate(
                PolicyContext(action="escalate_to_incident", risk_score=55), moment
            ).allowed
            is True
        )
        assert (
            policy.evaluate(
                PolicyContext(action="escalate_to_incident", risk_score=45), moment
            ).allowed
            is False
        )

    def test_action_without_threshold_carries_no_risk_rule(self):
        """Actions absent from the threshold map have no risk
        requirement (window still applies)."""
        policy = enabled_policy(min_risk_by_action={"block_source_ip": 70})
        ctx = PolicyContext(action="isolate_host", risk_score=None)
        assert policy.evaluate(ctx, at(10, 0)).allowed is True

    def test_missing_risk_fact_is_fail_closed(self):
        """No EventRisk row -> risk_score None -> refuse; never treated
        as a passing zero or an implicit allow."""
        policy = enabled_policy()
        ctx = PolicyContext(action="block_source_ip", risk_score=None)
        decision = policy.evaluate(ctx, at(10, 0))
        assert decision.allowed is False
        assert decision.code == "risk_threshold_not_met"
        assert "no risk assessment" in decision.reason

    def test_zero_risk_denied(self):
        policy = enabled_policy()
        ctx = PolicyContext(action="escalate_to_incident", risk_score=0)
        assert policy.evaluate(ctx, at(10, 0)).allowed is False

    def test_custom_thresholds_respected(self):
        policy = enabled_policy(min_risk_by_action={"isolate_host": 99})
        moment = at(10, 0)
        assert (
            policy.evaluate(
                PolicyContext(action="isolate_host", risk_score=98), moment
            ).allowed
            is False
        )
        assert (
            policy.evaluate(
                PolicyContext(action="isolate_host", risk_score=99), moment
            ).allowed
            is True
        )


# --------------------------------------------------------------------------
# Policy Core — combined, disabled, deterministic
# --------------------------------------------------------------------------
class TestCombinedAndModes:
    def test_window_refusal_wins_over_risk(self):
        """First refusal wins, window first: at 23:00 with risk 10 the
        verdict is outside_execution_window, not risk."""
        policy = enabled_policy()
        ctx = PolicyContext(action="block_source_ip", risk_score=10)
        decision = policy.evaluate(ctx, at(23, 0))
        assert decision.code == "outside_execution_window"

    def test_risk_refusal_when_window_passes(self):
        policy = enabled_policy()
        ctx = PolicyContext(action="block_source_ip", risk_score=10)
        decision = policy.evaluate(ctx, at(10, 0))
        assert decision.code == "risk_threshold_not_met"

    def test_both_pass_allows(self):
        policy = enabled_policy()
        ctx = PolicyContext(action="isolate_host", risk_score=85)
        assert policy.evaluate(ctx, at(14, 0)).allowed is True

    def test_disabled_policy_always_allows(self):
        """EXECUTION_POLICY_ENABLED=false -> ALLOW regardless of time
        and risk (the default shipping mode)."""
        policy = ExecutionPolicy()  # enabled=False by default
        ctx = PolicyContext(action="block_source_ip", risk_score=0)
        assert policy.evaluate(ctx, at(3, 0)).allowed is True
        assert policy.evaluate(ctx, at(23, 59)).allowed is True

    def test_disabled_returns_the_allow_constant(self):
        policy = ExecutionPolicy()
        ctx = PolicyContext(action="block_source_ip", risk_score=None)
        assert policy.evaluate(ctx, at(3, 0)) is ALLOW

    def test_functional_entrypoint_matches_method(self):
        policy = enabled_policy()
        ctx = PolicyContext(action="block_source_ip", risk_score=40)
        moment = at(10, 0)
        assert evaluate_execution_policy(ctx, policy, moment) == policy.evaluate(
            ctx, moment
        )

    def test_decision_is_deterministic(self):
        """Same (context, config, now) -> identical verdict, every
        time; no clock read, no randomness inside evaluate()."""
        policy = enabled_policy()
        ctx = PolicyContext(action="disable_account", risk_score=79)
        moment = at(10, 0)
        verdicts = {policy.evaluate(ctx, moment) for _ in range(20)}
        assert len(verdicts) == 1
        verdict = verdicts.pop()
        assert verdict.allowed is False
        assert verdict.code == "risk_threshold_not_met"


# --------------------------------------------------------------------------
# Configuration validation (fail-closed at construction)
# --------------------------------------------------------------------------
class TestConfigValidation:
    def test_malformed_window_start_rejected(self):
        with pytest.raises(PolicyViolation, match="window_start"):
            enabled_policy(window_start="9am")

    def test_malformed_window_end_rejected(self):
        with pytest.raises(PolicyViolation, match="window_end"):
            enabled_policy(window_end="25:00")

    def test_unpadded_hour_rejected(self):
        with pytest.raises(PolicyViolation, match="window_start"):
            enabled_policy(window_start="9:00")

    def test_non_string_window_rejected(self):
        with pytest.raises(PolicyViolation, match="window_end"):
            enabled_policy(window_end=1800)  # type: ignore[arg-type]

    def test_non_executable_threshold_key_rejected(self):
        with pytest.raises(PolicyViolation, match="not an executable action"):
            enabled_policy(min_risk_by_action={"monitor_only": 50})

    def test_unknown_action_threshold_key_rejected(self):
        with pytest.raises(PolicyViolation, match="not an executable action"):
            enabled_policy(min_risk_by_action={"launch_missiles": 10})

    def test_threshold_out_of_range_rejected(self):
        with pytest.raises(PolicyViolation, match="0..100"):
            enabled_policy(min_risk_by_action={"isolate_host": 101})
        with pytest.raises(PolicyViolation, match="0..100"):
            enabled_policy(min_risk_by_action={"isolate_host": -1})

    def test_non_integer_threshold_rejected(self):
        with pytest.raises(PolicyViolation, match="must be an integer"):
            enabled_policy(min_risk_by_action={"isolate_host": "70"})  # type: ignore[dict-item]
        # bool is an int subclass — still refused (determinism first).
        with pytest.raises(PolicyViolation, match="must be an integer"):
            enabled_policy(min_risk_by_action={"isolate_host": True})  # type: ignore[dict-item]

    def test_non_mapping_thresholds_rejected(self):
        with pytest.raises(PolicyViolation, match="must be a mapping"):
            enabled_policy(min_risk_by_action=[("isolate_host", 70)])  # type: ignore[arg-type]

    def test_error_messages_are_stable_and_secret_free(self):
        """Config errors name the FIELD, never echo values a deployment
        might have injected elsewhere."""
        with pytest.raises(PolicyViolation) as exc:
            enabled_policy(window_start="not-a-time")
        assert "window_start" in str(exc.value)

    def test_parsed_bounds_exposed(self):
        policy = enabled_policy(window_start="08:30", window_end="17:45")
        assert policy.window_start_time == time(8, 30)
        assert policy.window_end_time == time(17, 45)

    def test_default_threshold_table_is_the_frozen_four(self):
        assert dict(DEFAULT_MIN_RISK_BY_ACTION) == {
            "block_source_ip": 70,
            "isolate_host": 70,
            "disable_account": 80,
            "escalate_to_incident": 50,
        }

    def test_parse_hhmm_helper(self):
        assert parse_hhmm("09:00", "x") == time(9, 0)
        assert parse_hhmm(" 18:30 ", "x") == time(18, 30)
        with pytest.raises(PolicyViolation):
            parse_hhmm("", "x")


# --------------------------------------------------------------------------
# Attack suite — forged client inputs have no channel
# --------------------------------------------------------------------------
class TestForgedInputImmunity:
    def test_fake_risk_cannot_enter_context(self):
        """Attack: client claims risk=100, real server fact is 40.
        PolicyContext carries ONLY the server fact — the forged value
        has no field to land in, so the verdict follows the real 40."""
        policy = enabled_policy()
        real_server_fact = PolicyContext(action="block_source_ip", risk_score=40)
        decision = policy.evaluate(real_server_fact, at(10, 0))
        assert decision.allowed is False  # 40 < 70, regardless of claims

    def test_fake_severity_has_no_channel(self):
        """PolicyContext exposes NO severity field — a forged
        severity=critical cannot influence the decision."""
        fields = set(PolicyContext.__dataclass_fields__)
        assert "severity" not in fields

    def test_fake_timestamp_has_no_channel(self):
        """PolicyContext exposes NO timestamp field; the decision
        follows the server ``now`` argument only. A client claiming
        'it is 10:00' cannot move the verdict when the server clock
        says 23:00."""
        fields = set(PolicyContext.__dataclass_fields__)
        assert "timestamp" not in fields
        policy = enabled_policy()
        ctx = PolicyContext(action="block_source_ip", risk_score=90)
        decision = policy.evaluate(ctx, at(23, 0))  # server clock wins
        assert decision.allowed is False

    def test_fake_operator_has_no_channel(self):
        fields = set(PolicyContext.__dataclass_fields__)
        assert "operator" not in fields

    def test_context_carries_exactly_action_and_risk(self):
        """Frozen surface: the ONLY inputs are the executable action
        and the server-side risk score. Adding any client-facing field
        here must fail this lock."""
        assert set(PolicyContext.__dataclass_fields__) == {"action", "risk_score"}

    def test_request_schema_still_forbids_policy_fields(self):
        """Boundary proof from the other side: the API request schemas
        (extra='forbid') accept no risk / severity / timestamp, so
        forged values die at 422 before any service runs."""
        from app.schemas.response_execution import CompensateRequest, ExecuteRequest

        for schema in (ExecuteRequest, CompensateRequest):
            assert schema.model_config.get("extra") == "forbid"
            fields = set(schema.model_fields)
            assert fields.isdisjoint({"risk_score", "severity", "timestamp"})


# --------------------------------------------------------------------------
# Fact immunity + executor zero-call (structural locks)
# --------------------------------------------------------------------------
class TestPurityLocks:
    def test_policy_module_never_writes(self):
        """Source lock: policy.py contains no DB-write primitive. The
        guard_rejected row is the Execute Service's job."""
        source = inspect.getsource(policy_module)
        for forbidden in (".add(", ".flush(", ".commit(", ".rollback("):
            assert forbidden not in source, f"policy.py must never {forbidden}"

    def test_policy_module_never_imports_executor(self):
        """Import lock (AST-level): policy.py imports no executor
        module — a policy refusal must stop the chain BEFORE dispatch
        (Executor zero-call). The module docstring may mention the
        Executor to explain the boundary; imports may not."""
        import ast

        tree = ast.parse(inspect.getsource(policy_module))
        imported: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
            elif isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
        assert not any(
            mod.endswith((".base", ".mock", ".registry", ".shuffle",
                          ".wazuh", ".thehive"))
            or "executor" in mod.lower()
            for mod in imported
        ), f"policy.py must not import executor surfaces: {imported}"
        source = inspect.getsource(policy_module)
        assert "ResponseExecutor" not in source

    def test_evaluate_signature_has_no_db_or_executor(self):
        params = inspect.signature(ExecutionPolicy.evaluate).parameters
        assert set(params) == {"self", "context", "now"}

    def test_context_is_immutable(self):
        ctx = PolicyContext(action="block_source_ip", risk_score=40)
        with pytest.raises(Exception):
            ctx.risk_score = 100  # type: ignore[misc]

    def test_threshold_map_is_frozen(self):
        policy = enabled_policy()
        with pytest.raises(TypeError):
            policy._min_risk["block_source_ip"] = 0  # type: ignore[index]

    def test_policy_cannot_mutate_approval_or_risk(self):
        """The Policy consumes plain values (str / int), never ORM
        objects — structurally it cannot modify EventRisk / Incident /
        Recommendation / Approval."""
        import typing

        hints = typing.get_type_hints(PolicyContext)
        assert hints["action"] is str
        assert hints["risk_score"] == (int | None)
        # The real lock: policy.py imports no ORM model (the docstring
        # may NAME EventRisk to explain provenance; imports may not).
        source = inspect.getsource(policy_module)
        assert "from app.models" not in source
        assert "import app.models" not in source
