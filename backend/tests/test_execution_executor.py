"""Phase 3.1.5: ResponseExecutor contract + Mock/DryRun + registry tests.

Hard requirements this suite nails down (acceptance gate 1–14):
 1. mock name is always "mock"
 2. the three executable actions are supported
 3. non-executable vocabulary words are NOT supported
 4. compensation capability mirrors the executable vocabulary
 5. deterministic output — same dispatch, byte-identical outcome
 6/7. ExecutionOutcome succeeded / failed paths
 8. bad adapter result -> platform judges protocol_violation (D9)
 9. fail_with injects the three ADAPTER classifications only
10. compensate is deterministic too
11. registry default is mock
12. reserved/unknown adapters raise ConfigError — never fake support
13. dispatch/outcome DTOs are not client-forgeable (extra=forbid)
14. zero network surface in the mock module

Plus the layering promise: Guard -> ExecutorCapability protocol only;
MockExecutor satisfies it structurally; guard.py imports no concrete
executor module.

All tests are DB-free.
"""
import uuid

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.services.ai.models import RESPONSE_ACTIONS
from app.services.executions.base import ResponseExecutor
from app.services.executions.exceptions import (
    ExecutorConfigError,
    ExecutorError,
    ExecutorOutcomeViolation,
)
from app.services.executions.guard import (
    EXECUTABLE_ACTIONS,
    ExecutorCapability,
    GuardRejection,
    check_executor_capability,
)
from app.services.executions.mock import FAIL_WITH_CHOICES, MockExecutor
from app.services.executions.models import (
    ADAPTER_CLASSIFICATIONS,
    OUTCOME_STATUSES,
    ExecutionDispatch,
    ExecutionOutcome,
)
from app.services.executions.protocol import parse_execution_outcome
from app.services.executions.registry import (
    ADAPTER_NAMES,
    RESERVED_ADAPTER_NAMES,
    create_executor,
)

NON_EXECUTABLE_ACTIONS = sorted(RESPONSE_ACTIONS - EXECUTABLE_ACTIONS)


def make_dispatch(**overrides) -> ExecutionDispatch:
    payload = {
        "execution_id": uuid.UUID("11111111-1111-1111-1111-111111111111"),
        "action": "block_source_ip",
        "target": "203.0.113.9",
        "approval_id": uuid.UUID("22222222-2222-2222-2222-222222222222"),
    }
    payload.update(overrides)
    return ExecutionDispatch(**payload)


class TestMockIdentityAndCapability:
    """Gate 1–4: name, supports, supports_compensation."""

    def test_name_is_always_mock(self):
        assert MockExecutor().name == "mock"
        assert MockExecutor(fail_with="timeout").name == "mock"

    @pytest.mark.parametrize("action", sorted(EXECUTABLE_ACTIONS))
    def test_supports_executable_actions(self, action):
        assert MockExecutor().supports(action) is True

    @pytest.mark.parametrize("action", NON_EXECUTABLE_ACTIONS)
    def test_does_not_support_non_executable_actions(self, action):
        assert MockExecutor().supports(action) is False

    def test_does_not_support_unknown_action(self):
        assert MockExecutor().supports("rm_rf_everything") is False

    @pytest.mark.parametrize("action", sorted(EXECUTABLE_ACTIONS))
    def test_supports_compensation_for_executable_actions(self, action):
        assert MockExecutor().supports_compensation(action) is True

    @pytest.mark.parametrize("action", NON_EXECUTABLE_ACTIONS + ["garbage"])
    def test_no_compensation_for_non_executable_actions(self, action):
        assert MockExecutor().supports_compensation(action) is False


class TestMockDeterminismAndDryRun:
    """Gate 5, 6, 10: deterministic outcomes + DryRun echo."""

    def test_execute_succeeded_outcome(self):
        outcome = MockExecutor().execute(make_dispatch())
        assert outcome.status == "succeeded"
        assert outcome.status in OUTCOME_STATUSES

    def test_execute_dry_run_echo_records_action_target_params(self):
        dispatch = make_dispatch(action="isolate_host", target="WS-042")
        echo = MockExecutor().execute(dispatch).detail["dry_run"]
        assert echo == {
            "executor": "mock",
            "operation": "execute",
            "action": "isolate_host",
            "target": "WS-042",
            "execution_id": str(dispatch.execution_id),
            "approval_id": str(dispatch.approval_id),
        }

    def test_execute_is_deterministic(self):
        dispatch = make_dispatch()
        first = MockExecutor().execute(dispatch)
        second = MockExecutor().execute(dispatch)
        assert first.model_dump() == second.model_dump()

    def test_compensate_succeeded_outcome(self):
        outcome = MockExecutor().compensate(make_dispatch())
        assert outcome.status == "succeeded"
        assert outcome.detail["dry_run"]["operation"] == "compensate"

    def test_compensate_is_deterministic(self):
        dispatch = make_dispatch(action="disable_account", target="user@corp")
        first = MockExecutor().compensate(dispatch)
        second = MockExecutor().compensate(dispatch)
        assert first.model_dump() == second.model_dump()

    def test_execute_rejects_unsupported_action(self):
        with pytest.raises(ValueError, match="does not support"):
            MockExecutor().execute(make_dispatch(action="monitor_only"))

    def test_compensate_rejects_unsupported_action(self):
        with pytest.raises(ValueError, match="cannot compensate"):
            MockExecutor().compensate(make_dispatch(action="monitor_only"))


class TestFailureInjection:
    """Gate 7, 9: fail_with injects the three ADAPTER classifications."""

    @pytest.mark.parametrize("classification", sorted(ADAPTER_CLASSIFICATIONS))
    def test_fail_with_injects_failed_outcome(self, classification):
        outcome = MockExecutor(fail_with=classification).execute(make_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == classification
        assert outcome.raw_response is None

    @pytest.mark.parametrize("classification", sorted(ADAPTER_CLASSIFICATIONS))
    def test_fail_with_applies_to_compensate(self, classification):
        outcome = MockExecutor(fail_with=classification).compensate(make_dispatch())
        assert outcome.status == "failed"
        assert outcome.detail["classification"] == classification

    def test_fail_with_choices_exclude_protocol_violation(self):
        # D9: protocol_violation is platform-judged only — an adapter can
        # never be configured to emit it.
        assert FAIL_WITH_CHOICES == ADAPTER_CLASSIFICATIONS
        assert "protocol_violation" not in FAIL_WITH_CHOICES

    def test_fail_with_protocol_violation_is_not_injectable(self):
        with pytest.raises(ValueError, match="platform-judged"):
            MockExecutor(fail_with="protocol_violation")

    def test_fail_with_unknown_classification_rejected(self):
        with pytest.raises(ValueError, match="fail_with"):
            MockExecutor(fail_with="made_up_failure")


class TestPlatformOutcomeParse:
    """Gate 8: bad adapter result -> protocol_violation (D9)."""

    def test_valid_mapping_parses(self):
        outcome = parse_execution_outcome({"status": "succeeded"})
        assert outcome.status == "succeeded"

    def test_valid_outcome_instance_passes_through(self):
        original = ExecutionOutcome(status="failed", detail={"classification": "timeout"})
        assert parse_execution_outcome(original) is original

    def test_dispatched_status_is_rejected(self):
        # D8: no adapter may answer `dispatched` — that word belongs to
        # the platform log.
        with pytest.raises(ExecutorOutcomeViolation):
            parse_execution_outcome({"status": "dispatched"})

    def test_extra_fields_are_rejected(self):
        with pytest.raises(ExecutorOutcomeViolation):
            parse_execution_outcome({"status": "succeeded", "smuggled": True})

    def test_missing_status_is_rejected(self):
        with pytest.raises(ExecutorOutcomeViolation):
            parse_execution_outcome({"detail": {}})

    def test_non_mapping_result_is_rejected(self):
        for bad in (None, "succeeded", 42, ["succeeded"]):
            with pytest.raises(ExecutorOutcomeViolation):
                parse_execution_outcome(bad)

    def test_self_declared_protocol_violation_is_rejected(self):
        # D9: the word is reserved to the platform parse.
        with pytest.raises(ExecutorOutcomeViolation, match="self-declared"):
            parse_execution_outcome(
                {"status": "failed", "detail": {"classification": "protocol_violation"}}
            )

    def test_self_declared_violation_on_outcome_instance_is_rejected(self):
        forged = ExecutionOutcome(
            status="failed", detail={"classification": "protocol_violation"}
        )
        with pytest.raises(ExecutorOutcomeViolation, match="self-declared"):
            parse_execution_outcome(forged)

    def test_unknown_classification_is_rejected(self):
        with pytest.raises(ExecutorOutcomeViolation, match="unknown failure"):
            parse_execution_outcome(
                {"status": "failed", "detail": {"classification": "nope"}}
            )

    def test_violation_carries_protocol_violation_classification(self):
        with pytest.raises(ExecutorOutcomeViolation) as exc_info:
            parse_execution_outcome({"status": "dispatched"})
        assert exc_info.value.classification == "protocol_violation"


class TestDispatchAndOutcomeFreeze:
    """Gate 13: DTOs are server-side facts, not client-forgeable."""

    def test_dispatch_forbids_extra_fields(self):
        with pytest.raises(ValidationError):
            ExecutionDispatch(
                execution_id=uuid.uuid4(),
                action="block_source_ip",
                target="10.0.0.1",
                approval_id=uuid.uuid4(),
                client_smuggled="evil",
            )

    def test_dispatch_requires_all_fields(self):
        with pytest.raises(ValidationError):
            ExecutionDispatch(action="block_source_ip", target="10.0.0.1")

    def test_outcome_forbids_extra_fields(self):
        with pytest.raises(ValidationError):
            ExecutionOutcome(status="succeeded", fake_field=1)

    def test_outcome_status_is_limited_to_adapter_vocabulary(self):
        assert OUTCOME_STATUSES == frozenset({"succeeded", "failed"})
        with pytest.raises(ValidationError):
            ExecutionOutcome(status="dispatched")


class TestNoNetworkSurface:
    """Gate 14: the mock is an offline DryRun — no network machinery."""

    def test_mock_module_imports_no_network_libraries(self):
        import inspect

        import app.services.executions.mock as mock_module

        source = inspect.getsource(mock_module)
        for banned in ("import socket", "import urllib", "import requests",
                       "import httpx", "import aiohttp", "from urllib",
                       "from requests", "from httpx", "from aiohttp"):
            assert banned not in source

    def test_mock_does_not_open_sockets_at_runtime(self):
        # Deterministic + zero side-effects: calling execute/compensate
        # never leaves the process (no sockets created). We assert the
        # adapter performs no attribute-level IO by running it with the
        # socket module's connect poisoned for the duration of the call.
        import socket

        real_connect = socket.socket.connect
        attempts = []

        def poisoned_connect(self, *args, **kwargs):
            attempts.append(args)
            raise AssertionError("mock executor attempted a network connect")

        socket.socket.connect = poisoned_connect
        try:
            MockExecutor().execute(make_dispatch())
            MockExecutor().compensate(make_dispatch())
        finally:
            socket.socket.connect = real_connect
        assert attempts == []


class TestRegistry:
    """Gate 11, 12: create_executor(settings)."""

    def test_default_adapter_is_mock(self):
        executor = create_executor(Settings())
        assert isinstance(executor, MockExecutor)
        assert executor.name == "mock"

    def test_explicit_mock_setting(self):
        executor = create_executor(Settings(EXECUTION_ADAPTER="mock"))
        assert isinstance(executor, MockExecutor)

    def test_adapter_name_is_case_and_whitespace_insensitive(self):
        executor = create_executor(Settings(EXECUTION_ADAPTER="  Mock "))
        assert executor.name == "mock"

    @pytest.mark.parametrize("reserved", list(RESERVED_ADAPTER_NAMES))
    def test_reserved_adapters_raise_config_error(self, reserved):
        # 3.2.1: reserved -> recognized architecture slots; selecting one
        # before its 3.2.3+ implementation raises ConfigError (missing
        # credentials with empty config, "recognized but not implemented"
        # once the pair is filled — see the 3.2.1 architecture suite).
        with pytest.raises(
            ExecutorConfigError,
            match=r"missing required configuration|recognized but not implemented",
        ):
            create_executor(Settings(EXECUTION_ADAPTER=reserved))

    def test_unknown_adapter_raises_config_error(self):
        with pytest.raises(ExecutorConfigError, match="Unknown"):
            create_executor(Settings(EXECUTION_ADAPTER="nmap"))

    def test_config_error_is_executor_error(self):
        assert issubclass(ExecutorConfigError, ExecutorError)

    def test_registry_vocabulary_freeze(self):
        # 3.2.1 evolution: shuffle / wazuh / thehive moved from RESERVED
        # to RECOGNIZED slots; only mock is implemented.
        assert ADAPTER_NAMES == ("mock",)
        assert RESERVED_ADAPTER_NAMES == ("shuffle", "wazuh", "thehive")

    def test_settings_default_is_mock(self):
        assert Settings().EXECUTION_ADAPTER == "mock"


class TestLayeringContract:
    """The 3.1.5 boundary: Guard -> ExecutorCapability protocol;
    MockExecutor -> protocol. Guard never imports a concrete executor."""

    def test_mock_structurally_satisfies_executor_capability(self):
        executor = MockExecutor()
        protocol_members = ("supports", "supports_compensation")
        for member in protocol_members:
            assert callable(getattr(executor, member))
        # The protocol's surface is usable directly through the Guard:
        check_executor_capability(executor, "block_source_ip", "execute")
        check_executor_capability(executor, "block_source_ip", "compensate")

    def test_guard_rejects_mock_capability_miss_as_business_rejection(self):
        with pytest.raises(GuardRejection):
            check_executor_capability(MockExecutor(), "monitor_only", "execute")

    def test_guard_module_does_not_import_concrete_executors(self):
        # Layering check on REAL imports (AST level): prose mentions of
        # ResponseExecutor in docstrings are fine — the dependency arrow
        # must not exist.
        import ast
        import inspect

        import app.services.executions.guard as guard_module

        tree = ast.parse(inspect.getsource(guard_module))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                imported.update(
                    f"{node.module}.{alias.name}" for alias in node.names
                )
            elif isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
        for banned in (
            "app.services.executions.mock",
            "app.services.executions.base",
            "app.services.executions.registry",
        ):
            assert not any(
                name.startswith(banned) for name in imported
            ), f"guard.py must not import concrete executor layer: {banned}"

    def test_mock_is_a_response_executor(self):
        assert issubclass(MockExecutor, ResponseExecutor)

    def test_capability_annotation_is_the_protocol_not_a_concrete_class(self):
        import typing

        import app.services.executions.guard as guard_module

        hints = typing.get_type_hints(check_executor_capability, guard_module.__dict__)
        assert hints["executor"] is ExecutorCapability
