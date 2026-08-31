"""Phase 3.2.1 — External Adapter Architecture regression.

This step builds ONLY the skeleton future external adapters plug into:
configuration surface, registry unlock (reserved -> recognized slots),
startup fail-closed validation, and the Single-Active-Adapter invariant.

ZERO real external HTTP anywhere in this file (or in 3.2.1 at all):
Shuffle / Wazuh / TheHive implementations land in 3.2.3 / 3.2.4 / 3.2.5.

Coverage map (user-frozen minimum bar):
 1. default adapter = mock                 9. wazuh requires its creds
 2. EXECUTION_ADAPTER=mock                 10. thehive requires its creds
 3. shuffle recognized                     11. single-active invariant
 4. wazuh recognized                       12. startup fail-closed (lifespan)
 5. thehive recognized                     13. secret never in config errors
 6. unknown adapter rejected               14. secret never in repr/str
 7. mock needs no external creds           15. Guard stays adapter-agnostic
 8. shuffle requires its creds             16. ATTACK: "shuffle,wazuh" -> hard error
"""
import inspect

import pytest
from fastapi.testclient import TestClient

from app import main as app_main
from app.core.config import Settings
from app.services.executions import (
    ADAPTER_NAMES,
    ADAPTER_REQUIRED_SETTINGS,
    KNOWN_ADAPTER_NAMES,
    RECOGNIZED_ADAPTER_NAMES,
    RESERVED_ADAPTER_NAMES,
    ExecutorConfigError,
    MockExecutor,
    create_executor,
    validate_adapter_config,
)

_SECRET = "s3cr3t-key-value-that-must-never-surface"

_FULL_CREDS = {
    "shuffle": {"SHUFFLE_BASE_URL": "http://stub", "SHUFFLE_API_KEY": _SECRET},
    "wazuh": {"WAZUH_BASE_URL": "http://stub", "WAZUH_API_KEY": _SECRET},
    "thehive": {"THEHIVE_BASE_URL": "http://stub", "THEHIVE_API_KEY": _SECRET},
}


def _settings(**overrides) -> Settings:
    return Settings(**overrides)


class TestSelection:
    """1/2. mock stays the default and always works with zero creds."""

    def test_default_adapter_is_mock(self):
        executor = create_executor(_settings())
        assert isinstance(executor, MockExecutor)
        assert executor.name == "mock"

    def test_explicit_mock_selection(self):
        validate_adapter_config(_settings(EXECUTION_ADAPTER="mock"))
        assert isinstance(create_executor(_settings(EXECUTION_ADAPTER="mock")), MockExecutor)

    def test_mock_requires_no_external_credentials(self):
        # 7. local development is never hostage to external creds: every
        # adapter credential empty and mock still validates + constructs.
        settings = _settings(
            EXECUTION_ADAPTER="mock",
            SHUFFLE_BASE_URL="",
            SHUFFLE_API_KEY="",
            WAZUH_BASE_URL="",
            WAZUH_API_KEY="",
            THEHIVE_BASE_URL="",
            THEHIVE_API_KEY="",
        )
        validate_adapter_config(settings)
        assert create_executor(settings).name == "mock"

    def test_unknown_adapter_is_a_selection_error(self):
        # 6. stable taxonomy: "Unknown ... selection error".
        with pytest.raises(ExecutorConfigError, match=r"Unknown EXECUTION_ADAPTER.*selection error"):
            validate_adapter_config(_settings(EXECUTION_ADAPTER="nmap"))

    def test_empty_adapter_is_a_selection_error(self):
        with pytest.raises(ExecutorConfigError, match="empty"):
            validate_adapter_config(_settings(EXECUTION_ADAPTER="   "))


class TestRecognizedSlots:
    """3/4/5. reserved -> recognized: known names, fail-closed, no fake."""

    def test_recognized_vocabulary(self):
        assert RECOGNIZED_ADAPTER_NAMES == ("shuffle", "wazuh", "thehive")
        # 3.1-era alias stays alive for frozen 3.1 imports/tests.
        assert RESERVED_ADAPTER_NAMES == RECOGNIZED_ADAPTER_NAMES
        # Only mock is IMPLEMENTED; the three slots stay recognized-only
        # until their 3.2.3+ code lands.
        assert ADAPTER_NAMES == ("mock",)
        assert KNOWN_ADAPTER_NAMES == ("mock", "shuffle", "wazuh", "thehive")

    @pytest.mark.parametrize("adapter", ["shuffle", "wazuh", "thehive"])
    def test_recognized_slot_with_full_creds_still_refuses_no_fake(self, adapter):
        # Recognized != implemented: even with COMPLETE credentials the
        # slot raises ConfigError until its 3.2.3+ code lands. Never a
        # silent mock fallback, never a fake external adapter.
        validate_adapter_config(_settings(EXECUTION_ADAPTER=adapter, **_FULL_CREDS[adapter]))
        with pytest.raises(ExecutorConfigError, match="recognized but not implemented"):
            create_executor(_settings(EXECUTION_ADAPTER=adapter, **_FULL_CREDS[adapter]))

    @pytest.mark.parametrize("adapter", ["shuffle", "wazuh", "thehive"])
    def test_recognized_slot_never_falls_back_to_mock(self, adapter):
        # The error is the ONLY outcome — asserting via raises, a mock
        # return would fail this test by never raising.
        with pytest.raises(ExecutorConfigError):
            create_executor(_settings(EXECUTION_ADAPTER=adapter))


class TestCredentialValidation:
    """8/9/10. each real adapter validates ONLY its own flat pair."""

    @pytest.mark.parametrize("adapter", ["shuffle", "wazuh", "thehive"])
    def test_adapter_requires_its_full_pair(self, adapter):
        with pytest.raises(ExecutorConfigError, match="missing required configuration"):
            validate_adapter_config(_settings(EXECUTION_ADAPTER=adapter))

    @pytest.mark.parametrize("adapter", ["shuffle", "wazuh", "thehive"])
    def test_partial_pair_names_exactly_the_missing_key(self, adapter):
        # Filling ONLY the BASE_URL must name exactly the missing API key
        # and nothing else (key names are reportable, values never).
        base_url_key, api_key_key = ADAPTER_REQUIRED_SETTINGS[adapter]
        with pytest.raises(ExecutorConfigError) as excinfo:
            validate_adapter_config(
                _settings(EXECUTION_ADAPTER=adapter, **{base_url_key: "http://stub"})
            )
        message = str(excinfo.value)
        assert api_key_key in message
        assert base_url_key not in message

    def test_adapter_never_validates_another_adapters_creds(self):
        # wazuh selected, ONLY the wazuh pair missing — even though every
        # shuffle/thehive credential is perfectly filled.
        with pytest.raises(ExecutorConfigError) as excinfo:
            validate_adapter_config(
                _settings(
                    EXECUTION_ADAPTER="wazuh",
                    SHUFFLE_BASE_URL="http://stub",
                    SHUFFLE_API_KEY="filled",
                    THEHIVE_BASE_URL="http://stub",
                    THEHIVE_API_KEY="filled",
                )
            )
        message = str(excinfo.value)
        assert "WAZUH_BASE_URL" in message
        assert "WAZUH_API_KEY" in message
        assert "SHUFFLE_" not in message and "THEHIVE_" not in message


class TestSingleActiveAdapter:
    """11/16. one deployment, one adapter — fan-out is a config error."""

    @pytest.mark.parametrize(
        "multi_value",
        ["shuffle,wazuh", "shuffle,wazuh,thehive", "shuffle+wazuh",
         "shuffle|wazuh", "shuffle;wazuh", "shuffle wazuh"],
    )
    def test_multi_value_selection_is_rejected_never_split(self, multi_value):
        with pytest.raises(ExecutorConfigError, match="exactly ONE adapter"):
            validate_adapter_config(_settings(EXECUTION_ADAPTER=multi_value))
        with pytest.raises(ExecutorConfigError):
            create_executor(_settings(EXECUTION_ADAPTER=multi_value))

    def test_attack_shuffle_comma_wazuh_does_not_autopick(self):
        # The exact attack vector from the 3.2.1 brief: no auto-split,
        # no first-value pick, no implicit mock — a hard ConfigError and
        # nothing else.
        with pytest.raises(ExecutorConfigError) as excinfo:
            create_executor(_settings(EXECUTION_ADAPTER="shuffle,wazuh"))
        assert "Single-Active-Adapter" in str(excinfo.value)


class TestStartupFailClosed:
    """12. the app refuses to BOOT on a broken adapter configuration."""

    def test_missing_credential_refuses_to_boot(self, monkeypatch):
        monkeypatch.setattr(
            app_main, "settings", _settings(EXECUTION_ADAPTER="shuffle")
        )
        with pytest.raises(ExecutorConfigError, match="missing required configuration"):
            with TestClient(app_main.app):
                pass  # pragma: no cover — startup must never succeed here

    def test_unknown_adapter_refuses_to_boot(self, monkeypatch):
        monkeypatch.setattr(
            app_main, "settings", _settings(EXECUTION_ADAPTER="metasploit")
        )
        with pytest.raises(ExecutorConfigError, match="Unknown EXECUTION_ADAPTER"):
            with TestClient(app_main.app):
                pass  # pragma: no cover — startup must never succeed here

    def test_multi_value_refuses_to_boot(self, monkeypatch):
        monkeypatch.setattr(
            app_main, "settings", _settings(EXECUTION_ADAPTER="shuffle,wazuh")
        )
        with pytest.raises(ExecutorConfigError, match="exactly ONE adapter"):
            with TestClient(app_main.app):
                pass  # pragma: no cover — startup must never succeed here

    def test_mock_boots_without_any_external_credential(self, monkeypatch):
        # Entering the client context runs the lifespan: validate_adapter_
        # config must pass for mock with ZERO external credentials. No
        # request is issued (health would touch the real DB dependency).
        monkeypatch.setattr(app_main, "settings", _settings(EXECUTION_ADAPTER="mock"))
        with TestClient(app_main.app):
            pass  # lifespan started and shut down without raising


class TestSecretDiscipline:
    """13/14. credential VALUES never surface — names of keys may."""

    def test_secret_never_appears_in_configuration_errors(self):
        # 13. missing BASE_URL while the API KEY holds a real value: the
        # error names the MISSING KEY and never echoes the secret value.
        with pytest.raises(ExecutorConfigError) as excinfo:
            validate_adapter_config(
                _settings(EXECUTION_ADAPTER="shuffle", SHUFFLE_API_KEY=_SECRET)
            )
        message = str(excinfo.value)
        assert _SECRET not in message
        assert "SHUFFLE_BASE_URL" in message

    def test_secret_never_appears_in_selection_or_slot_errors(self):
        with pytest.raises(ExecutorConfigError) as unknown_err:
            create_executor(_settings(EXECUTION_ADAPTER="nmap", SHUFFLE_API_KEY=_SECRET))
        assert _SECRET not in str(unknown_err.value)
        with pytest.raises(ExecutorConfigError) as slot_err:
            create_executor(
                _settings(EXECUTION_ADAPTER="thehive", **_FULL_CREDS["thehive"])
            )
        assert _SECRET not in str(slot_err.value)

    def test_secret_never_appears_in_settings_repr_or_str(self):
        # 14. the default pydantic repr prints every value — ours masks.
        settings = _settings(
            EXECUTION_ADAPTER="shuffle",
            SHUFFLE_API_KEY=_SECRET,
            WAZUH_API_KEY=_SECRET,
            THEHIVE_API_KEY=_SECRET,
            EXECUTION_TOKEN=_SECRET,
        )
        for surface in (repr(settings), str(settings)):
            assert _SECRET not in surface
            assert "***" in surface
            # key NAMES stay visible for config debugging
            assert "SHUFFLE_API_KEY" in surface

    def test_database_url_value_is_masked_too(self):
        settings = _settings()
        assert "change_me" not in repr(settings)


class TestGuardStaysAdapterAgnostic:
    """15. the Guard knows ExecutorCapability ONLY — never the registry,
    never a concrete adapter. Static source audit (frozen 3.1.4 layering)."""

    def test_guard_source_never_references_registry_or_adapters(self):
        from app.services.executions import guard

        source = inspect.getsource(guard)
        for forbidden in ("create_executor", "registry", "MockExecutor",
                          "ShuffleExecutor", "WazuhExecutor", "TheHiveExecutor"):
            assert forbidden not in source, (
                f"Guard must stay adapter-agnostic but references '{forbidden}'"
            )

    def test_capability_protocol_surface_unchanged(self):
        from app.services.executions.guard import ExecutorCapability

        methods = {
            name
            for name, member in vars(ExecutorCapability).items()
            if not name.startswith("_") and callable(member)
        }
        assert methods == {"supports", "supports_compensation"}
