"""The production startup gate is fail-closed.

Every unsafe production setting refuses to boot, with one sanitized error that
names keys only (never values); demo mode keeps the simple UX and accepts the
same settings unchanged. ``_settings`` builds each configuration explicitly, as
``test_compensation_experimental_gate`` does, so no ambient .env leaks in.
"""
import pytest

from app.core.config import Settings
from app.core.runtime_mode import (
    ProductionModeError,
    deployment_mode,
    is_production,
    validate_production_mode,
)

_SAFE_OPERATORS = (
    '[{"token": "tok-r-01", "name": "rev-1", "role": "reviewer"}, '
    '{"token": "tok-e-01", "name": "exe-1", "role": "executor"}]'
)
_REVIEWER_ONLY = '[{"token": "tok-r-01", "name": "rev-1", "role": "reviewer"}]'
_EXECUTOR_ONLY = '[{"token": "tok-e-01", "name": "exe-1", "role": "executor"}]'

# A fully production-safe configuration.
_SAFE = {
    "DEPLOYMENT_MODE": "production",
    "OPERATORS_JSON": _SAFE_OPERATORS,
    "DATABASE_URL": "postgresql+psycopg://user:pw@db.internal:5432/sentinelflow",
    "EXECUTION_ADAPTER": "wazuh",
    "BIND_HOST": "127.0.0.1",
    "SHUFFLE_WORKFLOW_REVERSE_BLOCK_SOURCE_IP": "",
    "SHUFFLE_WORKFLOW_REVERSE_ISOLATE_HOST": "",
    "EXECUTION_COMPENSATION_EXPERIMENTAL": False,
}


def _settings(**overrides) -> Settings:
    return Settings(**{**_SAFE, **overrides})


class TestModeParsing:
    def test_modes_are_case_insensitive_and_normalized(self):
        assert deployment_mode(_settings(DEPLOYMENT_MODE=" Production ")) == "production"
        assert deployment_mode(_settings(DEPLOYMENT_MODE="DEMO")) == "demo"
        assert is_production(_settings(DEPLOYMENT_MODE="PRODUCTION")) is True
        assert is_production(_settings(DEPLOYMENT_MODE="demo")) is False

    def test_unknown_mode_is_a_config_error(self):
        with pytest.raises(ProductionModeError, match="DEPLOYMENT_MODE"):
            deployment_mode(_settings(DEPLOYMENT_MODE="staging"))


class TestDemoNeverGated:
    def test_demo_accepts_every_unsafe_default(self):
        """The demo UX is unchanged: no production prohibition applies."""
        validate_production_mode(
            _settings(
                DEPLOYMENT_MODE="demo",
                OPERATORS_JSON="",
                DATABASE_URL="sqlite+pysqlite:///demo.db",
                EXECUTION_ADAPTER="mock",
                BIND_HOST="0.0.0.0",
                EXECUTION_COMPENSATION_EXPERIMENTAL=True,
                SHUFFLE_WORKFLOW_REVERSE_BLOCK_SOURCE_IP="wf-reverse-demo",
            )
        )  # no raise


class TestProductionGate:
    def test_safe_configuration_passes(self):
        validate_production_mode(_settings())  # no raise

    def test_missing_operators_refuses(self):
        with pytest.raises(ProductionModeError, match="OPERATORS_JSON"):
            validate_production_mode(_settings(OPERATORS_JSON=""))

    def test_sqlite_refuses(self):
        with pytest.raises(ProductionModeError, match="DATABASE_URL"):
            validate_production_mode(
                _settings(DATABASE_URL="sqlite+pysqlite:///prod.db")
            )

    def test_mock_adapter_refuses(self):
        with pytest.raises(ProductionModeError, match="EXECUTION_ADAPTER"):
            validate_production_mode(_settings(EXECUTION_ADAPTER="mock"))

    def test_compensation_experimental_flag_refuses(self):
        with pytest.raises(ProductionModeError, match="compensation"):
            validate_production_mode(
                _settings(EXECUTION_COMPENSATION_EXPERIMENTAL=True)
            )

    def test_reverse_workflow_configuration_refuses(self):
        with pytest.raises(ProductionModeError, match="SHUFFLE_WORKFLOW_REVERSE"):
            validate_production_mode(
                _settings(SHUFFLE_WORKFLOW_REVERSE_BLOCK_SOURCE_IP="wf-reverse-1")
            )

    def test_non_loopback_bind_refuses(self):
        with pytest.raises(ProductionModeError, match="BIND_HOST"):
            validate_production_mode(_settings(BIND_HOST="0.0.0.0"))

    def test_operator_set_without_approver_refuses(self):
        with pytest.raises(ProductionModeError, match="approval permission"):
            validate_production_mode(_settings(OPERATORS_JSON=_EXECUTOR_ONLY))

    def test_operator_set_without_executor_refuses(self):
        with pytest.raises(ProductionModeError, match="execution permission"):
            validate_production_mode(_settings(OPERATORS_JSON=_REVIEWER_ONLY))

    def test_invalid_operators_json_refuses_without_echoing_values(self):
        secret_token = "s3cr3t-operator-token-value"
        with pytest.raises(ProductionModeError) as excinfo:
            validate_production_mode(
                _settings(
                    OPERATORS_JSON=(
                        '[{"token": "' + secret_token + '", '
                        '"name": "x", "role": "wizard"}]'
                    )
                )
            )
        assert secret_token not in str(excinfo.value)  # values never echoed

    def test_all_problems_are_collected_in_one_error(self):
        with pytest.raises(ProductionModeError) as excinfo:
            validate_production_mode(
                _settings(
                    OPERATORS_JSON="",
                    DATABASE_URL="sqlite+pysqlite:///prod.db",
                    EXECUTION_ADAPTER="mock",
                    BIND_HOST="0.0.0.0",
                )
            )
        message = str(excinfo.value)
        for key in ("OPERATORS_JSON", "DATABASE_URL", "EXECUTION_ADAPTER", "BIND_HOST"):
            assert key in message
