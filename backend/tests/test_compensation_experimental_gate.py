"""Real-adapter compensation is experimental and fail-closed at boot.

The reverse (compensation) dispatch writes no durable pre-dispatch reservation
(unlike the forward path, which reserves before it dispatches), so configuring
a Shuffle reverse workflow without the explicit
``EXECUTION_COMPENSATION_EXPERIMENTAL`` acknowledgment is rejected by
``validate_adapter_config()`` — the same check the app lifespan
(``main._lifespan``) calls, so a mis-set lab config never boots into an
unprotected external reverse call.

The offline mock is exempt (DryRun, no external call) — demo compensation never
needs the flag. No real external HTTP is involved: this exercises only the
startup configuration check. Every assertion is hermetic against an ambient
``.env``: ``_settings`` seeds both reverse ids empty and the experimental flag
off, then applies each test's overrides (later keys win in the dict merge), so a
test can set exactly one reverse id while the other stays empty — with no
duplicate keyword clash.
"""
import pytest

from app.core.config import Settings
from app.services.executions import ExecutorConfigError, validate_adapter_config

_SECRET = "s3cr3t-key-value-that-must-never-surface"
_SHUFFLE_CREDS = {"SHUFFLE_BASE_URL": "http://stub", "SHUFFLE_API_KEY": _SECRET}
# The complete reverse-workflow slot set (see shuffle.SHUFFLE_REVERSE_WORKFLOW_SETTINGS)
# plus the acknowledgment flag, seeded to their safe/empty defaults.
_BASE = {
    "SHUFFLE_WORKFLOW_REVERSE_BLOCK_SOURCE_IP": "",
    "SHUFFLE_WORKFLOW_REVERSE_ISOLATE_HOST": "",
    "EXECUTION_COMPENSATION_EXPERIMENTAL": False,
}


def _settings(**overrides) -> Settings:
    return Settings(**{**_BASE, **overrides})


class TestCompensationExperimentalGate:
    """A configured reverse workflow requires the experimental acknowledgment."""

    def test_reverse_block_workflow_without_acknowledgment_refuses(self):
        with pytest.raises(ExecutorConfigError, match="EXPERIMENTAL"):
            validate_adapter_config(
                _settings(
                    EXECUTION_ADAPTER="shuffle",
                    **_SHUFFLE_CREDS,
                    SHUFFLE_WORKFLOW_REVERSE_BLOCK_SOURCE_IP="wf-reverse-block",
                )
            )

    def test_reverse_isolate_workflow_without_acknowledgment_refuses(self):
        with pytest.raises(ExecutorConfigError, match="C-1"):
            validate_adapter_config(
                _settings(
                    EXECUTION_ADAPTER="shuffle",
                    **_SHUFFLE_CREDS,
                    SHUFFLE_WORKFLOW_REVERSE_ISOLATE_HOST="wf-reverse-isolate",
                )
            )

    def test_experimental_acknowledgment_allows_lab_use(self):
        # Opting in (lab only) lets the identical configuration pass validation.
        validate_adapter_config(
            _settings(
                EXECUTION_ADAPTER="shuffle",
                EXECUTION_COMPENSATION_EXPERIMENTAL=True,
                **_SHUFFLE_CREDS,
                SHUFFLE_WORKFLOW_REVERSE_BLOCK_SOURCE_IP="wf-reverse-block",
            )
        )

    def test_forward_only_shuffle_needs_no_acknowledgment(self):
        # No reverse ids => no compensation => validation does not fire; forward
        # dispatch is unaffected by this flag.
        validate_adapter_config(
            _settings(EXECUTION_ADAPTER="shuffle", **_SHUFFLE_CREDS)
        )

    def test_mock_demo_unaffected_with_and_without_flag(self):
        # Demo (mock) compensates via DryRun and skips this validation, whether
        # or not the experimental flag is set.
        validate_adapter_config(_settings(EXECUTION_ADAPTER="mock"))
        validate_adapter_config(
            _settings(EXECUTION_ADAPTER="mock", EXECUTION_COMPENSATION_EXPERIMENTAL=True)
        )

    def test_gate_error_never_echoes_the_secret(self):
        with pytest.raises(ExecutorConfigError) as excinfo:
            validate_adapter_config(
                _settings(
                    EXECUTION_ADAPTER="shuffle",
                    **_SHUFFLE_CREDS,
                    SHUFFLE_WORKFLOW_REVERSE_BLOCK_SOURCE_IP="wf-reverse-block",
                )
            )
        message = str(excinfo.value)
        assert _SECRET not in message
        # names the knob to change, never a credential value
        assert "EXECUTION_COMPENSATION_EXPERIMENTAL" in message
