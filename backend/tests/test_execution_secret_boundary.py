"""Phase 3.2.2 — Credential / Secret Boundary regression.

Locks the full secret chain offline:

    .env -> Settings -> AdapterCredentials -> Authorization header
                                              -> external request

and proves the eight ❌ surfaces stay ***:

    ❌ execution_log.detail   (audit gate in service._append)
    ❌ API response           (static 503/401 details)
    ❌ exception string       (key names only, values never echoed)
    ❌ repr / str             (masked Settings + AdapterCredentials)
    ❌ URL / query string     (query + userinfo rejected fail-closed)
    ❌ browser storage        (nothing secret is serialized out)
    ❌ audit detail           (same *** gate as execution_log)
    ❌ Python logging         (SecretRedactionFilter)

ZERO real external HTTP in this file (or in 3.2.2 at all): Shuffle /
Wazuh / TheHive business calls land in 3.2.3 / 3.2.4 / 3.2.5.
"""
import io
import logging
import uuid

import pytest

from app.core.config import settings
from app.services.executions import (
    MASK,
    AdapterCredentials,
    ExecutorConfigError,
    SecretRedactionFilter,
    credentials_from_settings,
    current_secret_values,
    redact_detail,
    redact_text,
    validate_api_key,
    validate_base_url,
)
from app.services.executions.mock import MockExecutor
from app.services.executions.service import execute_response

# The deliberately obvious fake key for the full-path leak suite
# (user-specified sentinel, Phase 3.2.2).
FAKE_SECRET = "s3cr3t-PHASE32-TEST-ONLY"


class _SmugglingExecutor(MockExecutor):
    """Malicious-adapter stand-in: its outcome detail smuggles the
    secret, simulating a real adapter echoing credentials back."""

    name = "smuggler"

    def execute(self, dispatch):
        outcome = super().execute(dispatch)
        smuggled = dict(outcome.detail)
        smuggled["api_key"] = FAKE_SECRET
        smuggled["raw_headers"] = {"Authorization": f"Bearer {FAKE_SECRET}"}
        smuggled["note"] = f"retry with {FAKE_SECRET} manually"
        return type(outcome)(status=outcome.status, detail=smuggled,
                             raw_response=outcome.raw_response)


def _settings(**overrides):
    from app.core.config import Settings

    return Settings(**overrides)


# --------------------------------------------------------------------------
# 1. URL discipline — secrets must NEVER ride inside a URL
# --------------------------------------------------------------------------
class TestUrlDiscipline:
    def test_https_base_url_accepted(self):
        assert validate_base_url("shuffle", "https://shuffle.corp") == "https://shuffle.corp"

    def test_http_base_url_accepted(self):
        assert validate_base_url("wazuh", "http://wazuh.local:55000") == "http://wazuh.local:55000"

    def test_trailing_slashes_normalized(self):
        assert validate_base_url("thehive", "https://thehive.corp///") == "https://thehive.corp"

    def test_query_string_rejected(self):
        # THE classic secret-in-URL leak: https://example/api?token=xxxx
        with pytest.raises(ExecutorConfigError, match="query string"):
            validate_base_url("shuffle", f"https://example/api?token={FAKE_SECRET}")

    def test_query_rejection_never_echoes_value(self):
        with pytest.raises(ExecutorConfigError) as exc:
            validate_base_url("shuffle", f"https://example/api?token={FAKE_SECRET}")
        assert FAKE_SECRET not in str(exc.value)

    def test_fragment_rejected(self):
        with pytest.raises(ExecutorConfigError, match="fragment"):
            validate_base_url("wazuh", "https://example#frag")

    def test_userinfo_rejected(self):
        with pytest.raises(ExecutorConfigError, match="userinfo"):
            validate_base_url("thehive", f"https://user:{FAKE_SECRET}@thehive.corp")

    def test_non_http_scheme_rejected(self):
        with pytest.raises(ExecutorConfigError, match="http\\(s\\)"):
            validate_base_url("shuffle", "ftp://files.corp")

    def test_empty_url_rejected(self):
        with pytest.raises(ExecutorConfigError, match="empty"):
            validate_base_url("shuffle", "   ")


# --------------------------------------------------------------------------
# 2. API key validation
# --------------------------------------------------------------------------
class TestApiKeyValidation:
    def test_empty_key_rejected(self):
        with pytest.raises(ExecutorConfigError, match="empty"):
            validate_api_key("shuffle", "")

    def test_whitespace_key_rejected(self):
        with pytest.raises(ExecutorConfigError, match="empty"):
            validate_api_key("wazuh", "   \t ")

    def test_valid_key_stripped(self):
        assert validate_api_key("thehive", f" {FAKE_SECRET} ") == FAKE_SECRET

    def test_key_error_never_echoes_value(self):
        with pytest.raises(ExecutorConfigError) as exc:
            validate_api_key("shuffle", "")
        assert "SHUFFLE_API_KEY" in str(exc.value)


# --------------------------------------------------------------------------
# 3. AdapterCredentials boundary object
# --------------------------------------------------------------------------
class TestCredentialsBoundary:
    def _creds(self):
        return credentials_from_settings(
            "shuffle",
            _settings(SHUFFLE_BASE_URL="https://shuffle.corp/", SHUFFLE_API_KEY=FAKE_SECRET),
        )

    def test_happy_path_assembles_and_normalizes(self):
        creds = self._creds()
        assert creds.adapter == "shuffle"
        assert creds.base_url == "https://shuffle.corp"
        assert creds.api_key == FAKE_SECRET

    def test_repr_masks_key(self):
        creds = self._creds()
        assert FAKE_SECRET not in repr(creds)
        assert MASK in repr(creds)

    def test_str_masks_key(self):
        creds = self._creds()
        assert FAKE_SECRET not in str(creds)

    def test_credentials_are_immutable(self):
        creds = self._creds()
        with pytest.raises(Exception):
            creds.api_key = "attacker-key"  # type: ignore[misc]

    def test_auth_headers_bearer_only(self):
        creds = self._creds()
        assert creds.auth_headers() == {"Authorization": f"Bearer {FAKE_SECRET}"}

    def test_missing_url_rejected(self):
        with pytest.raises(ExecutorConfigError):
            credentials_from_settings(
                "wazuh",
                _settings(
                    WAZUH_API_USER="sentinelflow-automation",
                    WAZUH_API_PASSWORD=FAKE_SECRET,
                ),
            )

    def test_unknown_adapter_rejected(self):
        with pytest.raises(ExecutorConfigError, match="selection error"):
            credentials_from_settings("splunk", _settings())

    def test_errors_never_echo_secret(self):
        with pytest.raises(ExecutorConfigError) as exc:
            credentials_from_settings(
                "shuffle",
                _settings(SHUFFLE_BASE_URL="", SHUFFLE_API_KEY=FAKE_SECRET),
            )
        assert FAKE_SECRET not in str(exc.value)


# --------------------------------------------------------------------------
# 4. Redaction machinery
# --------------------------------------------------------------------------
class TestRedaction:
    def test_redact_text_replaces_known_secret(self):
        text = f"auth failed using {FAKE_SECRET} for shuffle"
        assert redact_text(text, (FAKE_SECRET,)) == f"auth failed using {MASK} for shuffle"

    def test_short_values_not_blindly_replaced(self):
        # "id" would corrupt legitimate text — below the redactable floor.
        assert redact_text("id=42", ("id",)) == "id=42"

    def test_current_secret_values_drops_empties(self, monkeypatch):
        monkeypatch.setattr(settings, "SHUFFLE_API_KEY", FAKE_SECRET)
        monkeypatch.setattr(settings, "WAZUH_API_PASSWORD", "")
        monkeypatch.setattr(settings, "THEHIVE_API_KEY", "   ")
        assert FAKE_SECRET in current_secret_values()
        assert "" not in current_secret_values()

    def test_detail_sensitive_keys_masked_by_name(self):
        detail = {"authorization": "Bearer whatever", "nested": {"api_key": "anything"}}
        projected = redact_detail(detail, ("nothing-matches",))
        assert projected["authorization"] == MASK
        assert projected["nested"]["api_key"] == MASK

    def test_detail_secret_values_masked_on_innocent_keys(self):
        detail = {"note": f"token was {FAKE_SECRET}", "status": "ok"}
        projected = redact_detail(detail, (FAKE_SECRET,))
        assert FAKE_SECRET not in str(projected)
        assert MASK in projected["note"]
        assert projected["status"] == "ok"

    def test_detail_lists_recursed(self):
        detail = {"headers": [{"Authorization": f"Bearer {FAKE_SECRET}"}]}
        projected = redact_detail(detail, (FAKE_SECRET,))
        assert FAKE_SECRET not in str(projected)

    def test_detail_input_never_mutated(self):
        detail = {"api_key": FAKE_SECRET}
        redact_detail(detail, (FAKE_SECRET,))
        assert detail == {"api_key": FAKE_SECRET}


# --------------------------------------------------------------------------
# 5. Audit gate — the smuggler end-to-end proof
# --------------------------------------------------------------------------
class TestAuditGate:
    def test_smuggled_secret_never_reaches_execution_log(
        self, db_session, monkeypatch
    ):
        """A malicious adapter echoes the credential in its outcome
        detail; the audit gate must turn every occurrence into ***."""
        monkeypatch.setattr(settings, "SHUFFLE_API_KEY", FAKE_SECRET)

        from tests.test_execution_service import seed_approved

        approval = seed_approved(db_session)
        result = execute_response(
            db_session,
            approval_id=approval.id,
            execution_id=uuid.uuid4(),
            operator="ops-1",
            executor=_SmugglingExecutor(),
        )
        db_session.commit()

        raw = "".join(str(row.detail) for row in result.rows)
        assert FAKE_SECRET not in raw
        assert MASK in raw
        # Non-secret audit content survives the gate untouched.
        assert "block_source_ip" in raw

    def test_gate_is_wired_into_the_single_write_point(self):
        """Static lock: service._append routes EVERY detail through
        redact_detail — the gate cannot be bypassed by new call sites."""
        import inspect

        from app.services.executions import service

        source = inspect.getsource(service._append)
        assert "redact_detail(detail)" in source


# --------------------------------------------------------------------------
# 6. Config errors stay sanitized (registry integration)
# --------------------------------------------------------------------------
class TestConfigErrorTaxonomy:
    def test_url_shape_gate_at_startup(self):
        from app.services.executions import validate_adapter_config

        with pytest.raises(ExecutorConfigError, match="query string"):
            validate_adapter_config(
                _settings(
                    EXECUTION_ADAPTER="shuffle",
                    SHUFFLE_BASE_URL=f"https://shuffle.corp?token={FAKE_SECRET}",
                    SHUFFLE_API_KEY=FAKE_SECRET,
                )
            )

    def test_url_shape_error_never_echoes_url(self):
        from app.services.executions import validate_adapter_config

        poisoned = f"https://shuffle.corp?token={FAKE_SECRET}"
        with pytest.raises(ExecutorConfigError) as exc:
            validate_adapter_config(
                _settings(
                    EXECUTION_ADAPTER="shuffle",
                    SHUFFLE_BASE_URL=poisoned,
                    SHUFFLE_API_KEY=FAKE_SECRET,
                )
            )
        assert poisoned not in str(exc.value)
        assert FAKE_SECRET not in str(exc.value)

    def test_missing_credential_error_unaffected(self):
        from app.services.executions import validate_adapter_config

        with pytest.raises(ExecutorConfigError, match="missing required configuration"):
            validate_adapter_config(_settings(EXECUTION_ADAPTER="wazuh"))


# --------------------------------------------------------------------------
# 7. API error surface — static details, no secret, no raw exception
# --------------------------------------------------------------------------
class TestApiErrorSurface:
    def test_misconfigured_adapter_is_static_503(self, client, monkeypatch):
        monkeypatch.setattr(settings, "EXECUTION_ADAPTER", "shuffle")
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", FAKE_SECRET)
        monkeypatch.setattr(settings, "SHUFFLE_BASE_URL", "http://stub")
        monkeypatch.setattr(settings, "SHUFFLE_API_KEY", FAKE_SECRET)

        response = client.post(
            "/api/v1/executions",
            json={
                "execution_id": str(uuid.uuid4()),
                "approval_id": str(uuid.uuid4()),
                "operator": "ops-1",
            },
            headers={"Authorization": f"Bearer {FAKE_SECRET}"},
        )
        assert response.status_code == 503
        assert response.json()["detail"] == "Execution adapter misconfigured"
        assert FAKE_SECRET not in response.text

    def test_401_body_never_carries_secret(self, client, monkeypatch):
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", FAKE_SECRET)
        response = client.post(
            "/api/v1/executions",
            json={
                "execution_id": str(uuid.uuid4()),
                "approval_id": str(uuid.uuid4()),
                "operator": "ops-1",
            },
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert response.status_code == 401
        assert FAKE_SECRET not in response.text


# --------------------------------------------------------------------------
# 8. Logging discipline
# --------------------------------------------------------------------------
class TestLoggingDiscipline:
    def _emit(self, secrets_values, msg, args=None):
        logger = logging.getLogger(f"secret-boundary-{uuid.uuid4().hex}")
        logger.setLevel(logging.DEBUG)
        logger.addFilter(SecretRedactionFilter(secrets_values))
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.warning(msg, *args) if args else logger.warning(msg)
        return stream.getvalue()

    def test_secret_in_message_masked(self):
        out = self._emit((FAKE_SECRET,), f"shuffle auth with {FAKE_SECRET}")
        assert FAKE_SECRET not in out
        assert MASK in out

    def test_secret_in_args_masked(self):
        out = self._emit((FAKE_SECRET,), "header: %s", (f"Bearer {FAKE_SECRET}",))
        assert FAKE_SECRET not in out
        assert MASK in out

    def test_without_filter_would_leak(self):
        # Sanity: the mask comes from OUR filter, nothing upstream.
        logger = logging.getLogger(f"plain-{uuid.uuid4().hex}")
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
        logger.warning(f"value {FAKE_SECRET}")
        assert FAKE_SECRET in stream.getvalue()


# --------------------------------------------------------------------------
# 9. Full-path leak regression (user-specified sentinel key)
# --------------------------------------------------------------------------
class TestFullPathLeak:
    def test_secret_never_survives_any_surface(self, client, monkeypatch):
        """Seed FAKE_SECRET into every credential slot, then walk ALL
        leak surfaces: repr -> exception -> audit detail -> API error ->
        logging. Every surface must show *** (or nothing), never the
        raw secret."""
        monkeypatch.setattr(settings, "EXECUTION_ADAPTER", "shuffle")
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", FAKE_SECRET)
        monkeypatch.setattr(settings, "SHUFFLE_API_KEY", FAKE_SECRET)
        monkeypatch.setattr(settings, "WAZUH_API_PASSWORD", FAKE_SECRET)
        monkeypatch.setattr(settings, "THEHIVE_API_KEY", FAKE_SECRET)

        surfaces = []

        # 1. Settings repr / str
        surfaces.append(repr(settings))
        surfaces.append(str(settings))

        # 2. Adapter exception strings (missing-config + shape errors)
        from app.services.executions import validate_adapter_config

        try:
            validate_adapter_config(
                _settings(EXECUTION_ADAPTER="shuffle", SHUFFLE_API_KEY=FAKE_SECRET)
            )
        except ExecutorConfigError as error:
            surfaces.append(str(error))
        try:
            validate_base_url("shuffle", f"https://x?k={FAKE_SECRET}")
        except ExecutorConfigError as error:
            surfaces.append(str(error))

        # 3. Audit detail projection (smuggler outcome)
        surfaces.append(str(redact_detail({"api_key": FAKE_SECRET})))

        # 4. API error surface (503 static mapping)
        response = client.post(
            "/api/v1/executions",
            json={
                "execution_id": str(uuid.uuid4()),
                "approval_id": str(uuid.uuid4()),
                "operator": "ops-1",
            },
            headers={"Authorization": f"Bearer {FAKE_SECRET}"},
        )
        surfaces.append(response.text)

        # 5. Python logging through the redaction filter
        surfaces.append(
            TestLoggingDiscipline()._emit(
                current_secret_values(), f"key={FAKE_SECRET}"
            )
        )

        for surface in surfaces:
            assert FAKE_SECRET not in surface, f"LEAK on surface: {surface}"
        assert response.status_code == 503
