"""Phase 3.4.4-A — Adapter Callback Authentication tests (Webhook Gate 1).

Locks Gate 1 of the four frozen webhook inbound gates:

    External System -> HTTP Webhook
        -> Gate 1 Authentication    (THIS FILE, 3.4.4-A)
        -> Gate 2 Schema            (3.4.4-B)
        -> Gate 3 Correlation       (3.4.4-C)
        -> Gate 4 Semantic Mapping  (3.4.4-D)
        -> Outcome Fact Append      (3.4.4-E)

Coverage map (acceptance gate — spec §15 items 1-20, plus §16 / §12 / §14):
- Callback config (§4/§17): three *_CALLBACK_TOKEN fields, empty default,
  auto-masked, NOT wired into startup validation, no MOCK_CALLBACK_TOKEN.
- Per-adapter auth (§15.1-8): shuffle / wazuh / thehive valid + invalid.
- Cross-adapter isolation (§15.9-11 / §8): one adapter's token never
  authenticates another adapter's channel.
- Mock rejection (§15.12 / §5 / §17): mock (and any unknown adapter) is a
  404 unsupported channel — never a 401, never a webhook.
- Bearer handling (§15.13-14 / §7): malformed / non-Bearer / empty /
  non-ASCII all collapse to the uniform 401 (never a 500).
- Uniform 401 (§9): every failure shape is byte-identical, leaking nothing
  about token existence / adapter / length.
- Identity binding (§15.18 / §10 / §11): the trusted identity comes from the
  SERVER-SIDE route + that adapter's own token, never from client input.
- Operator isolation (§15.19-20 / §6): no EXECUTION_TOKEN fallback, no
  OPERATORS_JSON reuse — the callback trust domain is disjoint.
- Token secrecy (§15.15-17 / §12): never in a log / response / exception /
  repr.
- AST import surface (§16): webhooks.py imports ONLY {__future__, secrets,
  fastapi, app.core.config}; defines ONLY the three sanctioned functions;
  never references EXECUTION_TOKEN / OPERATORS_JSON / operators / executor.

AUTH ONLY. No schema, no correlation, no mapping, no persistence (spec §3);
those arrive in 3.4.4-B..E. The Shuffle/TheHive Gate-4 fail-closed behaviour
is untouched here and must not be relaxed to "make a demo pass".
"""
import ast
import inspect
import json
import logging

import pytest
from fastapi import HTTPException

from app.api.v1 import webhooks as webhook_module
from app.api.v1.webhooks import (
    CALLBACK_ADAPTERS,
    CALLBACK_AUTH_FAILURE_DETAIL,
    CALLBACK_TOKEN_SETTINGS,
    CALLBACK_UNSUPPORTED_ADAPTER_DETAIL,
    authenticate_callback,
)
from app.core.config import Settings, settings
from app.services.executions.registry import RECOGNIZED_ADAPTER_NAMES

WEBHOOK = "/api/v1/webhooks"

# Distinct per-adapter secrets so cross-adapter isolation is unambiguous.
SHUFFLE_TOKEN = "shuffle-callback-secret"
WAZUH_TOKEN = "wazuh-callback-secret"
THEHIVE_TOKEN = "thehive-callback-secret"

# A malformed non-ASCII credential, built with chr(233) at RUNTIME rather
# than embedded as a source literal, so the test input is encoding-
# unambiguous. It still exercises compare_digest's non-ASCII str rejection:
# the gate encodes both sides to UTF-8 bytes, so this is a uniform 401,
# never an unhandled TypeError / 500.
NON_ASCII_BEARER = "Bearer caf" + chr(233)


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
@pytest.fixture()
def all_tokens(monkeypatch):
    """Configure all three callback channels with distinct secrets."""
    monkeypatch.setattr(settings, "SHUFFLE_CALLBACK_TOKEN", SHUFFLE_TOKEN)
    monkeypatch.setattr(settings, "WAZUH_CALLBACK_TOKEN", WAZUH_TOKEN)
    monkeypatch.setattr(settings, "THEHIVE_CALLBACK_TOKEN", THEHIVE_TOKEN)


@pytest.fixture()
def no_tokens(monkeypatch):
    """Every callback channel unconfigured (fail-closed baseline)."""
    monkeypatch.setattr(settings, "SHUFFLE_CALLBACK_TOKEN", "")
    monkeypatch.setattr(settings, "WAZUH_CALLBACK_TOKEN", "")
    monkeypatch.setattr(settings, "THEHIVE_CALLBACK_TOKEN", "")


# --------------------------------------------------------------------------
# 1. Callback configuration (§4 / §17)
# --------------------------------------------------------------------------
class TestCallbackConfiguration:
    def test_three_callback_token_fields_default_empty(self):
        fields = Settings.model_fields
        for name in (
            "SHUFFLE_CALLBACK_TOKEN",
            "WAZUH_CALLBACK_TOKEN",
            "THEHIVE_CALLBACK_TOKEN",
        ):
            assert name in fields, f"{name} must exist"
            assert fields[name].default == "", f"{name} must default empty"

    def test_no_mock_callback_token_field(self):
        # §17: mock is never a callback channel — no token field may exist.
        assert "MOCK_CALLBACK_TOKEN" not in Settings.model_fields

    def test_callback_tokens_are_masked_in_repr(self):
        # §12: values end in TOKEN -> auto-masked; the field NAME stays
        # visible so config debugging still works.
        s = Settings(SHUFFLE_CALLBACK_TOKEN="abc123secret")
        assert "abc123secret" not in repr(s)
        assert "SHUFFLE_CALLBACK_TOKEN" in repr(s)

    def test_empty_callback_tokens_do_not_block_startup(self):
        # §4: an unconfigured callback token must NOT prevent app startup —
        # constructing Settings with all-empty callback tokens raises nothing.
        s = Settings(
            SHUFFLE_CALLBACK_TOKEN="",
            WAZUH_CALLBACK_TOKEN="",
            THEHIVE_CALLBACK_TOKEN="",
        )
        assert s.WAZUH_CALLBACK_TOKEN == ""

    def test_allow_list_is_exactly_the_recognized_adapters(self):
        # §5/§16: the callback allow-list == the recognized external adapters
        # (single source of truth), with mock deliberately excluded.
        assert set(CALLBACK_ADAPTERS) == set(RECOGNIZED_ADAPTER_NAMES)
        assert set(CALLBACK_ADAPTERS) == {"shuffle", "wazuh", "thehive"}
        assert "mock" not in CALLBACK_ADAPTERS

    def test_token_settings_bind_each_adapter_to_its_own_field(self):
        # §8: route adapter -> its OWN server-side token setting name.
        assert CALLBACK_TOKEN_SETTINGS == {
            "shuffle": "SHUFFLE_CALLBACK_TOKEN",
            "wazuh": "WAZUH_CALLBACK_TOKEN",
            "thehive": "THEHIVE_CALLBACK_TOKEN",
        }


# --------------------------------------------------------------------------
# 2. Shuffle authentication (§15.1-4)
# --------------------------------------------------------------------------
class TestShuffleAuthentication:
    def test_1_valid_shuffle_token(self, all_tokens):
        assert (
            authenticate_callback("shuffle", f"Bearer {SHUFFLE_TOKEN}")
            == "shuffle"
        )

    def test_2_invalid_shuffle_token(self, all_tokens):
        with pytest.raises(HTTPException) as exc:
            authenticate_callback("shuffle", "Bearer wrong-token")
        assert exc.value.status_code == 401

    def test_3_missing_shuffle_token(self, all_tokens):
        with pytest.raises(HTTPException) as exc:
            authenticate_callback("shuffle", None)
        assert exc.value.status_code == 401

    def test_4_unconfigured_shuffle_token(self, no_tokens):
        # channel exists but its token is empty -> fail-closed 401
        with pytest.raises(HTTPException) as exc:
            authenticate_callback("shuffle", f"Bearer {SHUFFLE_TOKEN}")
        assert exc.value.status_code == 401


# --------------------------------------------------------------------------
# 3. Wazuh authentication (§15.5-6)
# --------------------------------------------------------------------------
class TestWazuhAuthentication:
    def test_5_valid_wazuh_token(self, all_tokens):
        assert (
            authenticate_callback("wazuh", f"Bearer {WAZUH_TOKEN}") == "wazuh"
        )

    def test_6_invalid_wazuh_token(self, all_tokens):
        with pytest.raises(HTTPException) as exc:
            authenticate_callback("wazuh", "Bearer wrong-token")
        assert exc.value.status_code == 401


# --------------------------------------------------------------------------
# 4. TheHive authentication (§15.7-8)
# --------------------------------------------------------------------------
class TestTheHiveAuthentication:
    def test_7_valid_thehive_token(self, all_tokens):
        assert (
            authenticate_callback("thehive", f"Bearer {THEHIVE_TOKEN}")
            == "thehive"
        )

    def test_8_invalid_thehive_token(self, all_tokens):
        with pytest.raises(HTTPException) as exc:
            authenticate_callback("thehive", "Bearer wrong-token")
        assert exc.value.status_code == 401


# --------------------------------------------------------------------------
# 5. Cross-adapter isolation (§15.9-11 / §8)
# --------------------------------------------------------------------------
class TestCrossAdapterIsolation:
    def test_9_shuffle_token_cannot_authenticate_wazuh(self, all_tokens):
        with pytest.raises(HTTPException) as exc:
            authenticate_callback("wazuh", f"Bearer {SHUFFLE_TOKEN}")
        assert exc.value.status_code == 401

    def test_10_wazuh_token_cannot_authenticate_shuffle(self, all_tokens):
        with pytest.raises(HTTPException) as exc:
            authenticate_callback("shuffle", f"Bearer {WAZUH_TOKEN}")
        assert exc.value.status_code == 401

    def test_11_thehive_token_cannot_authenticate_shuffle(self, all_tokens):
        with pytest.raises(HTTPException) as exc:
            authenticate_callback("shuffle", f"Bearer {THEHIVE_TOKEN}")
        assert exc.value.status_code == 401


# --------------------------------------------------------------------------
# 6. Mock rejection (§15.12 / §5 / §17)
# --------------------------------------------------------------------------
class TestMockRejection:
    def test_12_mock_is_rejected_unsupported(self, all_tokens):
        # mock is never a callback channel -> 404, NOT 401, and never a fact.
        with pytest.raises(HTTPException) as exc:
            authenticate_callback("mock", f"Bearer {SHUFFLE_TOKEN}")
        assert exc.value.status_code == 404
        assert exc.value.detail == CALLBACK_UNSUPPORTED_ADAPTER_DETAIL

    def test_unknown_adapter_is_rejected_unsupported(self, all_tokens):
        with pytest.raises(HTTPException) as exc:
            authenticate_callback("not-a-real-adapter", "Bearer anything")
        assert exc.value.status_code == 404
        assert exc.value.detail == CALLBACK_UNSUPPORTED_ADAPTER_DETAIL

    def test_mock_endpoint_is_unsupported_via_http(self, client, all_tokens):
        # Even carrying a valid-looking bearer, /webhooks/mock is no channel.
        resp = client.post(f"{WEBHOOK}/mock", headers=_bearer(SHUFFLE_TOKEN))
        assert resp.status_code == 404


# --------------------------------------------------------------------------
# 7. Bearer handling / malformed authorization (§15.13-14 / §7 / §9)
# --------------------------------------------------------------------------
class TestBearerHandling:
    def test_13_malformed_authorization(self, all_tokens):
        for header in (
            "Bearer",              # scheme with no credential / no space
            "BearerNoSpace",       # not the Bearer scheme
            "bearer " + WAZUH_TOKEN,  # wrong case -> not recognized
            "Bearer  ",            # only whitespace credential
            "random garbage",      # no scheme at all
        ):
            with pytest.raises(HTTPException) as exc:
                authenticate_callback("wazuh", header)
            assert exc.value.status_code == 401, header

    def test_14_non_bearer_authorization(self, all_tokens):
        for header in (
            f"Basic {WAZUH_TOKEN}",
            f"Token {WAZUH_TOKEN}",
            WAZUH_TOKEN,           # raw token, no scheme
        ):
            with pytest.raises(HTTPException) as exc:
                authenticate_callback("wazuh", header)
            assert exc.value.status_code == 401, header

    def test_empty_bearer_credential_rejected(self, all_tokens):
        with pytest.raises(HTTPException) as exc:
            authenticate_callback("wazuh", "Bearer ")
        assert exc.value.status_code == 401

    def test_non_ascii_credential_is_401_never_500(self, all_tokens):
        # secrets.compare_digest rejects non-ASCII str; the gate encodes both
        # sides to UTF-8 bytes first, so a malformed non-ASCII credential is
        # a uniform 401 — never an unhandled TypeError / 500.
        with pytest.raises(HTTPException) as exc:
            authenticate_callback("wazuh", NON_ASCII_BEARER + "-" + WAZUH_TOKEN)
        assert exc.value.status_code == 401
        assert exc.value.detail == CALLBACK_AUTH_FAILURE_DETAIL


# --------------------------------------------------------------------------
# 8. Uniform 401 — no metadata leakage (§9)
# --------------------------------------------------------------------------
class TestUniformErrorResponse:
    @pytest.mark.parametrize(
        "authz",
        [
            None,
            "",
            "Bearer",
            "Bearer ",
            "Basic x",
            "Token x",
            "Bearer definitely-wrong-token",
            NON_ASCII_BEARER,
        ],
    )
    def test_every_failure_shape_is_identical_401(self, all_tokens, authz):
        # §9: missing / malformed / non-Bearer / wrong / non-ASCII are ALL
        # byte-identical — an attacker cannot discriminate between them.
        with pytest.raises(HTTPException) as exc:
            authenticate_callback("wazuh", authz)
        assert exc.value.status_code == 401
        assert exc.value.detail == CALLBACK_AUTH_FAILURE_DETAIL

    def test_unconfigured_and_wrong_token_indistinguishable(self, monkeypatch):
        # §9: "does a token exist?" must never be observable from the response.
        monkeypatch.setattr(settings, "WAZUH_CALLBACK_TOKEN", "")
        with pytest.raises(HTTPException) as unconfigured:
            authenticate_callback("wazuh", f"Bearer {WAZUH_TOKEN}")
        monkeypatch.setattr(settings, "WAZUH_CALLBACK_TOKEN", WAZUH_TOKEN)
        with pytest.raises(HTTPException) as wrong:
            authenticate_callback("wazuh", "Bearer not-the-token")
        assert unconfigured.value.status_code == wrong.value.status_code == 401
        assert unconfigured.value.detail == wrong.value.detail

    def test_failure_detail_leaks_no_metadata(self):
        # §9/§12: the single static detail carries no token, no adapter name,
        # and no "does a token exist / how long is it" hint.
        detail = CALLBACK_AUTH_FAILURE_DETAIL
        assert detail == "callback authentication failed"
        lowered = detail.lower()
        for forbidden in (
            "wazuh", "shuffle", "thehive", "mock",
            "exists", "unconfigured", "missing", "malformed", "length",
        ):
            assert forbidden not in lowered, f"detail leaks {forbidden!r}"


# --------------------------------------------------------------------------
# 9. Identity binding (§15.18 / §10 / §11 / §8)
# --------------------------------------------------------------------------
class TestIdentityBinding:
    def test_18_identity_from_route_and_server_config(self, all_tokens):
        # The returned identity is the ROUTE adapter, resolved against that
        # adapter's OWN server-side token — never derived from the credential.
        for adapter, token in (
            ("shuffle", SHUFFLE_TOKEN),
            ("wazuh", WAZUH_TOKEN),
            ("thehive", THEHIVE_TOKEN),
        ):
            assert authenticate_callback(adapter, f"Bearer {token}") == adapter

    def test_identity_ignores_credential_content(self, monkeypatch):
        # §11: a token whose VALUE names other adapters still yields the
        # route identity — identity is server-side, never client-supplied.
        impostor = "shuffle-wazuh-thehive-mock"
        monkeypatch.setattr(settings, "WAZUH_CALLBACK_TOKEN", impostor)
        assert (
            authenticate_callback("wazuh", f"Bearer {impostor}") == "wazuh"
        )

    def test_identity_is_plain_string_not_credential(self, all_tokens):
        ident = authenticate_callback("wazuh", f"Bearer {WAZUH_TOKEN}")
        assert isinstance(ident, str)
        assert ident in CALLBACK_ADAPTERS
        assert WAZUH_TOKEN not in ident  # never echoes the secret

    def test_identity_via_http_is_not_echoed(self, client, all_tokens):
        # §14: the stub ack is minimal and credential-free.
        resp = client.post(f"{WEBHOOK}/wazuh", headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 200
        assert resp.json() == {"accepted": True}
        assert WAZUH_TOKEN not in resp.text
        assert "wazuh" not in resp.text  # identity not echoed either


# --------------------------------------------------------------------------
# 10. Operator trust-domain isolation (§15.19-20 / §6)
# --------------------------------------------------------------------------
class TestOperatorIsolation:
    def test_19_no_execution_token_fallback(self, monkeypatch, no_tokens):
        # §6/§19: EXECUTION_TOKEN is a DIFFERENT trust domain — it must never
        # authenticate a callback channel, even when it equals the bearer.
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", WAZUH_TOKEN)
        with pytest.raises(HTTPException) as exc:
            authenticate_callback("wazuh", f"Bearer {WAZUH_TOKEN}")
        assert exc.value.status_code == 401

    def test_20_no_operators_json_dependency(self, monkeypatch, no_tokens):
        # §6/§20: a valid OPERATOR token must never authenticate a callback.
        monkeypatch.setattr(
            settings,
            "OPERATORS_JSON",
            json.dumps(
                [{"token": WAZUH_TOKEN, "name": "alice", "role": "executor"}]
            ),
        )
        with pytest.raises(HTTPException) as exc:
            authenticate_callback("wazuh", f"Bearer {WAZUH_TOKEN}")
        assert exc.value.status_code == 401

    def test_shared_secret_still_requires_callback_token(self, monkeypatch):
        # Even when BOTH domains hold the SAME secret value, the callback
        # channel accepts it ONLY via <ADAPTER>_CALLBACK_TOKEN — proving the
        # callback path reads its own setting, never the operator registry.
        monkeypatch.setattr(settings, "WAZUH_CALLBACK_TOKEN", "")
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", "shared-secret")
        with pytest.raises(HTTPException) as exc:
            authenticate_callback("wazuh", "Bearer shared-secret")
        assert exc.value.status_code == 401


# --------------------------------------------------------------------------
# 11. Token secrecy (§15.15-17 / §12)
# --------------------------------------------------------------------------
class TestTokenSecrecy:
    def test_15_token_never_logged(self, client, all_tokens, caplog):
        with caplog.at_level(logging.DEBUG):
            client.post(f"{WEBHOOK}/wazuh", headers=_bearer(WAZUH_TOKEN))
            client.post(f"{WEBHOOK}/wazuh", headers=_bearer("wrong-token"))
        for secret in (SHUFFLE_TOKEN, WAZUH_TOKEN, THEHIVE_TOKEN):
            assert secret not in caplog.text

    def test_16_token_never_in_response(self, client, all_tokens):
        ok = client.post(f"{WEBHOOK}/wazuh", headers=_bearer(WAZUH_TOKEN))
        assert WAZUH_TOKEN not in ok.text
        bad = client.post(f"{WEBHOOK}/wazuh", headers=_bearer("wrong-token"))
        assert WAZUH_TOKEN not in bad.text

    def test_17_token_never_in_exception(self, all_tokens):
        with pytest.raises(HTTPException) as exc:
            authenticate_callback("wazuh", "Bearer wrong-token")
        # the exception carries ONLY the static detail — no credential, and
        # not even the attempted (wrong) token value.
        assert WAZUH_TOKEN not in str(exc.value)
        assert WAZUH_TOKEN not in exc.value.detail
        assert "wrong-token" not in exc.value.detail

    def test_authorization_header_never_echoed(self, client, all_tokens):
        resp = client.post(f"{WEBHOOK}/wazuh", headers=_bearer(WAZUH_TOKEN))
        assert "Authorization" not in resp.text
        assert "Bearer" not in resp.text

    def test_settings_repr_masks_all_callback_tokens(self):
        s = Settings(
            SHUFFLE_CALLBACK_TOKEN="sh-secret",
            WAZUH_CALLBACK_TOKEN="wz-secret",
            THEHIVE_CALLBACK_TOKEN="th-secret",
        )
        rendered = repr(s)
        for secret in ("sh-secret", "wz-secret", "th-secret"):
            assert secret not in rendered
        assert "SHUFFLE_CALLBACK_TOKEN" in rendered  # name stays visible


# --------------------------------------------------------------------------
# 12. Endpoint surface — Gate 1 ONLY (§14 / §3)
# --------------------------------------------------------------------------
class TestEndpointSurface:
    def test_valid_callback_returns_accepted_ack(self, client, all_tokens):
        resp = client.post(f"{WEBHOOK}/wazuh", headers=_bearer(WAZUH_TOKEN))
        assert resp.status_code == 200
        assert resp.json() == {"accepted": True}

    def test_all_three_channels_reachable(self, client, all_tokens):
        for adapter, token in (
            ("shuffle", SHUFFLE_TOKEN),
            ("wazuh", WAZUH_TOKEN),
            ("thehive", THEHIVE_TOKEN),
        ):
            resp = client.post(f"{WEBHOOK}/{adapter}", headers=_bearer(token))
            assert resp.status_code == 200, adapter
            assert resp.json() == {"accepted": True}

    def test_unauthenticated_callback_never_reaches_ack(self, client, all_tokens):
        resp = client.post(f"{WEBHOOK}/wazuh", headers=_bearer("wrong-token"))
        assert resp.status_code == 401
        assert resp.json() == {"detail": CALLBACK_AUTH_FAILURE_DETAIL}

    def test_missing_header_via_http_is_401(self, client, all_tokens):
        resp = client.post(f"{WEBHOOK}/shuffle")
        assert resp.status_code == 401
        assert resp.json() == {"detail": CALLBACK_AUTH_FAILURE_DETAIL}

    def test_unconfigured_channel_via_http_is_401(self, client, no_tokens):
        resp = client.post(f"{WEBHOOK}/thehive", headers=_bearer(THEHIVE_TOKEN))
        assert resp.status_code == 401

    def test_endpoint_writes_no_outcome_fact(self, client, db_session, all_tokens):
        # §3/§14: Gate 1 ONLY — no persistence. The append-only
        # execution_outcome table stays empty after an accepted callback
        # (the fact append is 3.4.4-E, never here).
        from app.models.execution_outcome import ExecutionOutcome

        client.post(f"{WEBHOOK}/wazuh", headers=_bearer(WAZUH_TOKEN))
        assert db_session.query(ExecutionOutcome).count() == 0


# --------------------------------------------------------------------------
# 13. AST / import surface (§16) — structural security proof
# --------------------------------------------------------------------------
def _imported_webhooks():
    """AST view of webhooks.py's OWN imports + defined functions — the robust
    structural proof, immune to docstring mentions (mirrors the 3.4.3
    reconciliation import-surface test)."""
    tree = ast.parse(inspect.getsource(webhook_module))
    modules, names, funcs = set(), set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module:
                modules.add(node.module)
            for alias in node.names:
                names.add(alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                modules.add(alias.name)
        elif isinstance(node, ast.FunctionDef):
            funcs.add(node.name)
    return modules, names, funcs


class TestImportSurface:
    def test_modules_are_exactly_the_authentication_dependencies(self):
        # §16: ONLY these four modules — proves no operators / executor /
        # execution service / response_execution / persistence / HTTP-client
        # import sneaks into the callback gate.
        modules, _, _ = _imported_webhooks()
        assert modules == {"__future__", "secrets", "fastapi", "app.core.config"}

    def test_no_forbidden_symbol_imported(self):
        modules, names, _ = _imported_webhooks()
        for mod in modules:
            for bad in (
                "operators", "executor", "response_execution", "registry",
                "derivation", "reconciliation", "sqlalchemy", "httpx",
                "requests", "models",
            ):
                assert bad not in mod, f"module {mod} pulls in forbidden {bad}"
        # §6/§16: operator identity machinery must never be imported.
        assert "authenticate_operator" not in names
        assert "OperatorRegistry" not in names
        assert "get_operator_registry" not in names

    def test_functions_are_exactly_the_sanctioned_three(self):
        # §3/§16: only bearer extraction + Gate-1 auth + the stub endpoint.
        # No schema / correlation / mapping / persistence function exists.
        _, _, funcs = _imported_webhooks()
        assert funcs == {
            "_extract_bearer",
            "authenticate_callback",
            "receive_adapter_callback",
        }

    def test_source_never_references_operator_trust_domain(self):
        # §16: source-text scan (safe here — these literals are deliberately
        # absent even from the docstring) proves the callback gate never
        # reads EXECUTION_TOKEN / OPERATORS_JSON.
        source = inspect.getsource(webhook_module)
        assert "EXECUTION_TOKEN" not in source
        assert "OPERATORS_JSON" not in source

    def test_source_has_no_persistence_or_execution_surface(self):
        # §3: no DB / executor / schema / mapping construct in the module.
        source = inspect.getsource(webhook_module)
        for forbidden in (
            "db.commit", "db.rollback", "SessionLocal", "execute(",
            "derive_outcome_state", "ExecutionOutcome(", "BaseModel",
            ".query(", "validate_adapter_config",
        ):
            assert forbidden not in source, f"forbidden construct: {forbidden}"

    def test_authenticate_callback_has_no_body_parameter(self):
        # §8/§11: the gate takes ONLY the route adapter + Authorization
        # header — there is no request body from which a client could try to
        # override the adapter identity.
        params = inspect.signature(authenticate_callback).parameters
        assert set(params) == {"adapter", "authorization"}
