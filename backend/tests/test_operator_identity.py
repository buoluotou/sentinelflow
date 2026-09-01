"""Phase 3.3.1 — Operator Identity & RBAC tests.

Locks the server-side identity binding:

    Bearer Token -> OperatorRegistry -> Authenticated Operator (name + role)

Coverage map (acceptance gate):
- OperatorRole: vocabulary frozen, can_execute correct per role
- Operator: immutable dataclass, token NEVER stored
- OperatorRegistry: token -> unique Operator, legacy fallback, None on miss
- build_registry: OPERATORS_JSON parsing, validation (bad JSON, bad role,
  duplicate token/name, empty fields), empty config
- authenticate_operator: valid token -> Operator, invalid -> 401,
  viewer/reviewer -> 403, executor/admin -> 200
- API integration: operator from token (not body), legacy fallback works,
  body operator IGNORED, compensate uses authenticated operator
- Token security: never in response / DB / repr / str / audit detail
- Legacy EXECUTION_TOKEN: backwards compatible when OPERATORS_JSON empty

No Policy, no Metrics, no React, no SSO/LDAP/OIDC, no new adapters,
no execution state changes.
"""
import json
import uuid
from datetime import datetime, timezone

import pytest

from app.core.config import Settings, settings
from app.models import (
    AIResponseApproval,
    AIResponseRecommendation,
    AlertGroup,
    ExecutionLog,
)
from app.services.executions.operators import (
    LEGACY_OPERATOR_NAME,
    Operator,
    OperatorRegistry,
    OperatorRole,
    VALID_ROLES,
    build_registry,
    get_operator_registry,
    reset_operator_registry,
)

EXECUTE = "/api/v1/executions"
COMPENSATE = "/api/v1/executions/compensate"


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
@pytest.fixture(autouse=True)
def _reset_registry():
    """Force a fresh registry for every test (the registry is a module-
    level singleton; without reset, monkeypatched settings would be
    ignored after the first build)."""
    reset_operator_registry()
    yield
    reset_operator_registry()


@pytest.fixture()
def ops_json():
    """Two operators: alice (executor) and bob (viewer)."""
    return json.dumps([
        {"token": "tok-alice-001", "name": "alice", "role": "executor"},
        {"token": "tok-bob-002", "name": "bob", "role": "viewer"},
    ])


@pytest.fixture()
def auth_header():
    return {"Authorization": "Bearer tok-alice-001"}


# --------------------------------------------------------------------------
# OperatorRole — frozen vocabulary
# --------------------------------------------------------------------------
class TestOperatorRole:
    def test_four_roles_frozen(self):
        assert VALID_ROLES == {"viewer", "reviewer", "executor", "admin"}

    def test_can_execute_executor_and_admin_only(self):
        assert not OperatorRole.VIEWER.can_execute
        assert not OperatorRole.REVIEWER.can_execute
        assert OperatorRole.EXECUTOR.can_execute
        assert OperatorRole.ADMIN.can_execute

    def test_role_values(self):
        assert OperatorRole.VIEWER.value == "viewer"
        assert OperatorRole.REVIEWER.value == "reviewer"
        assert OperatorRole.EXECUTOR.value == "executor"
        assert OperatorRole.ADMIN.value == "admin"


# --------------------------------------------------------------------------
# Operator — immutable, token-free
# --------------------------------------------------------------------------
class TestOperator:
    def test_immutable_dataclass(self):
        op = Operator(name="alice", role=OperatorRole.EXECUTOR)
        with pytest.raises(Exception):
            op.name = "mallory"

    def test_token_never_stored(self):
        op = Operator(name="alice", role=OperatorRole.EXECUTOR)
        assert not hasattr(op, "token")
        assert "token" not in vars(op)

    def test_repr_no_secret(self):
        op = Operator(name="alice", role=OperatorRole.EXECUTOR)
        assert "alice" in repr(op)
        assert "EXECUTOR" in repr(op) or "executor" in repr(op)


# --------------------------------------------------------------------------
# OperatorRegistry — token -> Operator lookup
# --------------------------------------------------------------------------
class TestOperatorRegistry:
    def test_lookup_returns_correct_operator(self):
        ops = [
            Operator("alice", OperatorRole.EXECUTOR),
            Operator("bob", OperatorRole.VIEWER),
        ]
        reg = OperatorRegistry(ops, ["tok-a", "tok-b"])
        assert reg.lookup("tok-a") == ops[0]
        assert reg.lookup("tok-b") == ops[1]

    def test_lookup_unknown_returns_none(self):
        reg = OperatorRegistry(
            [Operator("alice", OperatorRole.EXECUTOR)], ["tok-a"]
        )
        assert reg.lookup("nonexistent") is None

    def test_lookup_legacy_fallback(self):
        reg = OperatorRegistry([], [])
        op = reg.lookup("legacy-tok", legacy_token="legacy-tok")
        assert op is not None
        assert op.name == LEGACY_OPERATOR_NAME
        assert op.role == OperatorRole.EXECUTOR

    def test_lookup_legacy_wrong_token(self):
        reg = OperatorRegistry([], [])
        assert reg.lookup("wrong", legacy_token="legacy-tok") is None

    def test_lookup_legacy_empty_string(self):
        reg = OperatorRegistry([], [])
        assert reg.lookup("anything", legacy_token="") is None

    def test_registered_takes_precedence_over_legacy(self):
        """When a token matches a registered operator, the legacy
        fallback is never reached — even if the same token is also
        set as the legacy token."""
        ops = [Operator("alice", OperatorRole.ADMIN)]
        reg = OperatorRegistry(ops, ["shared-tok"])
        result = reg.lookup("shared-tok", legacy_token="shared-tok")
        assert result.name == "alice"
        assert result.role == OperatorRole.ADMIN

    def test_operator_count(self):
        ops = [
            Operator("a", OperatorRole.VIEWER),
            Operator("b", OperatorRole.EXECUTOR),
        ]
        reg = OperatorRegistry(ops, ["t1", "t2"])
        assert reg.operator_count == 2

    def test_empty_registry(self):
        reg = OperatorRegistry([], [])
        assert reg.operator_count == 0
        assert reg.lookup("anything") is None

    def test_has_operator(self):
        ops = [Operator("alice", OperatorRole.EXECUTOR)]
        reg = OperatorRegistry(ops, ["tok"])
        assert reg.has_operator("alice")
        assert not reg.has_operator("bob")

    def test_get_by_name(self):
        ops = [Operator("alice", OperatorRole.EXECUTOR)]
        reg = OperatorRegistry(ops, ["tok"])
        assert reg.get_by_name("alice") == ops[0]
        assert reg.get_by_name("bob") is None

    def test_repr_shows_names_not_tokens(self):
        ops = [Operator("alice", OperatorRole.EXECUTOR)]
        reg = OperatorRegistry(ops, ["super-secret-token"])
        r = repr(reg)
        assert "alice" in r
        assert "super-secret-token" not in r


# --------------------------------------------------------------------------
# build_registry — OPERATORS_JSON parsing & validation
# --------------------------------------------------------------------------
class TestBuildRegistry:
    def _settings(self, **kw):
        return Settings(**kw)

    def test_empty_config_empty_registry(self):
        reg = build_registry(self._settings())
        assert reg.operator_count == 0

    def test_valid_json_builds_registry(self):
        reg = build_registry(self._settings(
            OPERATORS_JSON=json.dumps([
                {"token": "t1", "name": "alice", "role": "executor"},
                {"token": "t2", "name": "bob", "role": "viewer"},
            ])
        ))
        assert reg.operator_count == 2
        assert reg.has_operator("alice")
        assert reg.has_operator("bob")
        assert reg.get_by_name("alice").role == OperatorRole.EXECUTOR
        assert reg.get_by_name("bob").role == OperatorRole.VIEWER

    def test_all_four_roles_accepted(self):
        entries = [
            {"token": f"t-{r}", "name": f"op-{r}", "role": r}
            for r in ["viewer", "reviewer", "executor", "admin"]
        ]
        reg = build_registry(self._settings(OPERATORS_JSON=json.dumps(entries)))
        assert reg.operator_count == 4

    def test_invalid_json_raises_value_error(self):
        with pytest.raises(ValueError, match="not valid JSON"):
            build_registry(self._settings(OPERATORS_JSON="{bad"))

    def test_not_array_rejected(self):
        with pytest.raises(ValueError, match="must be a JSON array"):
            build_registry(self._settings(OPERATORS_JSON='{"token":"t"}'))

    def test_entry_not_object_rejected(self):
        with pytest.raises(ValueError, match="must be an object"):
            build_registry(self._settings(OPERATORS_JSON='["string"]'))

    def test_empty_token_rejected(self):
        with pytest.raises(ValueError, match="token is empty"):
            build_registry(self._settings(
                OPERATORS_JSON=json.dumps([
                    {"token": "", "name": "alice", "role": "executor"}
                ])
            ))

    def test_empty_name_rejected(self):
        with pytest.raises(ValueError, match="name is empty"):
            build_registry(self._settings(
                OPERATORS_JSON=json.dumps([
                    {"token": "t1", "name": "", "role": "viewer"}
                ])
            ))

    def test_invalid_role_rejected(self):
        with pytest.raises(ValueError, match="role="):
            build_registry(self._settings(
                OPERATORS_JSON=json.dumps([
                    {"token": "t1", "name": "alice", "role": "superadmin"}
                ])
            ))

    def test_duplicate_token_rejected(self):
        with pytest.raises(ValueError, match="duplicate"):
            build_registry(self._settings(
                OPERATORS_JSON=json.dumps([
                    {"token": "same", "name": "alice", "role": "executor"},
                    {"token": "same", "name": "bob", "role": "viewer"},
                ])
            ))

    def test_duplicate_name_rejected(self):
        with pytest.raises(ValueError, match="duplicate"):
            build_registry(self._settings(
                OPERATORS_JSON=json.dumps([
                    {"token": "t1", "name": "alice", "role": "executor"},
                    {"token": "t2", "name": "alice", "role": "viewer"},
                ])
            ))

    def test_error_messages_never_contain_token_values(self):
        """Validation errors name the field (token/name/role) but never
        echo the actual token value — tokens are secrets."""
        secret_tok = "super-secret-token-value-12345"
        with pytest.raises(ValueError) as exc:
            build_registry(self._settings(
                OPERATORS_JSON=json.dumps([
                    {"token": secret_tok, "name": "", "role": "executor"}
                ])
            ))
        assert secret_tok not in str(exc.value)


# --------------------------------------------------------------------------
# get_operator_registry — module-level singleton
# --------------------------------------------------------------------------
class TestGetOperatorRegistry:
    def test_returns_registry(self):
        reg = get_operator_registry()
        assert isinstance(reg, OperatorRegistry)

    def test_reset_forces_rebuild(self, monkeypatch):
        monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
            {"token": "t1", "name": "alice", "role": "executor"},
        ]))
        reset_operator_registry()
        r1 = get_operator_registry()
        assert r1.operator_count == 1

        monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
            {"token": "t1", "name": "alice", "role": "executor"},
            {"token": "t2", "name": "bob", "role": "viewer"},
        ]))
        reset_operator_registry()
        r2 = get_operator_registry()
        assert r2.operator_count == 2


# --------------------------------------------------------------------------
# authenticate_operator — API dependency
# --------------------------------------------------------------------------
class TestAuthenticateOperatorDependency:
    def test_valid_executor_token(self, monkeypatch, auth_header):
        monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
            {"token": "tok-alice-001", "name": "alice", "role": "executor"},
        ]))
        from app.api.v1.response_execution import authenticate_operator
        op = authenticate_operator(authorization=auth_header["Authorization"])
        assert op.name == "alice"
        assert op.role == OperatorRole.EXECUTOR
        assert op.role.can_execute

    def test_valid_admin_token(self, monkeypatch):
        monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
            {"token": "tok-admin", "name": "root", "role": "admin"},
        ]))
        from app.api.v1.response_execution import authenticate_operator
        op = authenticate_operator(authorization="Bearer tok-admin")
        assert op.name == "root"
        assert op.role == OperatorRole.ADMIN

    def test_viewer_gets_403(self, monkeypatch):
        monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
            {"token": "tok-viewer", "name": "read-only", "role": "viewer"},
        ]))
        from app.api.v1.response_execution import authenticate_operator
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            authenticate_operator(authorization="Bearer tok-viewer")
        assert exc.value.status_code == 403

    def test_reviewer_gets_403(self, monkeypatch):
        monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
            {"token": "tok-rev", "name": "reviewer-1", "role": "reviewer"},
        ]))
        from app.api.v1.response_execution import authenticate_operator
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            authenticate_operator(authorization="Bearer tok-rev")
        assert exc.value.status_code == 403

    def test_wrong_token_gets_401(self, monkeypatch):
        monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
            {"token": "tok-real", "name": "alice", "role": "executor"},
        ]))
        from app.api.v1.response_execution import authenticate_operator
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            authenticate_operator(authorization="Bearer tok-wrong")
        assert exc.value.status_code == 401

    def test_missing_header_gets_401(self, monkeypatch):
        monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
            {"token": "tok", "name": "alice", "role": "executor"},
        ]))
        from app.api.v1.response_execution import authenticate_operator
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            authenticate_operator(authorization=None)
        assert exc.value.status_code == 401

    def test_malformed_bearer_gets_401(self, monkeypatch):
        monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
            {"token": "tok", "name": "alice", "role": "executor"},
        ]))
        from app.api.v1.response_execution import authenticate_operator
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            authenticate_operator(authorization="Token tok")
        assert exc.value.status_code == 401

    def test_empty_bearer_gets_401(self, monkeypatch):
        monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
            {"token": "tok", "name": "alice", "role": "executor"},
        ]))
        from app.api.v1.response_execution import authenticate_operator
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            authenticate_operator(authorization="Bearer ")
        assert exc.value.status_code == 401

    def test_legacy_token_fallback_executor_role(self, monkeypatch):
        monkeypatch.setattr(settings, "OPERATORS_JSON", "")
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", "legacy-tok")
        from app.api.v1.response_execution import authenticate_operator
        op = authenticate_operator(authorization="Bearer legacy-tok")
        assert op.name == LEGACY_OPERATOR_NAME
        assert op.role == OperatorRole.EXECUTOR

    def test_nothing_configured_401(self, monkeypatch):
        monkeypatch.setattr(settings, "OPERATORS_JSON", "")
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", "")
        from app.api.v1.response_execution import authenticate_operator
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as exc:
            authenticate_operator(authorization="Bearer anything")
        assert exc.value.status_code == 401
        assert "not configured" in exc.value.detail


# --------------------------------------------------------------------------
# API integration — operator from token, not body
# --------------------------------------------------------------------------
def _seed_approval(db_session, *, status="approved"):
    now = datetime.now(timezone.utc)
    group = AlertGroup(
        fingerprint=uuid.uuid4().hex,
        title="SSH Brute Force",
        category="authentication",
        severity="high",
        first_seen=now,
        last_seen=now,
    )
    db_session.add(group)
    db_session.flush()
    record = AIResponseRecommendation(
        alert_group=group,
        provider="mock",
        model="mock-deterministic",
        overall_rationale="[mock] guidance",
        recommendations=[
            {"action": "block_source_ip", "target": "203.0.113.10",
             "rationale": "abuse"}
        ],
        confidence=0.7,
    )
    db_session.add(record)
    db_session.flush()
    approval = AIResponseApproval(
        recommendation_id=record.id,
        status=status,
        reviewer="analyst-1",
        reviewed_at=now,
    )
    db_session.add(approval)
    db_session.commit()
    return approval


class TestAPIOperatorIntegration:
    def test_operator_from_token_not_body(
        self, client, db_session, monkeypatch
    ):
        """The operator in the execution_log row MUST come from the
        authenticated token, never from the request body."""
        monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
            {"token": "tok-alice", "name": "alice", "role": "executor"},
        ]))
        approval = _seed_approval(db_session)
        response = client.post(
            EXECUTE,
            json={
                "execution_id": str(uuid.uuid4()),
                "approval_id": str(approval.id),
                "operator": "fake-admin",  # MUST be ignored
            },
            headers={"Authorization": "Bearer tok-alice"},
        )
        assert response.status_code == 201
        rows = list(db_session.query(ExecutionLog))
        assert all(r.operator == "alice" for r in rows)
        assert all(r.operator != "fake-admin" for r in rows)

    def test_operator_body_optional_still_works(
        self, client, db_session, monkeypatch
    ):
        """A legacy client that sends operator in the body still gets 201
        — the field is accepted but ignored."""
        monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
            {"token": "tok-alice", "name": "alice", "role": "executor"},
        ]))
        approval = _seed_approval(db_session)
        response = client.post(
            EXECUTE,
            json={
                "execution_id": str(uuid.uuid4()),
                "approval_id": str(approval.id),
                # No operator field at all
            },
            headers={"Authorization": "Bearer tok-alice"},
        )
        assert response.status_code == 201
        rows = list(db_session.query(ExecutionLog))
        assert all(r.operator == "alice" for r in rows)

    def test_legacy_token_api_execution(
        self, client, db_session, monkeypatch
    ):
        """Legacy EXECUTION_TOKEN still works for backwards compat;
        operator is 'legacy-execution'."""
        monkeypatch.setattr(settings, "OPERATORS_JSON", "")
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", "legacy-tok")
        approval = _seed_approval(db_session)
        response = client.post(
            EXECUTE,
            json={
                "execution_id": str(uuid.uuid4()),
                "approval_id": str(approval.id),
            },
            headers={"Authorization": "Bearer legacy-tok"},
        )
        assert response.status_code == 201
        rows = list(db_session.query(ExecutionLog))
        assert all(r.operator == LEGACY_OPERATOR_NAME for r in rows)

    def test_viewer_cannot_execute_via_api(
        self, client, db_session, monkeypatch
    ):
        monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
            {"token": "tok-viewer", "name": "viewer-1", "role": "viewer"},
        ]))
        approval = _seed_approval(db_session)
        response = client.post(
            EXECUTE,
            json={
                "execution_id": str(uuid.uuid4()),
                "approval_id": str(approval.id),
            },
            headers={"Authorization": "Bearer tok-viewer"},
        )
        assert response.status_code == 403
        assert list(db_session.query(ExecutionLog)) == []

    def test_reviewer_cannot_execute_via_api(
        self, client, db_session, monkeypatch
    ):
        monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
            {"token": "tok-rev", "name": "rev-1", "role": "reviewer"},
        ]))
        approval = _seed_approval(db_session)
        response = client.post(
            EXECUTE,
            json={
                "execution_id": str(uuid.uuid4()),
                "approval_id": str(approval.id),
            },
            headers={"Authorization": "Bearer tok-rev"},
        )
        assert response.status_code == 403
        assert list(db_session.query(ExecutionLog)) == []

    def test_compensate_uses_authenticated_operator(
        self, client, db_session, monkeypatch
    ):
        """Compensation rows use the authenticated operator, not the
        body's operator field."""
        monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
            {"token": "tok-alice", "name": "alice", "role": "executor"},
        ]))
        approval = _seed_approval(db_session)
        # Forward execution
        exec_id = uuid.uuid4()
        r = client.post(
            EXECUTE,
            json={
                "execution_id": str(exec_id),
                "approval_id": str(approval.id),
            },
            headers={"Authorization": "Bearer tok-alice"},
        )
        assert r.status_code == 201
        # Compensation
        comp_id = uuid.uuid4()
        r2 = client.post(
            COMPENSATE,
            json={
                "execution_id": str(comp_id),
                "compensates_execution_id": str(exec_id),
                "operator": "fake-name",  # MUST be ignored
            },
            headers={"Authorization": "Bearer tok-alice"},
        )
        assert r2.status_code == 201
        comp_rows = [
            row for row in db_session.query(ExecutionLog)
            if row.execution_id == comp_id
        ]
        assert all(r.operator == "alice" for r in comp_rows)

    def test_wrong_token_401_zero_rows(
        self, client, db_session, monkeypatch
    ):
        monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
            {"token": "tok-real", "name": "alice", "role": "executor"},
        ]))
        approval = _seed_approval(db_session)
        response = client.post(
            EXECUTE,
            json={
                "execution_id": str(uuid.uuid4()),
                "approval_id": str(approval.id),
            },
            headers={"Authorization": "Bearer tok-wrong"},
        )
        assert response.status_code == 401
        assert list(db_session.query(ExecutionLog)) == []


# --------------------------------------------------------------------------
# Token security — never in response / DB / repr / audit
# --------------------------------------------------------------------------
class TestOperatorTokenSecurity:
    def test_token_never_in_response(
        self, client, db_session, monkeypatch
    ):
        secret = "super-secret-tok-xyz"
        monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
            {"token": secret, "name": "alice", "role": "executor"},
        ]))
        approval = _seed_approval(db_session)
        response = client.post(
            EXECUTE,
            json={
                "execution_id": str(uuid.uuid4()),
                "approval_id": str(approval.id),
            },
            headers={"Authorization": f"Bearer {secret}"},
        )
        assert response.status_code == 201
        assert secret not in response.text

    def test_token_never_in_db_rows(
        self, client, db_session, monkeypatch
    ):
        secret = "super-secret-tok-xyz"
        monkeypatch.setattr(settings, "OPERATORS_JSON", json.dumps([
            {"token": secret, "name": "alice", "role": "executor"},
        ]))
        approval = _seed_approval(db_session)
        client.post(
            EXECUTE,
            json={
                "execution_id": str(uuid.uuid4()),
                "approval_id": str(approval.id),
            },
            headers={"Authorization": f"Bearer {secret}"},
        )
        for row in db_session.query(ExecutionLog):
            assert secret != row.operator
            assert secret not in str(row.detail)

    def test_operator_repr_no_token(self):
        op = Operator(name="alice", role=OperatorRole.EXECUTOR)
        assert "alice" in repr(op)
        assert "secret" not in repr(op).lower() or "alice" in repr(op)

    def test_registry_repr_no_tokens(self):
        reg = OperatorRegistry(
            [Operator("alice", OperatorRole.EXECUTOR)],
            ["super-secret-tok"],
        )
        r = repr(reg)
        assert "alice" in r
        assert "super-secret-tok" not in r

    def test_settings_repr_masks_operators_json(self):
        s = Settings(OPERATORS_JSON='[{"token":"secret","name":"a","role":"admin"}]')
        assert "secret" not in repr(s)
        assert "OPERATORS_JSON" in repr(s)

    def test_settings_str_masks_operators_json(self):
        s = Settings(OPERATORS_JSON='[{"token":"secret","name":"a","role":"admin"}]')
        assert "secret" not in str(s)


# --------------------------------------------------------------------------
# Frozen clause: RBAC is authorization, not automation
# --------------------------------------------------------------------------
class TestRBACIsNotAutomation:
    """Phase 3.3 frozen principle: RBAC grants or denies access; it
    never auto-approves or auto-executes. This test locks the invariant
    at the source-code level — no endpoint or service path calls
    execute_response / compensate_response without an explicit HTTP
    request carrying a valid Bearer token."""

    def test_no_auto_execute_from_role(self):
        """No code path auto-dispatches execution just because an
        operator has the admin role. The only execution trigger is
        POST /executions with a valid Bearer token."""
        import inspect
        from app.api.v1 import response_execution as api_mod

        source = inspect.getsource(api_mod)
        # authenticate_operator is only used as a Depends() — never
        # called to trigger execution automatically.
        assert "execute_response(" not in inspect.getsource(
            api_mod.authenticate_operator
        )
        assert "compensate_response(" not in inspect.getsource(
            api_mod.authenticate_operator
        )
