"""M3 source-isolation proofs — webhook isolation + three-entry forgery rejection (§6).

WHAT THIS PROVES (Amendment §11.2 constraint #1: "an internal type is NOT a magic
credential ... 'do not import' is NOT the only defense — the call-chain reachability
is"). The trusted creation-proof channel is SOURCE-ISOLATED from the live PUSH
(webhook) ingress, and NO client entry point can inject a proof:

  1. IMPORT ISOLATION (AST) — the webhook SERVICE (``outcomes/webhook.py``) and the
     webhook ROUTER (``api/v1/webhooks.py``) have NO import edge to the proof kernel
     (``read_adapters.verified``) or the proof orchestration (``outcomes.verified_proof``),
     and import NONE of the proof symbols. NO ``api/v1`` router wires
     ``reconcile_verified_execution`` (the trusted channel is NOT wired — Amendment §5).
  2. VERIFIER REACHABILITY (AST call-graph) — ``verify_creation_effect`` is CALLED from
     EXACTLY ONE module: ``outcomes/verified_proof``. This is the single controlled call
     chain: no webhook, no router, no other service reaches the verifier.
  3. PROOF-KERNEL PURITY (AST) — ``read_adapters.verified`` imports ONLY stdlib + the
     pure A1 read-request shape: NO sqlalchemy, NO HTTP, NO ``app.models``, NO
     ``app.services.outcomes``, NO ``app.services.executions``. The kernel is physically
     side-effect-free, so it can never be the DB-owning path.
  4. RUNTIME ISOLATION (subprocess) — importing the webhook path in a FRESH interpreter
     never pulls ``outcomes.verified_proof`` into ``sys.modules`` (no transitive reach).
  5. THREE-ENTRY FORGERY REJECTION (HTTP) — a valid callback token + a bare
     ``case_created`` string, a webhook body smuggling internal-proof-shape fields
     (``verified`` / ``provenance`` / ``resource_id`` / ``instance_verified``), a webhook
     ``external_state`` Mapping dressed as a proof, and a reconcile body injecting proof
     fields are ALL refused (422) with ZERO Outcome Fact. The empty thehive vocabulary +
     ``extra="forbid"`` on both frozen request schemas close every entry.

These are STRUCTURAL + HTTP-integration proofs. They are NOT a real TheHive E2E (LAB
BLOCKED); they prove the isolation boundary holds with NO network and NO real system.
"""
import ast
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

from app.core.config import settings
from app.models import (
    AIResponseApproval,
    AIResponseRecommendation,
    AlertGroup,
    ExecutionLog,
    ExecutionOutcome,
)

BACKEND = Path(__file__).resolve().parents[1]
APP = BACKEND / "app"

NOW = datetime(2026, 9, 6, 12, 0, 0, tzinfo=timezone.utc)
THEHIVE_TOKEN = "thehive-callback-secret"
WEBHOOK = "/api/v1/webhooks"
RECONCILE = "/api/v1/executions/{eid}/reconcile"

#: The proof kernel (pure types + verifier) and the proof orchestration (DB-owning).
PROOF_MODULES = {
    "app.services.read_adapters.verified",
    "app.services.outcomes.verified_proof",
}
#: Every symbol the proof channel owns — a webhook/router must import NONE of them.
PROOF_SYMBOLS = {
    "verify_creation_effect",
    "VerifiedCreationEffect",
    "VerifiedReadResult",
    "ReadCorrelationContext",
    "CreationRefusal",
    "TrustedCreationReader",
    "reconcile_verified_execution",
    "derive_read_correlation_context",
    "_persist_verified_creation_outcome",
    "UnsealedCreationEffect",
    "VerifiedCreationRefused",
}


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------
def _module_name(py_file: Path) -> str:
    return ".".join(py_file.relative_to(BACKEND).with_suffix("").parts)


def _imported_modules(tree: ast.AST) -> set[str]:
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
    return mods


def _imported_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update(alias.name for alias in node.names)
    return names


def _called_function_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                names.add(fn.id)
            elif isinstance(fn, ast.Attribute):
                names.add(fn.attr)
    return names


def _parse(relpath: str) -> ast.AST:
    return ast.parse((APP / relpath).read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# seeding (mirrors test_webhook_persistence.py — correlation needs only existence)
# ---------------------------------------------------------------------------
def _seed_approval(db_session) -> AIResponseApproval:
    group = AlertGroup(
        fingerprint=uuid.uuid4().hex, title="SSH Brute Force on edge-gateway",
        category="authentication", severity="high", first_seen=NOW, last_seen=NOW,
    )
    db_session.add(group)
    db_session.flush()
    record = AIResponseRecommendation(
        alert_group=group, provider="mock", model="mock-deterministic",
        overall_rationale="[mock] guidance",
        recommendations=[{"action": "escalate_to_incident", "target": "case",
                          "rationale": "escalate"}],
        confidence=0.7,
    )
    db_session.add(record)
    db_session.flush()
    approval = AIResponseApproval(
        recommendation_id=record.id, status="approved", reviewer="analyst-1",
        reviewed_at=NOW,
    )
    db_session.add(approval)
    db_session.commit()
    return approval


def _seed_chain(db_session, execution_id, *, operator="ops-1"):
    # The single row carries BOTH the adapter (detail["executor"]) AND the reference
    # (detail["case_id"]) so the webhook path correlates (existence only) AND the reconcile
    # path can extract adapter+reference and reach the EMPTY registry (404), never the
    # 422 MissingExternalReference short-circuit.
    approval = _seed_approval(db_session)
    db_session.add(
        ExecutionLog(
            execution_id=execution_id, approval_id=approval.id, decision="succeeded",
            direction="execute", action="escalate_to_incident", target="case",
            operator=operator, detail={"executor": "thehive", "case_id": "~42"},
            created_at=NOW,
        )
    )
    db_session.commit()


def _body(execution_id, *, external_state="case_created", external_reference="~42",
          observed_at=NOW, **extra):
    """A Gate-2-shaped callback body; ``extra`` smuggles forbidden fields to prove
    ``extra="forbid"`` rejects them at the boundary."""
    payload = {
        "execution_id": str(execution_id),
        "external_reference": external_reference,
        "external_state": external_state,
        "observed_at": observed_at.isoformat(),
    }
    payload.update(extra)
    return payload


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _outcome_count(db_session) -> int:
    return len(list(db_session.scalars(select(ExecutionOutcome))))


# ===========================================================================
# 1. IMPORT ISOLATION — the webhook path has no edge to the proof channel
# ===========================================================================
class TestWebhookImportIsolation:
    def test_webhook_service_has_no_proof_import_edge(self):
        tree = _parse("services/outcomes/webhook.py")
        assert not (_imported_modules(tree) & PROOF_MODULES)
        assert not (_imported_names(tree) & PROOF_SYMBOLS)

    def test_webhook_router_has_no_proof_import_edge(self):
        tree = _parse("api/v1/webhooks.py")
        assert not (_imported_modules(tree) & PROOF_MODULES)
        assert not (_imported_names(tree) & PROOF_SYMBOLS)

    def test_no_api_router_wires_the_verified_channel(self):
        # Amendment §5: the trusted channel is NOT wired into ANY route. No router
        # imports the orchestration module or the reconcile_verified_execution entry.
        for router in sorted((APP / "api" / "v1").glob("*.py")):
            tree = ast.parse(router.read_text(encoding="utf-8"))
            assert "app.services.outcomes.verified_proof" not in _imported_modules(tree), router.name
            assert "reconcile_verified_execution" not in _imported_names(tree), router.name

    def test_reconcile_router_wires_only_the_sealed_a2_path(self):
        # The reconcile route delegates to the SEALED reconcile_execution (A2), never
        # the trusted reconcile_verified_execution — the router is unchanged by M3.
        tree = _parse("api/v1/reconcile.py")
        assert "reconcile_execution" in _imported_names(tree)
        assert "reconcile_verified_execution" not in _imported_names(tree)


# ===========================================================================
# 2. VERIFIER REACHABILITY — exactly one caller (the single controlled chain)
# ===========================================================================
class TestVerifierReachability:
    def test_verify_creation_effect_has_exactly_one_caller(self):
        callers = set()
        for py in APP.rglob("*.py"):
            if "verify_creation_effect" in _called_function_names(ast.parse(py.read_text(encoding="utf-8"))):
                callers.add(_module_name(py))
        # The ONLY module that CALLS the verifier is the DB-owning orchestration. The
        # webhook path, every router, and every other service NEVER reach it.
        assert callers == {"app.services.outcomes.verified_proof"}

    def test_no_webhook_module_calls_the_verifier(self):
        for relpath in ("services/outcomes/webhook.py", "api/v1/webhooks.py"):
            called = _called_function_names(_parse(relpath))
            assert "verify_creation_effect" not in called
            assert "reconcile_verified_execution" not in called


# ===========================================================================
# 2b. PROOF-CHANNEL CLOSURE (M4-C) — the effect has ONE mint site, persist ONE caller
# ===========================================================================
class TestProofChannelClosure:
    """M4-C: ``persist`` no longer trusts the TYPE NAME. ``VerifiedCreationEffect`` is minted
    at EXACTLY ONE site (``verify_creation_effect``) and the now-PRIVATE
    ``_persist_verified_creation_outcome`` is called from EXACTLY ONE module
    (``reconcile_verified_execution``), so the verify -> authorize -> persist triad is a single
    controlled chain. The runtime seal (``is_sealed()``) is the ACTIVE gate; these AST proofs
    are the REAL boundary (constraint #1: an internal type is NOT a magic credential)."""

    def test_verified_creation_effect_has_exactly_one_construction_site(self):
        sites = set()
        for py in APP.rglob("*.py"):
            if "VerifiedCreationEffect" in _called_function_names(
                ast.parse(py.read_text(encoding="utf-8"))
            ):
                sites.add(_module_name(py))
        # The ONLY module that CONSTRUCTS a VerifiedCreationEffect is the pure verifier. The
        # orchestration imports it for isinstance/type-hint only (never calls it); a plain
        # hand-built effect is refused at runtime by the seal (test_verified_creation_proof.py).
        assert sites == {"app.services.read_adapters.verified"}

    def test_persist_verified_creation_outcome_has_exactly_one_caller(self):
        callers = set()
        for py in APP.rglob("*.py"):
            if "_persist_verified_creation_outcome" in _called_function_names(
                ast.parse(py.read_text(encoding="utf-8"))
            ):
                callers.add(_module_name(py))
        # The private persist is called ONLY inside the controlled orchestration — no webhook,
        # no router, no other service reaches the confirmed_success persistence path.
        assert callers == {"app.services.outcomes.verified_proof"}

    def test_persist_is_module_private_not_publicly_exported(self):
        # The persist entry is PRIVATE (``_`` prefix): there is NO public
        # ``persist_verified_creation_outcome`` name left for an external caller to import.
        tree = _parse("services/outcomes/verified_proof.py")
        defined = {
            n.name
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        assert "_persist_verified_creation_outcome" in defined
        assert "persist_verified_creation_outcome" not in defined


# ===========================================================================
# 2c. M4-B IDENTITY SEAM ISOLATION — the read-side probe is an UNWIRED seam
# ===========================================================================
class TestIdentitySeamIsolation:
    """M4-B: the read-side identity/version evidence seam (``TheHiveReadAdapter.read_identity``
    + ``verified.assess_identity_evidence``) is DELIVERED + isolation-tested but NOT wired into
    any production router, the webhook path, or the reconcile derive orchestration (contract:
    the sealed registry stays empty, no production router). It NEVER back-fills a gate-5 binding:
    the assessor is PURE and its ``gate5_instance_binding`` / ``gate5_tenant_binding`` are ALWAYS
    ``None`` for TheHive 4.1.24-1 (the case-owned tenant is unobservable), so the seam can NEVER
    unlock ``confirmed_success`` on its own — it upgrades the version assertion to a runtime
    observation and records the reader's tenant context, nothing more."""

    def test_no_api_router_wires_the_identity_probe(self):
        for router in sorted((APP / "api" / "v1").glob("*.py")):
            called = _called_function_names(ast.parse(router.read_text(encoding="utf-8")))
            assert "read_identity" not in called, router.name
            assert "assess_identity_evidence" not in called, router.name

    def test_webhook_path_never_reaches_the_identity_probe(self):
        for relpath in ("services/outcomes/webhook.py", "api/v1/webhooks.py"):
            called = _called_function_names(_parse(relpath))
            assert "read_identity" not in called
            assert "assess_identity_evidence" not in called

    def test_assess_identity_evidence_has_no_production_caller(self):
        # The assessor is an UNWIRED seam: NO module under app/ CALLS it (only tests do). This is
        # the honest state — the identity evidence is assessed in isolation tests, never wired
        # into the reconcile derive path (which keeps the gate-5 bindings None for real history).
        callers = set()
        for py in APP.rglob("*.py"):
            if "assess_identity_evidence" in _called_function_names(
                ast.parse(py.read_text(encoding="utf-8"))
            ):
                callers.add(_module_name(py))
        assert callers == set()

    def test_derive_context_never_calls_the_identity_probe(self):
        # The reconcile derive path (verified_proof) NEVER consults read_identity to back-fill a
        # gate-5 binding — instance_binding / tenant_binding come ONLY from the M4-A dispatch
        # binding (None for 4.1.24-1), never from a read-side identity probe.
        called = _called_function_names(_parse("services/outcomes/verified_proof.py"))
        assert "read_identity" not in called
        assert "assess_identity_evidence" not in called


# ===========================================================================
# 3. PROOF-KERNEL PURITY — the pure types + verifier are side-effect-free
# ===========================================================================
class TestProofKernelPurity:
    def test_verified_kernel_imports_only_stdlib_and_the_pure_read_shape(self):
        mods = _imported_modules(_parse("services/read_adapters/verified.py"))
        allowed_stdlib = {"__future__", "uuid", "dataclasses", "datetime", "typing"}
        for m in mods:
            assert m in allowed_stdlib or m.startswith("app.services.manual_reconcile.read"), m

    def test_verified_kernel_has_no_db_http_write_or_outcome_imports(self):
        mods = _imported_modules(_parse("services/read_adapters/verified.py"))
        forbidden = (
            "sqlalchemy", "fastapi", "starlette", "pydantic", "urllib", "httpx",
            "requests", "app.models", "app.services.outcomes", "app.services.executions",
        )
        for f in forbidden:
            assert not any(m == f or m.startswith(f + ".") for m in mods), f


# ===========================================================================
# 4. RUNTIME ISOLATION — a fresh interpreter importing webhook pulls no proof orch
# ===========================================================================
class TestWebhookRuntimeIsolation:
    def test_webhook_import_never_pulls_the_proof_orchestration(self):
        code = (
            "import sys;"
            "import app.api.v1.webhooks;"
            "import app.services.outcomes.webhook;"
            "leaked='app.services.outcomes.verified_proof' in sys.modules;"
            "print('LEAK' if leaked else 'ISOLATED')"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, cwd=str(BACKEND)
        )
        assert proc.returncode == 0, proc.stderr
        assert "ISOLATED" in proc.stdout


# ===========================================================================
# 5. THREE-ENTRY FORGERY REJECTION (HTTP integration — fixture-approved, NOT a
#    real approval-API flow; NO network, NO real TheHive)
# ===========================================================================
class TestThreeEntryForgeryRejection:
    def test_entry1_webhook_bare_case_created_refused_zero_fact(
        self, client, db_session, monkeypatch
    ):
        # A VALID callback token + the bare synthesized string -> the EMPTY thehive
        # vocabulary refuses it at Gate 4 -> 422, ZERO fact (M2-R fail-closed, re-proven
        # in the M3 context: the new proof channel did NOT reopen the string path).
        monkeypatch.setattr(settings, "THEHIVE_CALLBACK_TOKEN", THEHIVE_TOKEN)
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        r = client.post(
            f"{WEBHOOK}/thehive",
            json=_body(eid, external_state="case_created"),
            headers=_bearer(THEHIVE_TOKEN),
        )
        assert r.status_code == 422
        assert r.json()["detail"] == "callback validation failed"
        assert _outcome_count(db_session) == 0

    def test_entry2_webhook_smuggled_proof_shape_fields_rejected(
        self, client, db_session, monkeypatch
    ):
        # Smuggle internal-proof-shape fields as EXTRA body keys -> extra="forbid"
        # rejects them at Gate 2 -> 422, ZERO fact. A client cannot inject verified /
        # provenance / resource_id / instance_verified (constraint #1: no client-controlled
        # verified flag).
        monkeypatch.setattr(settings, "THEHIVE_CALLBACK_TOKEN", THEHIVE_TOKEN)
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        r = client.post(
            f"{WEBHOOK}/thehive",
            json=_body(
                eid, external_state="case_created", verified=True,
                provenance="trusted_reader", resource_id="~42", instance_verified=True,
                source="verified_creation",
            ),
            headers=_bearer(THEHIVE_TOKEN),
        )
        assert r.status_code == 422
        assert _outcome_count(db_session) == 0

    def test_entry2b_webhook_forged_proof_mapping_refused_zero_fact(
        self, client, db_session, monkeypatch
    ):
        # A structured "proof-like" MAPPING in external_state PASSES Gate 2 (str|Mapping)
        # but the EMPTY thehive vocabulary refuses it at Gate 4 -> 422, ZERO fact. A
        # Mapping is NOT an authorization credential (Amendment §5.3).
        monkeypatch.setattr(settings, "THEHIVE_CALLBACK_TOKEN", THEHIVE_TOKEN)
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        forged = {"verified": True, "provenance": "trusted", "state": "case_created",
                  "source": "verified_creation", "instance_verified": True}
        r = client.post(
            f"{WEBHOOK}/thehive", json=_body(eid, external_state=forged),
            headers=_bearer(THEHIVE_TOKEN),
        )
        assert r.status_code == 422
        assert r.json()["detail"] == "callback validation failed"
        assert _outcome_count(db_session) == 0

    def test_entry3_reconcile_injected_proof_fields_rejected(
        self, client, db_session, monkeypatch
    ):
        # The Manual Reconcile body is EMPTY with extra="forbid": injecting proof /
        # context / adapter fields is a 422 at the boundary, ZERO fact. A client can
        # NEVER supply the ReadCorrelationContext the platform derives from history.
        monkeypatch.setattr(settings, "OPERATORS_JSON", "")
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", "legacy-tok")
        eid = uuid.uuid4()
        r = client.post(
            RECONCILE.format(eid=str(eid)),
            json={"verified": True, "provenance": "trusted", "adapter": "thehive",
                  "external_reference": "~42", "instance_binding": "lab"},
            headers=_bearer("legacy-tok"),
        )
        assert r.status_code == 422
        assert _outcome_count(db_session) == 0

    def test_entry3_reconcile_empty_body_never_reaches_the_verified_channel(
        self, client, db_session, monkeypatch
    ):
        # Even a WELL-FORMED empty reconcile body (valid auth) routes to the SEALED A2
        # reconcile_execution, whose EMPTY production registry -> 404, ZERO fact. The
        # trusted channel is never reached from HTTP (not wired).
        monkeypatch.setattr(settings, "OPERATORS_JSON", "")
        monkeypatch.setattr(settings, "EXECUTION_TOKEN", "legacy-tok")
        eid = uuid.uuid4()
        _seed_chain(db_session, eid)
        r = client.post(
            RECONCILE.format(eid=str(eid)), json={}, headers=_bearer("legacy-tok")
        )
        assert r.status_code == 404
        assert r.json()["detail"] == "adapter read unsupported"
        assert _outcome_count(db_session) == 0
