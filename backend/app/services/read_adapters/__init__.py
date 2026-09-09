"""Concrete READ adapters + their settings-driven registry factory (M2 §5).

The 3.4.5-A1 read CONTRACT lives in the SEALED PURE package
``app.services.manual_reconcile.read`` — AST- and runtime-audited
(``test_adapter_read_contract.py``) to forbid HTTP / DB / credentials /
``app.services.executions`` / ``app.services.outcomes`` imports. A CONCRETE reader
that issues a real authenticated ``GET`` therefore CANNOT live in that package; it
lives HERE, physically separate from BOTH the sealed contract package and the
WRITE adapters (``app.services.executions``), keeping Read and Write isolated
(design §21). The dependency direction is one-way: this package imports the pure
contract shapes (``ReadAdapter`` / ``AdapterReadRequest`` / ``AdapterReadResult`` /
``ReadAdapterRegistry``) and the read-side exception family (``ReadTransportError``)
— never the reverse.

M2 §5 delivers ONE concrete reader — ``TheHiveReadAdapter`` (the case-CREATION
effect verifier) — and ``create_read_adapter_registry``, a settings-driven factory
that registers it ONLY when the M2-R §4 THREE-gate authorization passes (a
well-formed base URL + an INDEPENDENT read-only key, never the create-capable
write key + an EXACT certified-version match; fail-closed otherwise). It is NOT
wired into the reconcile router in M2 (LAB BLOCKED — no real
TheHive runtime evidence; see the registry module docstring), so production
behavior is UNCHANGED: the router still resolves the SEALED EMPTY
``default_read_adapter_registry()``. The reader + factory are isolation-tested
(unit + service-level explicit injection) and production-READY for the phase that
has real runtime evidence.

M3 (Phase 3.4.5-M3 §3/§4) ADDS the SOURCE-ISOLATED trusted-proof kernel
``verified`` — the TYPED internal proof shapes (``VerifiedReadResult`` /
``ReadCorrelationContext`` / ``VerifiedCreationEffect`` / ``CreationRefusal``), the
``TrustedCreationReader`` protocol and the SINGLE pure creation-effect verifier
``verify_creation_effect`` (the six conjunctive gates of Amendment §4). It is a PURE,
side-effect-free module (no DB, no HTTP, no ``app.services.outcomes``) re-exported here
for the PULL-only orchestration (``outcomes/verified_proof``) and the M3 suite. It does
NOT extend the frozen public ``AdapterReadResult`` / ``AdapterReadRequest``, does NOT add
a second external-state vocabulary, and is reachable ONLY through the controlled
reconcile call chain — NEVER from the webhook path (Amendment §5.3 / §11.2 constraint #1).
``TheHiveReadAdapter.read_creation`` is the concrete reader's internal trusted verb that
returns a ``VerifiedReadResult``; the frozen public ``read`` is unchanged.
"""
from app.services.read_adapters.registry import create_read_adapter_registry
from app.services.read_adapters.thehive import (
    CASE_CREATED,
    CASE_UNVERIFIED,
    TheHiveReadAdapter,
)
from app.services.read_adapters.verified import (
    APPROVED_APPROVAL_STATUS,
    APPROVED_CREATION_ACTION,
    PROOF_SCOPE_VERIFIED_CREATION,
    CreationRefusal,
    ReadCorrelationContext,
    TrustedCreationReader,
    VerifiedCreationEffect,
    VerifiedReadResult,
    created_at_millis,
    created_at_to_datetime,
    verify_creation_effect,
)

__all__ = [
    "CASE_CREATED",
    "CASE_UNVERIFIED",
    "TheHiveReadAdapter",
    "create_read_adapter_registry",
    # M3 §3/§4 source-isolated trusted-proof kernel (pure types + the single verifier).
    "VerifiedReadResult",
    "ReadCorrelationContext",
    "VerifiedCreationEffect",
    "CreationRefusal",
    "TrustedCreationReader",
    "verify_creation_effect",
    "created_at_to_datetime",
    "created_at_millis",
    "APPROVED_CREATION_ACTION",
    "APPROVED_APPROVAL_STATUS",
    "PROOF_SCOPE_VERIFIED_CREATION",
]
