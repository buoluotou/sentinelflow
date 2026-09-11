"""Concrete READ adapters + their settings-driven registry factory.

The read contract lives in the sealed pure package
``app.services.manual_reconcile.read`` — AST- and runtime-audited
(``test_adapter_read_contract.py``) to forbid HTTP / DB / credentials /
``app.services.executions`` / ``app.services.outcomes`` imports. A concrete reader
that issues a real authenticated ``GET`` therefore cannot live in that package; it
lives here, physically separate from both the sealed contract package and the
write adapters (``app.services.executions``), keeping read and write isolated. The
dependency direction is one-way: this package imports the pure contract shapes
(``ReadAdapter`` / ``AdapterReadRequest`` / ``AdapterReadResult`` /
``ReadAdapterRegistry``) and the read-side exception family (``ReadTransportError``)
— never the reverse.

The one concrete reader is ``TheHiveReadAdapter`` (the case-creation effect
verifier), registered by ``create_read_adapter_registry``: a settings-driven factory
that registers it only when all three authorization gates hold — a well-formed base
URL, an independent read-only key (never the create-capable write key) and an exact
certified-version match — and fails closed otherwise. No live TheHive instance has
been exercised, so the factory is not wired into the reconcile router and production
behaviour is unchanged: the router still resolves the sealed empty
``default_read_adapter_registry()``. The reader and the factory are isolation-tested
(unit + service-level explicit injection).

The ``verified`` module is the source-isolated trusted-proof kernel: the typed
internal proof shapes (``VerifiedReadResult`` / ``ReadCorrelationContext`` /
``VerifiedCreationEffect`` / ``CreationRefusal``), the ``TrustedCreationReader``
protocol and the single pure creation-effect verifier ``verify_creation_effect``
(six conjunctive gates). It is pure and side-effect-free (no DB, no HTTP, no
``app.services.outcomes``) and is re-exported here for the pull-only orchestration
(``outcomes/verified_proof``). It does not extend the public ``AdapterReadResult`` /
``AdapterReadRequest``, does not add a second external-state vocabulary, and is
reachable only through the controlled reconcile call chain — never from the webhook
path. ``TheHiveReadAdapter.read_creation`` is the concrete reader's internal trusted
verb, returning a ``VerifiedReadResult``; the public ``read`` is unchanged.
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
    # Source-isolated trusted-proof kernel (pure types + the single verifier).
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
