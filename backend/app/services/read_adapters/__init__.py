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
"""
from app.services.read_adapters.registry import create_read_adapter_registry
from app.services.read_adapters.thehive import (
    CASE_CREATED,
    CASE_UNVERIFIED,
    TheHiveReadAdapter,
)

__all__ = [
    "CASE_CREATED",
    "CASE_UNVERIFIED",
    "TheHiveReadAdapter",
    "create_read_adapter_registry",
]
