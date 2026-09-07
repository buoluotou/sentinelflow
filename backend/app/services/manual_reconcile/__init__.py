"""Manual Reconcile services (Phase 3.4.5).

The READ / Reconcile side of the Execution Outcome Lifecycle — physically
isolated from the WRITE side (``app.services.executions``). Manual Reconcile is
an EXPLICIT, operator-triggered Pull that reads external state and reconciles it
into an append-only Outcome Fact; it is NEVER an Execution (design §3).

3.4.5-A1 (this package today) ships ONLY the Adapter Read Contract + Registry:
pure shapes, an EMPTY production registry, and the read-adapter exception family.
The Manual Reconcile platform pipeline (auth -> correlation -> external_reference
extraction -> registry -> read -> mapping -> append -> derivation) lands in
3.4.5-A2; concrete Shuffle / Wazuh / TheHive readers are Evidence-Gapped and land
in 3.4.5-B/C/D (design §16/§17).

NO API, NO DB, NO HTTP, NO mapping in A1 (design §12/§13/§14/§19).
"""
from app.services.manual_reconcile.exceptions import (
    ReadAdapterError,
    ReadTransportError,
    UnsupportedAdapterRead,
)
from app.services.manual_reconcile.read import (
    AdapterReadRequest,
    AdapterReadResult,
    ReadAdapter,
    ReadAdapterRegistry,
    default_read_adapter_registry,
)

__all__ = [
    "AdapterReadRequest",
    "AdapterReadResult",
    "ReadAdapter",
    "ReadAdapterError",
    "ReadAdapterRegistry",
    "ReadTransportError",
    "UnsupportedAdapterRead",
    "default_read_adapter_registry",
]
