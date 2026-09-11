"""Manual Reconcile services.

The read / reconcile side of the execution outcome lifecycle — physically
isolated from the write side (``app.services.executions``). Manual Reconcile is
an explicit, operator-triggered pull that reads external state and reconciles it
into an append-only Outcome Fact; it is never an execution.

This package ships only the adapter read contract and registry: pure shapes, an
empty production registry, and the read-adapter exception family. The platform
pipeline (auth -> correlation -> external_reference extraction -> registry -> read
-> mapping -> append -> derivation) lives in
``app.services.outcomes.manual_reconcile``; concrete Shuffle / Wazuh / TheHive
readers have no runtime evidence yet.

No API, no DB, no HTTP, no mapping here.
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
