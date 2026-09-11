"""Read side of Manual Reconcile.

The adapter read contract + registry — the pure, read-only, DB-free, HTTP-free
mirror of the write-side executor stack. Concrete Shuffle / Wazuh / TheHive readers
have no runtime evidence yet; this package ships the contract shapes and an empty
production registry that rejects every adapter.
"""
from app.services.manual_reconcile.read.base import (
    AdapterReadRequest,
    AdapterReadResult,
    ReadAdapter,
)
from app.services.manual_reconcile.read.registry import (
    ReadAdapterRegistry,
    default_read_adapter_registry,
)

__all__ = [
    "AdapterReadRequest",
    "AdapterReadResult",
    "ReadAdapter",
    "ReadAdapterRegistry",
    "default_read_adapter_registry",
]
