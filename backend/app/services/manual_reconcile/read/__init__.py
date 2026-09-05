"""Read side of Manual Reconcile (Phase 3.4.5-A1).

The Adapter Read Contract + Registry — the PURE, read-only, DB-free, HTTP-free
mirror of the write-side executor stack. Concrete readers (Shuffle / Wazuh /
TheHive) are Evidence-Gapped and land in 3.4.5-B/C/D; this package ships the
contract shapes and an EMPTY production registry that rejects every adapter.
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
