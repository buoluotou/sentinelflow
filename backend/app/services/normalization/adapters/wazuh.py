"""Wazuh adapter — placeholder interface for Phase 1.

Phase 1 intentionally does NOT connect to a real Wazuh deployment. The class
exists so the adapter registry, API contract and tests are already shaped for
the real integration (Phase 2), following the "reserve the interface, avoid
early coupling" principle.

Expected Wazuh alert shape for the future implementation::

    {
      "rule": {"level": 10, "description": "SSH brute force"},
      "agent": {"name": "server01"},
      ...
    }
"""
from app.services.normalization.base import BaseAdapter
from app.services.normalization.models import NormalizedAlert


class WazuhAdapter(BaseAdapter):
    source = "wazuh"

    def normalize(self, raw_data: dict) -> NormalizedAlert:
        # Placeholder: the engine translates NotImplementedError into
        # AdapterNotImplementedError, surfaced by the API as HTTP 501.
        raise NotImplementedError(
            "Wazuh adapter is reserved for Phase 2 and not implemented yet"
        )
