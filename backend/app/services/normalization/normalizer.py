"""Normalization engine: dispatches raw events to source adapters."""
from datetime import datetime

from app.schemas.alert import AlertCreate, HostInfo
from app.services.normalization.adapters.simulator import SimulatorAdapter
from app.services.normalization.adapters.wazuh import WazuhAdapter
from app.services.normalization.base import (
    AdapterNotImplementedError,
    BaseAdapter,
    UnknownSourceError,
)
from app.services.normalization.models import NormalizedAlert


class NormalizationEngine:
    """Routes raw events to the adapter registered for their source."""

    def __init__(self, adapters: list[BaseAdapter]):
        self._registry: dict[str, BaseAdapter] = {}
        for adapter in adapters:
            self._registry[adapter.source] = adapter

        # convenience aliases for the simulator identity used elsewhere
        if "simulator" in self._registry:
            self._registry["scenario-simulator"] = self._registry["simulator"]

    @property
    def sources(self) -> list[str]:
        return sorted(self._registry)

    def normalize(self, source: str, raw_data: dict) -> NormalizedAlert:
        adapter = self._registry.get(source)
        if adapter is None:
            raise UnknownSourceError(
                f"no normalization adapter registered for source '{source}' "
                f"(known sources: {', '.join(self.sources)})"
            )
        try:
            return adapter.normalize(raw_data)
        except NotImplementedError as exc:
            raise AdapterNotImplementedError(str(exc)) from exc

    @staticmethod
    def to_alert_create(normalized: NormalizedAlert) -> AlertCreate:
        """Map a NormalizedAlert onto the ingestion payload (Step 2 pipeline)."""
        timestamp = None
        raw_timestamp = normalized.raw_event.get("timestamp")
        if isinstance(raw_timestamp, str):
            try:
                timestamp = datetime.fromisoformat(raw_timestamp.replace("Z", "+00:00"))
            except ValueError:
                timestamp = None

        host = None
        if normalized.asset and (normalized.asset.hostname or normalized.asset.ip):
            host = HostInfo(hostname=normalized.asset.hostname, ip=normalized.asset.ip)

        return AlertCreate(
            source=normalized.source,
            event_type=normalized.event_type,
            severity=normalized.severity,
            timestamp=timestamp,
            title=normalized.title,
            message=normalized.description,
            host=host,
            source_ip=normalized.actor.ip if normalized.actor else None,
            user=normalized.actor.user if normalized.actor else None,
            raw_data=normalized.raw_event or None,
        )


#: engine shared by the API layer
engine = NormalizationEngine([SimulatorAdapter(), WazuhAdapter()])
