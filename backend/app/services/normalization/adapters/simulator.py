"""Adapter for the SentinelFlow scenario simulator.

Accepts both the full unified simulator event shape (as stored in
simulator/scenarios/*/events.json) and the minimal shape used by the
normalization test endpoint, e.g.::

    {"type": "ssh_failed_login", "src_ip": "10.10.10.5"}
"""
from app.schemas.alert import Severity
from app.services.normalization.base import BaseAdapter, MalformedRawEventError
from app.services.normalization.models import (
    ActorInfo,
    AssetInfo,
    Category,
    NormalizedAlert,
    Observable,
)

# event_type -> (category, severity, title template)
EVENT_TYPE_MAP: dict[str, tuple[Category, Severity, str]] = {
    "ssh_failed_login": (Category.AUTHENTICATION, Severity.MEDIUM, "SSH login failure detected"),
    "file_integrity_change": (Category.FILE_INTEGRITY, Severity.HIGH, "File integrity change detected"),
    "file_integrity": (Category.FILE_INTEGRITY, Severity.HIGH, "File integrity change detected"),
    "web_anomaly": (Category.WEB, Severity.MEDIUM, "Abnormal web request detected"),
    "suspicious_process": (Category.PROCESS, Severity.HIGH, "Suspicious process execution detected"),
    "malicious_ioc": (Category.THREAT_INTEL, Severity.CRITICAL, "Malicious IOC match detected"),
}

_FALLBACK = (Category.GENERIC, Severity.LOW, "Unclassified simulator event")


def _first(raw: dict, *keys: str):
    """Return the first non-None value among candidate keys."""
    for key in keys:
        value = raw.get(key)
        if value is not None:
            return value
    return None


class SimulatorAdapter(BaseAdapter):
    source = "simulator"

    def normalize(self, raw_data: dict) -> NormalizedAlert:
        if not isinstance(raw_data, dict) or not raw_data:
            raise MalformedRawEventError("simulator raw event must be a non-empty object")

        event_type = _first(raw_data, "type", "event_type")
        if not event_type:
            raise MalformedRawEventError(
                "simulator raw event is missing 'type' or 'event_type'"
            )

        category, severity, title = EVENT_TYPE_MAP.get(event_type, _FALLBACK)

        # --- asset (host the event happened on) ---
        host_block = raw_data.get("host")
        hostname = _first(raw_data, "hostname")
        host_ip = _first(raw_data, "host_ip")
        if isinstance(host_block, dict):
            hostname = hostname or host_block.get("hostname")
            host_ip = host_ip or host_block.get("ip")
        asset = AssetInfo(hostname=hostname, ip=host_ip) if (hostname or host_ip) else None

        # --- actor (who/where the event came from) ---
        actor_ip = _first(raw_data, "src_ip", "source_ip")
        actor_user = _first(raw_data, "user", "user_name")
        actor = ActorInfo(ip=actor_ip, user=actor_user) if (actor_ip or actor_user) else None

        observables = self._extract_observables(raw_data, hostname=hostname, host_ip=host_ip)

        return NormalizedAlert(
            event_type=event_type,
            source=self.source,
            category=category,
            severity=severity,
            title=title,
            description=_first(raw_data, "message", "description"),
            asset=asset,
            actor=actor,
            observables=observables,
            raw_event=raw_data,
        )

    @staticmethod
    def _extract_observables(
        raw: dict, *, hostname: str | None, host_ip: str | None
    ) -> list[Observable]:
        # scenario events carry extra details in a nested "raw_data" block
        nested = raw.get("raw_data") if isinstance(raw.get("raw_data"), dict) else {}

        def pick(*keys: str):
            return _first(raw, *keys) if _first(raw, *keys) is not None else _first(nested, *keys)

        seen: set[tuple[str, str]] = set()
        observables: list[Observable] = []

        def add(obs_type: str, value) -> None:
            if value is None:
                return
            value = str(value)
            key = (obs_type, value)
            if key not in seen:
                seen.add(key)
                observables.append(Observable(type=obs_type, value=value))

        add("ip", _first(raw, "src_ip", "source_ip"))
        add("ip", host_ip)
        add("hostname", hostname)
        add("user", _first(raw, "user", "user_name"))
        add("process", pick("process", "process_name"))
        add("file", pick("file", "file_path", "path"))

        # IOC payload, e.g. {"ioc_type": "ip", "ioc_value": "198.51.100.77"}
        ioc_type = pick("ioc_type")
        ioc_value = pick("ioc_value")
        if ioc_type and ioc_value:
            add(str(ioc_type), ioc_value)

        # file integrity hashes
        for hash_key in ("hash_after", "hash_before"):
            add("hash", pick(hash_key))

        return observables
