"""ReadAdapterRegistry.

The read-side mirror of the write-side ``create_executor`` registry, with the same
fail-closed behaviour: the registry does not fake a reader. It resolves an adapter
identity to a concrete ``ReadAdapter``; when no reader is registered it raises
``UnsupportedAdapterRead`` — a rejection (no Outcome Fact), never a fabricated
result, never ``None``.

The production registry is empty: no concrete reader exists for ``shuffle`` /
``wazuh`` / ``thehive`` (their read paths have no runtime evidence yet) and
``mock`` is never reconcilable. So ``default_read_adapter_registry()`` has zero
entries and every lookup — mock, shuffle, wazuh, thehive, or an unknown name —
raises ``UnsupportedAdapterRead``. A concrete reader registers here only for a
deployment with real external evidence. A test-only ``FakeReadAdapter`` is never
registered into the production default registry.

No HTTP, no DB, no credentials here: the registry owns no secret and issues no
request; it only resolves a name to a reader object.
"""
from __future__ import annotations

from collections.abc import Iterable

from app.services.manual_reconcile.exceptions import UnsupportedAdapterRead
from app.services.manual_reconcile.read.base import ReadAdapter


class ReadAdapterRegistry:
    """``adapter name -> ReadAdapter``. Immutable after construction.

- deterministic lookup (a name always resolves to the same reader);
- duplicate registration is a construction error (``ValueError``), never a
silent overwrite (one adapter, one reader, no ambiguity);
- an unregistered adapter raises ``UnsupportedAdapterRead`` (never ``None``,
never a fake — the registry does not invent support).
"""

    def __init__(self, readers: Iterable[ReadAdapter] = ()) -> None:
        self._readers: dict[str, ReadAdapter] = {}
        for reader in readers:
            name = reader.name
            if name in self._readers:
                raise ValueError(
                    f"duplicate read adapter registration for {name!r}"
                )
            self._readers[name] = reader

    def get(self, adapter: str) -> ReadAdapter:
        """Resolve a concrete reader, or raise ``UnsupportedAdapterRead``.

Never returns ``None`` and never fakes a reader. An unknown name,
``mock``, or an adapter whose read path has no runtime evidence
(``shuffle`` / ``wazuh`` / ``thehive``) all raise
``UnsupportedAdapterRead`` — a rejection: no Outcome Fact, no external
contact.
"""
        try:
            return self._readers[adapter]
        except KeyError:
            raise UnsupportedAdapterRead(
                f"no read adapter registered for adapter {adapter!r}",
                adapter=adapter,
            ) from None

    def is_supported(self, adapter: str) -> bool:
        """Whether a concrete reader exists for ``adapter`` (never raises)."""
        return adapter in self._readers

    def registered_adapters(self) -> tuple[str, ...]:
        """The registered adapter names, in deterministic insertion order."""
        return tuple(self._readers)


def default_read_adapter_registry() -> ReadAdapterRegistry:
    """The production read-adapter registry: empty.

No concrete read adapter exists yet — Shuffle / Wazuh / TheHive have no
runtime evidence and ``mock`` is never reconcilable. Every lookup therefore
rejects with ``UnsupportedAdapterRead``. This is the fail-closed state: the
platform does not fabricate an external read it cannot yet perform.
"""
    return ReadAdapterRegistry()
