"""ReadAdapterRegistry (Phase 3.4.5-A1, design §8/§15/§16).

The READ-side mirror of the WRITE-side ``create_executor`` registry — with the
SAME fail-closed philosophy: the registry REFUSES to fake a reader. It resolves
an adapter identity to a concrete ``ReadAdapter``; when no reader is registered it
raises ``UnsupportedAdapterRead`` — a REJECTION (no Outcome Fact), NEVER a
fabricated result, NEVER ``None`` (design §8/§17).

3.4.5-A1 ships an EMPTY production registry (design §15/§16): NO concrete reader
exists for ``shuffle`` / ``wazuh`` / ``thehive`` (their read paths are Evidence
Gaps, 3.4.5-B/C/D) and ``mock`` is never reconcilable (design §14). So
``default_read_adapter_registry()`` has ZERO entries and EVERY lookup — mock,
shuffle, wazuh, thehive, or an unknown name — raises ``UnsupportedAdapterRead``.
A concrete reader registers here ONLY when 3.4.5-B/C/D lands with real external
evidence. A test-only ``FakeReadAdapter`` is NEVER registered into the production
default registry (design §18).

NO HTTP, NO DB, NO credentials here (design §11/§12/§13): the registry owns no
secret and issues no request; it only resolves a name to a reader object.
"""
from __future__ import annotations

from collections.abc import Iterable

from app.services.manual_reconcile.exceptions import UnsupportedAdapterRead
from app.services.manual_reconcile.read.base import ReadAdapter


class ReadAdapterRegistry:
    """``adapter name -> ReadAdapter``. Immutable after construction.

    - deterministic lookup (a name always resolves to the same reader);
    - duplicate registration is a CONSTRUCTION error (``ValueError``), never a
      silent overwrite (design §8 — one adapter, one reader, no ambiguity);
    - an unregistered adapter raises ``UnsupportedAdapterRead`` (never ``None``,
      never a fake — the registry refuses to invent support).
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

        NEVER returns ``None`` and NEVER fakes a reader (design §8). An unknown
        name, ``mock``, or an Evidence-Gapped real adapter (``shuffle`` /
        ``wazuh`` / ``thehive`` in 3.4.5-A1) all raise ``UnsupportedAdapterRead``
        — a rejection, NO Outcome Fact, NO external contact (design §14/§16).
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
    """The PRODUCTION read-adapter registry for 3.4.5-A1: EMPTY (design §15/§16).

    No concrete read adapter exists yet — Shuffle / Wazuh / TheHive are Evidence
    Gaps (3.4.5-B/C/D) and ``mock`` is never reconcilable. Every lookup therefore
    rejects with ``UnsupportedAdapterRead``. This is the honest fail-closed state:
    the platform does NOT fabricate an external read it cannot yet perform.
    """
    return ReadAdapterRegistry()
