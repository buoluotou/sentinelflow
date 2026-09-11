"""Adapter Read Contract.

The pure, read-only abstraction the Manual Reconcile pipeline calls to ask one
external system: "what state is the object this execution references right now?".
It is the read-side mirror of the write-side ``ResponseExecutor``
(``app.services.executions.base``) — and the two are physically isolated::

WRITE side (services/executions/)     READ side (services/manual_reconcile/)
ResponseExecutor.execute / compensate  ReadAdapter.read
POST / mutate the external world       GET / query the external world only

This contract can only express "read external state". It structurally cannot
``execute`` / ``compensate`` / ``dispatch`` / ``trigger`` / ``create_case`` /
``send_command``: those verbs belong to the write side and never appear on a
ReadAdapter. ``read`` is the sole verb.

No HTTP, no DB, no mapping in this module — it defines shapes only:
- ``AdapterReadResult`` carries the raw ``external_state`` and no outcome word.
Mapping ``external_state`` -> {confirmed_success / confirmed_failure /
pending / unknown} is ``normalize_external_state``'s job and is never done
here. There is no ``outcome_status`` field.
- Concrete readers (Shuffle / Wazuh / TheHive) have no runtime evidence yet, and
``mock`` has no external system and is never reconcilable. No concrete
production ReadAdapter exists, so the registry rejects every adapter.

Allowed imports here are stdlib shape primitives only (``uuid`` / ``datetime`` /
``dataclasses`` / ``abc`` / ``collections.abc`` / ``typing``) — no SQLAlchemy, no
HTTP client, no FastAPI, no write-adapter module.
"""
from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class AdapterReadRequest:
    """The input to a read adapter. Immutable: a reader never mutates the
request; it produces a separate ``AdapterReadResult``.

Carries read-only context only:
- ``execution_id`` — the execution chain key (UUID);
- ``adapter`` — the adapter identity, taken from the historical Dispatch
Fact ``detail["executor"]``;
- ``external_reference`` — the external-object handle, taken from
``detail`` (Shuffle ``external_execution_id`` / Wazuh ``command_id`` /
TheHive ``case_id``).

It carries no operator credential, no callback token and no write intent:
those live in other trust domains and never travel in a read request. The
adapter API credential used to actually reach the external system comes from
server config at the concrete-reader layer, never from this request.
"""

    execution_id: uuid.UUID
    adapter: str
    external_reference: str


@dataclass(frozen=True)
class AdapterReadResult:
    """The output of a read adapter. Immutable.

Carries the raw external state and nothing interpreted:
- ``external_state`` — the state value the external system returned, kept
raw (``str`` word or a small structured ``Mapping``). It is never an
outcome word here; mapping to the five-word outcome vocabulary is the
mapper's job.
- ``observed_at`` — the external system's reliable state timestamp when it
provides one; ``None`` when it does not, signalling that the platform
must supply a server observation time (a fact observation time, never an
external event time).
- ``raw_evidence`` — a read-only snapshot of what was observed. Secret
redaction (``redact_detail``) happens before this ever reaches an Outcome
``detail``; this contract neither stores nor writes.

There is no ``outcome_status`` field: an adapter read yields external state,
and the outcome vocabulary belongs to mapping.
"""

    external_state: str | Mapping[str, Any]
    observed_at: datetime | None
    raw_evidence: Mapping[str, Any]


class ReadAdapter(ABC):
    """One external-system read adapter. The read-side mirror of
``ResponseExecutor`` — physically isolated from it: a ReadAdapter can only
read / query external state; it can never execute / compensate / dispatch /
trigger / create_case / send_command. Those verbs do not exist on this
contract; ``read`` is the sole abstract verb (besides the ``name`` identity).

No concrete production ReadAdapter exists: the Shuffle / Wazuh / TheHive read
paths have no runtime evidence yet, and ``mock`` has no external system and is
never reconcilable. The ``ReadAdapterRegistry`` therefore rejects every
adapter today.

A test-only ``FakeReadAdapter`` may subclass this to exercise the platform
pipeline, but is never registered into the production default registry.
"""

    @property
    @abstractmethod
    def name(self) -> str:
        """Adapter identity — never impersonated (mirrors ``ResponseExecutor.name``)."""

    @abstractmethod
    def read(self, request: AdapterReadRequest) -> AdapterReadResult:
        """Read the current external state of the object ``request`` references.

Returns the raw external state (``AdapterReadResult``) — never an outcome
word, never a fact write, never a mutation of the external system (read /
query only). May raise a transport-level failure (timeout / connection
refused / DNS failure / HTTP 5xx / adapter unavailable); the Manual
Reconcile pipeline maps such a failure to ``reconciliation_failed`` — that
mapping is not done here.
"""
