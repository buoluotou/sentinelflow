"""Adapter Read Contract (Phase 3.4.5-A1, design §4/§5/§7/§8).

The PURE, read-only abstraction the Manual Reconcile pipeline (3.4.5-A2) will
call to ask ONE external system: "what state is the object this execution
references in RIGHT NOW?". It is the READ-side mirror of the WRITE-side
``ResponseExecutor`` (``app.services.executions.base``) — and the two are
PHYSICALLY ISOLATED (design §8)::

    WRITE side (services/executions/)     READ side (services/manual_reconcile/)
    ResponseExecutor.execute / compensate  ReadAdapter.read
    POST / mutate the external world       GET / query the external world ONLY

This contract can ONLY express "read external state". It structurally CANNOT
``execute`` / ``compensate`` / ``dispatch`` / ``trigger`` / ``create_case`` /
``send_command`` (design §5/§7.3): those verbs belong to the write side and never
appear on a ReadAdapter. ``read`` is the SOLE verb.

NO HTTP, NO DB, NO mapping in this module (design §12/§13/§19) — it defines
SHAPES only:
  - ``AdapterReadResult`` carries the RAW ``external_state`` and NO outcome word.
    Mapping ``external_state`` -> {confirmed_success / confirmed_failure /
    pending / unknown} is 3.4.3-B's ``normalize_external_state`` and is NEVER
    done here (design §4/§19). There is deliberately NO ``outcome_status`` field.
  - Concrete readers (Shuffle / Wazuh / TheHive) are Evidence-Gapped (design §16)
    and land in 3.4.5-B/C/D; ``mock`` has no external system and is never
    reconcilable (design §14/§15). NO concrete production ReadAdapter exists in
    A1 — the registry rejects every adapter (§8).

Allowed imports here are stdlib shape primitives ONLY (``uuid`` / ``datetime`` /
``dataclasses`` / ``abc`` / ``collections.abc`` / ``typing``) — no SQLAlchemy, no
HTTP client, no FastAPI, no write-adapter module (design §16).
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
    """The frozen INPUT to a read adapter (design §7.1). Immutable: a reader
    NEVER mutates the request; it produces a separate ``AdapterReadResult``.

    Carries ONLY read-only context:
      - ``execution_id`` — the execution chain key (UUID);
      - ``adapter`` — the adapter identity, taken from the historical Dispatch
        Fact ``detail["executor"]`` (design §6.1);
      - ``external_reference`` — the external-object handle, taken from
        ``detail`` (Shuffle ``external_execution_id`` / Wazuh ``command_id`` /
        TheHive ``case_id`` — design §6.2).

    It deliberately carries NO operator credential, NO callback token, NO write
    intent (design §3/§9): those live in other trust domains and NEVER travel in
    a read request. The adapter API credential used to actually reach the
    external system comes from SERVER CONFIG at the concrete-reader layer
    (3.4.5-B/C/D), never from this request (design §9/§11).
    """

    execution_id: uuid.UUID
    adapter: str
    external_reference: str


@dataclass(frozen=True)
class AdapterReadResult:
    """The frozen OUTPUT of a read adapter (design §7.2). Immutable.

    Carries the RAW external state and NOTHING interpreted:
      - ``external_state`` — the state value the external system returned, kept
        RAW (``str`` word or a small structured ``Mapping``). It is NEVER an
        outcome word here; mapping to the five-word outcome vocabulary is
        3.4.3-B's job (design §4/§19/§24).
      - ``observed_at`` — the external system's reliable state timestamp when it
        provides one; ``None`` when it does not, signalling that the A2 platform
        must supply a SERVER OBSERVATION time (a FACT observation time, never an
        external event time — design §9/§12).
      - ``raw_evidence`` — a read-only snapshot of what was observed. Secret
        redaction (``redact_detail``) happens in A2 BEFORE this ever reaches an
        Outcome ``detail`` (design §13); this contract neither stores nor writes.

    There is deliberately NO ``outcome_status`` field (design §4, test #25):
    Adapter Read = External State; the outcome vocabulary belongs to Mapping.
    """

    external_state: str | Mapping[str, Any]
    observed_at: datetime | None
    raw_evidence: Mapping[str, Any]


class ReadAdapter(ABC):
    """ONE external-system read adapter (design §5/§7/§8). The READ-side mirror
    of ``ResponseExecutor`` — physically isolated from it: a ReadAdapter can ONLY
    read / query external state; it can NEVER execute / compensate / dispatch /
    trigger / create_case / send_command. Those verbs do not exist on this
    contract; ``read`` is the SOLE abstract verb (besides the ``name`` identity).

    NO concrete production ReadAdapter exists in 3.4.5-A1: Shuffle / Wazuh /
    TheHive read paths are Evidence-Gapped (design §16) and land in 3.4.5-B/C/D;
    ``mock`` has no external system and is never reconcilable (design §14/§15).
    The ``ReadAdapterRegistry`` therefore rejects every adapter today (§8).

    A test-only ``FakeReadAdapter`` (3.4.5-A2) MAY subclass this to exercise the
    platform pipeline, but is NEVER registered into the production default
    registry (design §18).
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Adapter identity — never impersonated (mirrors ``ResponseExecutor.name``)."""

    @abstractmethod
    def read(self, request: AdapterReadRequest) -> AdapterReadResult:
        """Read the CURRENT external state of the object ``request`` references.

        Returns the RAW external state (``AdapterReadResult``) — NEVER an outcome
        word, NEVER a fact write, NEVER a mutation of the external system (read /
        query ONLY). May raise a transport-level failure (timeout / connection
        refused / DNS failure / HTTP 5xx / adapter unavailable); the A2 pipeline
        maps such a failure to ``reconciliation_failed`` — that mapping is NOT
        done here (design §10/§19).
        """
