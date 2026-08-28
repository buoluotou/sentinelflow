"""Executor DTOs + frozen vocabularies (Phase 3.1.5, design §8).

Two server-side frozen DTOs and two vocabularies:

- ``ExecutionDispatch`` — what SentinelFlow hands TO an adapter. Assembled
  exclusively by the server from the approved recommendation snapshot;
  zero client input ever reaches an adapter. extra=forbid.
- ``ExecutionOutcome`` — what an adapter hands BACK. status is
  {succeeded, failed} only — ``dispatched`` is a PLATFORM log state,
  never an adapter product (D8). extra=forbid.

Adapters never self-declare ``protocol_violation`` (D9): structural
violations are judged by the platform parse in ``protocol.py``.
"""
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

#: Adapter terminal statuses (D8). `dispatched` deliberately absent — it
#: is written by the SentinelFlow Execution Service, never by an adapter.
OUTCOME_STATUSES = frozenset({"succeeded", "failed"})

#: Frozen failure-classification vocabulary (design §8). Written into the
#: failed row's detail by the Execution Service (3.1.6); adapters may
#: classify themselves with the first three words only — the fourth
#: (protocol_violation) is reserved to the platform parse (D9).
FAILURE_CLASSIFICATIONS = frozenset(
    {"adapter_unavailable", "timeout", "adapter_error", "protocol_violation"}
)
ADAPTER_CLASSIFICATIONS = FAILURE_CLASSIFICATIONS - {"protocol_violation"}


class ExecutionDispatch(BaseModel):
    """Server-side frozen DTO handed to an adapter (design §8).

    Every field is assembled by the server from the approved
    recommendation snapshot + the Execute Intent — the client request
    schema accepts none of them. extra=forbid so no smuggled field can
    ever ride along."""

    model_config = ConfigDict(extra="forbid")

    execution_id: uuid.UUID
    action: str
    target: str
    approval_id: uuid.UUID


class ExecutionOutcome(BaseModel):
    """Adapter result (design §8). extra=forbid; status restricted to the
    adapter vocabulary. ``detail`` carries the adapter's classification /
    DryRun echo; ``raw_response`` the verbatim adapter answer (audit)."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["succeeded", "failed"]
    detail: dict[str, Any] = {}
    raw_response: Any = None
