"""Executor DTOs + vocabularies.

Two server-side DTOs and two vocabularies:

- ``ExecutionDispatch`` — what SentinelFlow hands TO an adapter. Assembled
exclusively by the server from the approved recommendation snapshot;
no client input ever reaches an adapter. extra=forbid.
- ``ExecutionOutcome`` — what an adapter hands BACK. status is
{succeeded, failed} only — ``dispatched`` is a platform log state,
never an adapter product. extra=forbid.

Adapters never self-declare ``protocol_violation``: structural
violations are judged by the platform parse in ``protocol.py``.
"""
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

# Adapter terminal statuses. `dispatched` is absent — it is written by
# the SentinelFlow Execution Service, never by an adapter.
OUTCOME_STATUSES = frozenset({"succeeded", "failed"})

# Failure-classification vocabulary. Written into the failed row's detail
# by the Execution Service; adapters may classify themselves with the
# first three words only — the fourth (protocol_violation) is reserved to
# the platform parse.
FAILURE_CLASSIFICATIONS = frozenset(
    {"adapter_unavailable", "timeout", "adapter_error", "protocol_violation"}
)
ADAPTER_CLASSIFICATIONS = FAILURE_CLASSIFICATIONS - {"protocol_violation"}


class ExecutionDispatch(BaseModel):
    """Server-side DTO handed to an adapter.

Every field is assembled by the server from the approved
recommendation snapshot + the Execute Intent — the client request
schema accepts none of them. extra=forbid so no smuggled field can
ride along."""

    model_config = ConfigDict(extra="forbid")

    execution_id: uuid.UUID
    action: str
    target: str
    approval_id: uuid.UUID


class ExecutionOutcome(BaseModel):
    """Adapter result. extra=forbid; status restricted to the adapter
vocabulary. ``detail`` carries the adapter's classification / DryRun
echo; ``raw_response`` the verbatim adapter answer (audit)."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["succeeded", "failed"]
    detail: dict[str, Any] = {}
    raw_response: Any = None
