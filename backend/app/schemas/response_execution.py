"""Pydantic schemas of the response-execution API (Phase 3.1.7).

The client expresses Intent ONLY: identity keys (execution_id /
approval_id / compensates_execution_id) and who asked (operator). Every
execution fact — action, target, direction, decisions, audit clock — is
a server-side construct. extra="forbid" makes any smuggling attempt
(action / target / direction / detail / created_at / status ...) a 422
at the schema boundary, before the Service ever runs.
"""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ExecuteRequest(BaseModel):
    """Body of POST /executions — the Execute Intent, nothing more.

    extra="forbid" is the schema-level guard against fact-smuggling: the
    approved recommendation's action/target snapshot is resolved by the
    Service, never accepted here (frozen trust boundary, design §9).
    """

    model_config = ConfigDict(extra="forbid")

    execution_id: uuid.UUID
    approval_id: uuid.UUID
    operator: str = Field(min_length=1, max_length=128)
    comment: str | None = Field(default=None, max_length=512)


class CompensateRequest(BaseModel):
    """Body of POST /executions/compensate — the Compensation Intent.

    approval_id is deliberately ABSENT: the Service inherits it from the
    original execution server-side (D11) — a client-supplied approval_id
    is rejected by extra="forbid" exactly like any smuggled fact.
    """

    model_config = ConfigDict(extra="forbid")

    execution_id: uuid.UUID
    compensates_execution_id: uuid.UUID
    operator: str = Field(min_length=1, max_length=128)
    comment: str | None = Field(default=None, max_length=512)


class ExecutionLogRowRead(BaseModel):
    """One immutable audit row, rendered exactly as stored."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    execution_id: uuid.UUID
    approval_id: uuid.UUID
    decision: str
    direction: str
    action: str
    target: str
    operator: str
    detail: dict
    compensates_execution_id: uuid.UUID | None
    created_at: datetime


class ExecutionRead(BaseModel):
    """The 201 body of both write endpoints and the GET detail body.

    201 means the Intent formed an execution FACT — it does NOT mean the
    underlying action succeeded: ``derived_state`` carries the verdict
    (succeeded / failed / guard_rejected / compensation_*), straight from
    the frozen derive_execution_state rule, never recomputed here.
    """

    execution_id: uuid.UUID
    approval_id: uuid.UUID
    direction: str
    action: str
    target: str
    derived_state: str
    chain: list[str]
    history: list[ExecutionLogRowRead]


class ExecutionSummaryRead(BaseModel):
    """One GET /executions list entry: identity + derived state of one
    execution chain (executions and compensations listed separately —
    each has its own execution_id)."""

    execution_id: uuid.UUID
    approval_id: uuid.UUID
    direction: str
    action: str
    target: str
    operator: str
    derived_state: str
    chain: list[str]
    created_at: datetime
    last_decision_at: datetime


class ExecutionListResponse(BaseModel):
    """GET /executions — paged audit list envelope (Phase 3.1.9), mirrors
    the IncidentListResponse / EventListResponse shape: the filtered
    total plus the requested page, most recent activity first."""

    total: int
    page: int
    size: int
    items: list[ExecutionSummaryRead]
