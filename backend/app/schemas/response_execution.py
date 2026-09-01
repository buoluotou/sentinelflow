"""Pydantic schemas of the response-execution API (Phase 3.1.7, operator
optional since 3.3.1).

The client expresses Intent ONLY: identity keys (execution_id /
approval_id / compensates_execution_id). The operator identity is
resolved server-side from the Bearer token (Phase 3.3.1); the optional
``operator`` field in the request body is accepted for backwards
compatibility but IGNORED — the authenticated operator name is the
only source of truth. Every execution fact — action, target, direction,
decisions, audit clock — is a server-side construct. extra="forbid"
makes any smuggling attempt (action / target / direction / detail /
created_at / status ...) a 422 at the schema boundary, before the
Service ever runs.
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
    # 3.3.1: operator is optional and IGNORED when present — the server
    # resolves identity from the Bearer token. Kept optional (not
    # removed) so existing clients that send it still get a 200; the
    # authenticated operator name is the only source of truth.
    operator: str | None = Field(default=None, max_length=128)
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
    # 3.3.1: optional and ignored (same rule as ExecuteRequest.operator).
    operator: str | None = Field(default=None, max_length=128)
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


# --------------------------------------------------------------------------
# Metrics read-model views (Phase 3.3.3.2)
#
# EXACT mirrors of the three frozen dataclasses in
# services/executions/metrics.py — no second DTO design, no renaming,
# no reshaping: model_validate() serializes the read model field for
# field. Rates keep the frozen None semantics (JSON null on an empty
# denominator), never a fake percentage.
# --------------------------------------------------------------------------
class LatencyStatsRead(BaseModel):
    """Mirror of metrics.LatencyStats — adapter-run time of chains that
    reached a terminal executor outcome."""

    model_config = ConfigDict(from_attributes=True)

    count: int
    average_seconds: float | None
    min_seconds: float | None
    max_seconds: float | None


class AdapterMetricsRead(BaseModel):
    """Mirror of metrics.AdapterMetrics — observed health of ONE adapter
    (adapter identity is the server-recorded detail.executor fact, never
    client-supplied)."""

    model_config = ConfigDict(from_attributes=True)

    adapter: str
    total_chains: int
    succeeded: int
    failed: int
    guard_rejected: int
    in_flight: int
    success_rate: float | None
    failure_classifications: dict[str, int]


class ExecutionMetricsRead(BaseModel):
    """Mirror of metrics.ExecutionMetrics — the whole-platform read model
    over direction='execute' chains (GET /executions/metrics body)."""

    model_config = ConfigDict(from_attributes=True)

    total_chains: int
    executed_chains: int
    succeeded: int
    failed: int
    guard_rejected: int
    in_flight: int
    success_rate: float | None
    executor_failure_rate: float | None
    guard_rejection_rate: float | None
    rejections_by_source: dict[str, int]
    failure_classifications: dict[str, int]
    latency: LatencyStatsRead
    by_adapter: dict[str, AdapterMetricsRead]


# --------------------------------------------------------------------------
# Observed-health views (Phase 3.3.3.3.2)
#
# EXACT mirrors of the three frozen dataclasses in
# services/executions/health.py — Read mirrors only, no second model
# (no HealthResponse / HealthItem / AdapterStatus). The verdict word
# stays ``observed_status``: it must NEVER degrade into a boolean
# ``healthy`` flag, which would be misread as a live probe result.
# --------------------------------------------------------------------------
class RecentFailureRead(BaseModel):
    """Mirror of health.RecentFailure — one failed chain inside the
    recent window."""

    model_config = ConfigDict(from_attributes=True)

    execution_id: uuid.UUID
    classification: str | None
    failed_at: datetime


class AdapterHealthRead(BaseModel):
    """Mirror of health.AdapterHealth — one adapter's observed health
    (recent window + all-time facts + last execution)."""

    model_config = ConfigDict(from_attributes=True)

    adapter: str
    observed_status: str
    window_size: int
    window_succeeded: int
    window_failed: int
    window_success_rate: float | None
    timeout_count: int
    unavailable_count: int
    protocol_violation_count: int
    recent_failures: list[RecentFailureRead]
    total_chains: int
    all_time_succeeded: int
    all_time_failed: int
    all_time_guard_rejected: int
    all_time_in_flight: int
    last_execution_at: datetime | None
    last_execution_state: str | None


class ObservedHealthRead(BaseModel):
    """Mirror of health.ObservedHealth — the GET /executions/health
    body. ``generated_at`` is the only wall-clock field and the only
    one allowed to differ between identical follow-up calls."""

    model_config = ConfigDict(from_attributes=True)

    generated_at: datetime
    window_size: int
    adapters: dict[str, AdapterHealthRead]
