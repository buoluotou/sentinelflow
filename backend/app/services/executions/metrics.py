"""Execution Metrics read model (Phase 3.3.3.1).

Metrics are a READ MODEL over execution facts — never a second source
of truth:

    execution_log -> Metrics Service -> (future) GET /executions/metrics

Frozen discipline:

- Pure read: ONE SELECT over execution_log; NO add / flush / commit /
  rollback, no writes of any kind. The same rows in, the same numbers
  out — deterministic by construction.
- execution_log is the SOLE fact source: every counter, rate and
  classification is derived from stored rows (decision, direction,
  detail, created_at). There is no metrics table and no new column —
  the log's schema is untouched.
- Adapter identity is a server-recorded fact: it comes from the
  chain's ``requested`` row ``detail.executor`` (chosen by
  EXECUTION_ADAPTER -> registry -> actual executor). A client has no
  field through which it could claim an adapter.
- Guard refusals are GOVERNANCE, not adapter health: guard_rejected
  chains never reached the Executor, so they are counted separately
  and NEVER pollute the adapter success/failure rates.

Rate definitions (frozen):

    success_rate          = succeeded / (succeeded + failed)
                            (chains with a terminal EXECUTOR outcome;
                            requested / dispatched are non-terminal and
                            guard_rejected never touched the adapter)
    executor_failure_rate = failed / (succeeded + failed)
    guard_rejection_rate  = guard_rejected / total chains
                            (a governance metric: many guard refusals
                            point at Policy / Approval / RBAC, many
                            failures point at the adapter)

Rates are None (undefined) whenever their denominator is zero — the
empty dataset is explicit, never a fake 0% or 100%.

Latency is derived from the log's frozen server-stamped created_at
(high-water mark clause): for chains that reached a terminal executor
outcome it is ``terminal.created_at - dispatched.created_at`` — the
time the adapter actually spent. Chains rejected before dispatch have
no adapter time and are excluded.

Scope: direction="execute" chains only. Compensation chains are a
separate direction with their own vocabulary and are not part of this
read model. In-flight chains (derived state requested / dispatched)
count toward totals only — never toward outcome rates.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.execution_log import ExecutionLog
from app.services.executions.models import FAILURE_CLASSIFICATIONS
from app.services.executions.state import derive_execution_state

#: Terminal EXECUTOR outcomes — the only states that feed the adapter
#: success/failure rates.
_TERMINAL_EXECUTOR_OUTCOMES = frozenset({"succeeded", "failed"})

#: Derived states that are NOT outcomes: requested/dispatched are
#: in-flight, compensation words belong to the other direction.
#: guard_rejected is governance — counted separately.

#: Adapter identity for chains whose requested row carries no usable
#: detail.executor (legacy / corrupted data). Derived placeholder only
#: — never client-supplied.
UNKNOWN_ADAPTER = "unknown"


#: The empty immutable mapping shared by every default field below.
_EMPTY: Mapping[str, int] = MappingProxyType({})


@dataclass(frozen=True)
class LatencyStats:
    """Adapter-run time of chains that reached a terminal executor
    outcome: terminal.created_at - dispatched.created_at, in seconds."""

    count: int = 0
    average_seconds: float | None = None
    min_seconds: float | None = None
    max_seconds: float | None = None


@dataclass(frozen=True)
class AdapterMetrics:
    """Observed health of ONE adapter, derived from its execute chains.

    ``success_rate`` is undefined (None) when no chain of this adapter
    reached a terminal executor outcome."""

    adapter: str
    total_chains: int = 0
    succeeded: int = 0
    failed: int = 0
    guard_rejected: int = 0
    in_flight: int = 0
    success_rate: float | None = None
    failure_classifications: Mapping[str, int] = field(default_factory=lambda: _EMPTY)


@dataclass(frozen=True)
class ExecutionMetrics:
    """The whole-platform read model over direction='execute' chains."""

    total_chains: int = 0
    #: Chains with a terminal executor outcome (succeeded + failed).
    executed_chains: int = 0
    succeeded: int = 0
    failed: int = 0
    guard_rejected: int = 0
    #: Chains whose derived state is still requested / dispatched.
    in_flight: int = 0
    success_rate: float | None = None
    executor_failure_rate: float | None = None
    guard_rejection_rate: float | None = None
    #: guard_rejected chains split by provenance (detail.source):
    #: "guard" (structural refusal) vs "policy" (3.3.2 governance).
    rejections_by_source: Mapping[str, int] = field(default_factory=lambda: _EMPTY)
    failure_classifications: Mapping[str, int] = field(default_factory=lambda: _EMPTY)
    latency: LatencyStats = field(default_factory=LatencyStats)
    by_adapter: Mapping[str, AdapterMetrics] = field(default_factory=lambda: _EMPTY)


def _rate(numerator: int, denominator: int) -> float | None:
    """Frozen rate semantics: undefined (None) on a zero denominator —
    the empty set is never reported as a fake percentage."""
    if denominator == 0:
        return None
    return numerator / denominator


def _classification_of(row: ExecutionLog) -> str | None:
    """The failure classification of a failed terminal row, validated
    against the frozen vocabulary; None when absent or foreign (a
    foreign word is counted nowhere — the vocabulary is closed)."""
    detail = row.detail if isinstance(row.detail, dict) else {}
    classification = detail.get("classification")
    if classification in FAILURE_CLASSIFICATIONS:
        return classification
    return None


def _adapter_of(rows: list[ExecutionLog]) -> str:
    """The chain's adapter — the detail.executor recorded by the Server
    in the requested row. Never reconstructed from client input."""
    first = rows[0]
    detail = first.detail if isinstance(first.detail, dict) else {}
    executor = detail.get("executor")
    if isinstance(executor, str) and executor:
        return executor
    return UNKNOWN_ADAPTER


def _count(mapping: dict[str, int], key: str) -> None:
    mapping[key] = mapping.get(key, 0) + 1


def collect_execution_metrics(session: Session) -> ExecutionMetrics:
    """Derive the execution metrics read model from execution_log.

    ONE read-only SELECT, no writes, no executor calls, no outbound
    traffic. The result is a pure function of the stored rows —
    calling it twice over an unchanged log returns equal objects."""
    rows = list(
        session.scalars(
            select(ExecutionLog)
            .where(ExecutionLog.direction == "execute")
            .order_by(
                ExecutionLog.execution_id,
                ExecutionLog.created_at.asc(),
                ExecutionLog.id.asc(),
            )
        )
    )

    chains: dict = {}
    for row in rows:
        chains.setdefault(row.execution_id, []).append(row)

    total = 0
    succeeded = 0
    failed = 0
    guard_rejected = 0
    in_flight = 0
    rejections_by_source: dict[str, int] = {}
    classifications: dict[str, int] = {}
    latencies: list[float] = []
    adapters: dict[str, dict] = {}

    for chain in chains.values():
        total += 1
        adapter = _adapter_of(chain)
        bucket = adapters.setdefault(
            adapter,
            {
                "total": 0,
                "succeeded": 0,
                "failed": 0,
                "guard_rejected": 0,
                "in_flight": 0,
                "classifications": {},
            },
        )
        bucket["total"] += 1

        state = derive_execution_state(chain)
        if state == "succeeded":
            succeeded += 1
            bucket["succeeded"] += 1
        elif state == "failed":
            failed += 1
            bucket["failed"] += 1
            terminal = chain[-1]
            classification = _classification_of(terminal)
            if classification is not None:
                _count(classifications, classification)
                _count(bucket["classifications"], classification)
        elif state == "guard_rejected":
            guard_rejected += 1
            bucket["guard_rejected"] += 1
            terminal = chain[-1]
            detail = terminal.detail if isinstance(terminal.detail, dict) else {}
            source = detail.get("source")
            if isinstance(source, str) and source:
                _count(rejections_by_source, source)
        else:
            # requested / dispatched: in flight — counts toward totals
            # only, never toward outcome rates.
            in_flight += 1
            bucket["in_flight"] += 1

        # Adapter-run latency: dispatched -> terminal executor outcome.
        if state in _TERMINAL_EXECUTOR_OUTCOMES:
            dispatched = next(
                (row for row in chain if row.decision == "dispatched"), None
            )
            if dispatched is not None:
                span = (chain[-1].created_at - dispatched.created_at).total_seconds()
                latencies.append(span)

    executed = succeeded + failed
    adapter_metrics = {}
    for name in sorted(adapters):
        bucket = adapters[name]
        adapter_executed = bucket["succeeded"] + bucket["failed"]
        adapter_metrics[name] = AdapterMetrics(
            adapter=name,
            total_chains=bucket["total"],
            succeeded=bucket["succeeded"],
            failed=bucket["failed"],
            guard_rejected=bucket["guard_rejected"],
            in_flight=bucket["in_flight"],
            success_rate=_rate(bucket["succeeded"], adapter_executed),
            failure_classifications=MappingProxyType(dict(bucket["classifications"])),
        )

    return ExecutionMetrics(
        total_chains=total,
        executed_chains=executed,
        succeeded=succeeded,
        failed=failed,
        guard_rejected=guard_rejected,
        in_flight=in_flight,
        success_rate=_rate(succeeded, executed),
        executor_failure_rate=_rate(failed, executed),
        guard_rejection_rate=_rate(guard_rejected, total),
        rejections_by_source=MappingProxyType(dict(rejections_by_source)),
        failure_classifications=MappingProxyType(dict(classifications)),
        latency=LatencyStats(
            count=len(latencies),
            average_seconds=(sum(latencies) / len(latencies)) if latencies else None,
            min_seconds=min(latencies) if latencies else None,
            max_seconds=max(latencies) if latencies else None,
        ),
        by_adapter=MappingProxyType(adapter_metrics),
    )
