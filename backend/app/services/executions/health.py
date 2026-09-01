"""Adapter Observed-Health read model (Phase 3.3.3.3.1).

OBSERVED health, never ACTIVE health (frozen adjudication):

    execution_log -> Health read model

There is NO probe: this module never sends a request to Shuffle /
Wazuh / TheHive (or anywhere else), never calls an executor, never
writes. What it reports is "how the adapter behaved over its recent
executed chains", NOT "the adapter is online right now" — hence the
deliberate field name ``observed_status`` and the vocabulary below.

Frozen vocabulary (3.3.3.3.1 adjudication):

    OBSERVED_STATUSES = {healthy, degraded, failing, unknown}

Frozen judgement rule (recent-N terminal window, default N=20):

    unknown   no TERMINAL executor chain of this adapter was ever
              observed — nothing seen, nothing claimed
    healthy   window success_rate >= healthy_threshold (default 0.9)
    degraded  degraded_threshold <= success_rate < healthy_threshold
              (defaults 0.5 / 0.9)
    failing   success_rate < degraded_threshold

Frozen window basis: ONLY chains with a terminal EXECUTOR outcome
(succeeded / failed) enter the window. guard_rejected chains never
touched the adapter (governance refusals) and in-flight chains have no
outcome yet — both are excluded, so Policy / Approval / RBAC pressure
can NEVER be misattributed to an external system.

Recency ordering (frozen): a terminal chain's recency is its TERMINAL
row's ``(created_at, id)``; the window keeps the newest N. All-time
totals are counted separately so a long-lived adapter's full history
stays visible next to its recent window.

Pure-read discipline (same nail as metrics): ONE read-only SELECT over
execution_log; no add / flush / commit / rollback; the same rows in,
the same numbers out — the wall-clock stamp is injected as ``now`` so
the derivation itself is deterministic.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.execution_log import ExecutionLog
from app.services.executions.metrics import (
    _adapter_of,
    _classification_of,
    _rate,
)
from app.services.executions.state import derive_execution_state

#: Frozen observed-status vocabulary. Words are chosen to be impossible
#: to read as a live probe result: "observed_status = healthy" means
#: "recent executions went well", never "the adapter answers right now".
OBSERVED_STATUSES = frozenset({"healthy", "degraded", "failing", "unknown"})

#: The default recent-window size (configurable per call, validated).
DEFAULT_WINDOW_SIZE = 20


@dataclass(frozen=True)
class HealthThresholds:
    """Frozen success-rate bands for observed_status.

    Validation is eager and fail-closed (policy.py precedent): both
    bounds must be real ratios in [0, 1] (bool excluded) and the
    healthy band must start at or above the degraded band."""

    healthy: float = 0.9
    degraded: float = 0.5

    def __post_init__(self) -> None:
        for name in ("healthy", "degraded"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} threshold must be a ratio, got {value!r}")
            if not 0 <= value <= 1:
                raise ValueError(f"{name} threshold out of [0, 1]: {value!r}")
        if self.healthy < self.degraded:
            raise ValueError(
                f"healthy threshold ({self.healthy}) must be >= "
                f"degraded threshold ({self.degraded})"
            )


#: The default frozen bands (success-rate basis, 3.3.3.3.1 adjudication).
DEFAULT_THRESHOLDS = HealthThresholds()


@dataclass(frozen=True)
class RecentFailure:
    """One failed chain inside the recent window — identity + the frozen
    failure classification (None when the terminal row carried no
    in-vocabulary classification word)."""

    execution_id: object
    classification: str | None
    failed_at: datetime


@dataclass(frozen=True)
class AdapterHealth:
    """Observed health of ONE adapter.

    Two scopes, deliberately separate:

    - the RECENT WINDOW (newest ``window_size`` terminal chains) drives
      success_rate and observed_status — "how is it behaving lately";
    - the ALL-TIME counters plus last_execution_* describe the adapter's
      full recorded life — "what has it done, and when last".

    ``observed_status`` is the ONLY verdict word; there is no boolean
    ``healthy`` field (a true/false would be misread as a live probe)."""

    adapter: str
    observed_status: str = "unknown"
    #: Recent window (newest N terminal executor chains).
    window_size: int = 0
    window_succeeded: int = 0
    window_failed: int = 0
    window_success_rate: float | None = None
    timeout_count: int = 0
    unavailable_count: int = 0
    protocol_violation_count: int = 0
    #: Newest-first failures inside the window.
    recent_failures: tuple[RecentFailure, ...] = ()
    #: All-time totals (every chain of this adapter, any derived state).
    total_chains: int = 0
    all_time_succeeded: int = 0
    all_time_failed: int = 0
    all_time_guard_rejected: int = 0
    all_time_in_flight: int = 0
    #: The most recent chain of this adapter, ANY outcome (observed
    #: fact; a governance refusal or an in-flight chain is still the
    #: last thing that happened).
    last_execution_at: datetime | None = None
    last_execution_state: str | None = None


@dataclass(frozen=True)
class ObservedHealth:
    """The whole-platform observed-health snapshot over
    direction='execute' chains, stamped with the injected clock."""

    generated_at: datetime
    window_size: int
    adapters: Mapping[str, AdapterHealth] = field(default_factory=lambda: MappingProxyType({}))


def _observed_status(
    succeeded: int, failed: int, thresholds: HealthThresholds
) -> str:
    """Frozen judgement rule over the recent window's success rate."""
    rate = _rate(succeeded, succeeded + failed)
    if rate is None:
        return "unknown"  # zero terminal chains observed
    if rate >= thresholds.healthy:
        return "healthy"
    if rate >= thresholds.degraded:
        return "degraded"
    return "failing"


def _terminal_recency(rows: list[ExecutionLog]) -> tuple:
    """A terminal chain's recency key: its TERMINAL row's stamp + id."""
    last = rows[-1]
    return (last.created_at, last.id)


def _recent_failures(window: list[list[ExecutionLog]]) -> tuple[RecentFailure, ...]:
    failures: list[RecentFailure] = []
    for chain in window:
        terminal = chain[-1]
        failures.append(
            RecentFailure(
                execution_id=terminal.execution_id,
                classification=_classification_of(terminal),
                failed_at=terminal.created_at,
            )
        )
    # Newest first (window arrives newest-first already).
    return tuple(failures)


def collect_observed_health(
    session: Session,
    *,
    window_size: int = DEFAULT_WINDOW_SIZE,
    thresholds: HealthThresholds = DEFAULT_THRESHOLDS,
    now: datetime,
) -> ObservedHealth:
    """Derive the observed-health snapshot from execution_log.

    ONE read-only SELECT, no writes, no executor calls, ZERO outbound
    traffic (no probe exists by design). ``now`` is the injected server
    clock stamp — the derivation itself is a pure function of the
    stored rows and the parameters."""
    if isinstance(window_size, bool) or not isinstance(window_size, int):
        raise ValueError(f"window_size must be an int, got {window_size!r}")
    if window_size < 1:
        raise ValueError(f"window_size must be >= 1, got {window_size}")

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

    stats: dict[str, dict] = {}
    for chain in chains.values():
        adapter = _adapter_of(chain)
        bucket = stats.setdefault(
            adapter,
            {
                "total": 0,
                "succeeded": 0,
                "failed": 0,
                "guard_rejected": 0,
                "in_flight": 0,
                "terminal": [],  # chains with an executor outcome
                "last_key": None,
                "last_state": None,
                "last_at": None,
            },
        )
        bucket["total"] += 1

        state = derive_execution_state(chain)
        if state == "succeeded":
            bucket["succeeded"] += 1
            bucket["terminal"].append(chain)
        elif state == "failed":
            bucket["failed"] += 1
            bucket["terminal"].append(chain)
        elif state == "guard_rejected":
            bucket["guard_rejected"] += 1
        else:
            # requested / dispatched: in flight, no outcome yet.
            bucket["in_flight"] += 1

        # Last thing that happened on this adapter, ANY outcome.
        recency = (chain[-1].created_at, chain[-1].id)
        if bucket["last_key"] is None or recency > bucket["last_key"]:
            bucket["last_key"] = recency
            bucket["last_state"] = state
            bucket["last_at"] = chain[-1].created_at

    adapters: dict[str, AdapterHealth] = {}
    for adapter in sorted(stats):
        bucket = stats[adapter]
        # Newest-first terminal window (frozen basis: executor outcomes
        # only — governance refusals never pollute adapter health).
        terminal = sorted(
            bucket["terminal"], key=_terminal_recency, reverse=True
        )
        window = terminal[:window_size]
        window_succeeded = sum(
            1 for chain in window if chain[-1].decision == "succeeded"
        )
        window_failed = len(window) - window_succeeded

        classifications = [_classification_of(chain[-1]) for chain in window]
        adapters[adapter] = AdapterHealth(
            adapter=adapter,
            observed_status=_observed_status(
                window_succeeded, window_failed, thresholds
            ),
            window_size=len(window),
            window_succeeded=window_succeeded,
            window_failed=window_failed,
            window_success_rate=_rate(window_succeeded, len(window)),
            timeout_count=classifications.count("timeout"),
            unavailable_count=classifications.count("adapter_unavailable"),
            protocol_violation_count=classifications.count("protocol_violation"),
            recent_failures=_recent_failures(
                [chain for chain in window if chain[-1].decision == "failed"]
            ),
            total_chains=bucket["total"],
            all_time_succeeded=bucket["succeeded"],
            all_time_failed=bucket["failed"],
            all_time_guard_rejected=bucket["guard_rejected"],
            all_time_in_flight=bucket["in_flight"],
            last_execution_at=bucket["last_at"],
            last_execution_state=bucket["last_state"],
        )

    return ObservedHealth(
        generated_at=now,
        window_size=window_size,
        adapters=MappingProxyType(adapters),
    )
