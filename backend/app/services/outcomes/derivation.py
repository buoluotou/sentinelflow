"""Outcome derivation — a PURE read of External Outcome Facts.

The Outcome layer is an append-only fact log: every row of
``execution_outcome`` is one immutable observation of what the EXTERNAL
world eventually did. This module is the single source of truth for one
question:

given the observations of ONE execution, what is its current
derived / effective outcome state?

It is a PURE function — the exact discipline of
``app.services.executions.state.derive_execution_state``:
observations in, derived state out. No INSERT / UPDATE / DELETE, no flush
/ commit, no ORM mutation, no HTTP, no adapter / executor call, no retry,
no compensation. Derivation NEVER writes back into the dispatch log and
NEVER alters a historical fact (D3.4-05 / O5): a dispatch of
``succeeded`` next to an outcome of ``confirmed_failure`` derives to
``confirmed_failure`` while the dispatch row stays ``succeeded`` forever.
Reading facts and computing a viewpoint is all this layer does.

Frozen derivation rule (O2):
1. order the observations by ``observed_at DESC, id DESC``;
2. take the FIRST — the latest observation, ties on ``observed_at``
broken deterministically by the larger ``id``;
3. its ``outcome_status`` is the derived state;
4. no observations at all -> ``unknown`` (the explicit fifth word,
NOT None — unlike the dispatch log, whose empty-chain sentinel is
None because it has no such word).

The ordering is computed HERE, in Python, never delegated to a database's
incidental row order: out-of-order delivery, callback replay and equal
timestamps must all resolve deterministically, so the derivation re-sorts
whatever it is handed and never depends on the caller's ordering. Any
future SQL read path that feeds this function MUST use the identical
``ORDER BY observed_at DESC, id DESC`` — but correctness never rests on
it (a replayed older fact simply loses to the newer ``observed_at``).

Vocabulary is imported from ``app.models.execution_outcome`` — one source, never duplicated here. Dispatch-layer words (``succeeded`` /
``failed`` / ``requested`` / ...) are NOT outcome states; were one ever to
reach this layer it is refused, not improvised (D3.4-04: the two
vocabularies never cross-contaminate — the storage CHECK is the last
integrity line, derivation refuses first).
"""
from __future__ import annotations

from typing import Protocol, Sequence

from app.models.execution_outcome import OUTCOME_STATUSES

# The empty-fact sentinel. ``unknown`` is a real, storable outcome word
# (the fifth of the five), so an execution with no observations
# yet derives to ``unknown`` — "nothing observed, nothing claimed". It is
# NOT None: the dispatch log uses None for "not started"
# only because its vocabulary has no such word; the outcome layer does.
UNKNOWN_OUTCOME = "unknown"


class OutcomeDerivationError(Exception):
    """Base class of all outcome derivation errors (never silent)."""


class ForeignOutcomeVocabulary(OutcomeDerivationError):
    """An observation carried a status outside the five-word outcome
vocabulary — almost certainly a dispatch-layer word (``succeeded`` /
``failed`` / ``requested`` / ...) that must never cross into the
Outcome layer (D3.4-04 / O1). The storage CHECK is the last integrity
line; derivation refuses first and never improvises a state. Carries
the offending ``status`` so callers can render a stable message."""

    def __init__(self, message: str, status: str | None = None):
        super().__init__(message)
        self.status = status


class OutcomeObservation(Protocol):
    """Structural shape derivation needs — ``ExecutionOutcome`` satisfies
it, tests may supply lightweight stubs (the logic is pure and DB-free).
Only three attributes are ever read."""

    id: object
    observed_at: object
    outcome_status: str


def latest_observation(
    observations: Sequence[OutcomeObservation],
) -> OutcomeObservation | None:
    """Pure selection primitive (O2): the winning observation of ONE
execution is the one with the latest ``observed_at``, ties broken by
the larger ``id`` — STRICTLY ``ORDER BY observed_at DESC, id DESC``,
never list position, never id alone.

Returns None for an empty input. The input is expected to be the
observations of a single execution_id (mixing executions is a caller
bug); the order of the input itself does not matter — this function
re-sorts, so it never trusts a database's incidental row order. No DB
access, no writes of any kind.
"""
    if not observations:
        return None
    return max(observations, key=lambda o: (o.observed_at, o.id))


def derive_outcome_state(observations: Sequence[OutcomeObservation]) -> str:
    """Pure derived-state logic: the current outcome state of ONE execution
is the ``outcome_status`` of its latest observation
(``latest_observation``), or ``unknown`` when there are no facts.

The returned word is guaranteed to belong to the five-word
``OUTCOME_STATUSES`` — a foreign (e.g. dispatch-layer) status on the
winning observation raises ``ForeignOutcomeVocabulary`` rather than
leaking into the Outcome view. No DB access, no writes of any kind.
"""
    latest = latest_observation(observations)
    if latest is None:
        return UNKNOWN_OUTCOME
    status = latest.outcome_status
    if status not in OUTCOME_STATUSES:
        raise ForeignOutcomeVocabulary(
            f"Outcome observation carries a non-outcome status: {status!r}",
            status=status,
        )
    return status
