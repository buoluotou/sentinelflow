"""Reconciliation Contract — Phase 3.4.3-A: Contract Types + Validation.

This module is the INPUT layer of the Reconciliation Contract frozen in
docs/design/phase3.4-reconciliation-contract.md (Design Freeze ``a125f1e``).
It answers exactly one question:

    given a raw ``ExternalObservation`` about what an external system says
    happened to one execution, is it a WELL-FORMED contract input — and if
    so, what is its normalized, validated form?

Pipeline position (design §14)::

    External State
          |  [3.4.3-A THIS MODULE]  ExternalObservation -> validation ->
          |                         NormalizedObservation (or reject)
          |  [3.4.3-B]              external_state -> outcome_status (NOT here)
    Outcome Fact (append-only, execution_outcome)
          |  [3.4.2 derivation]     observed_at DESC, id DESC -> derived state

WHAT THIS STEP DOES (3.4.3-A, Contract Types + Validation ONLY):
  - domain types: ``ExternalObservation`` (input) / ``NormalizedObservation``
    (output), both immutable;
  - contract validation of the six required fields (RC-02);
  - ``observed_at`` normalization to UTC + rejection of naive / non-datetime /
    excessive-future timestamps (design §10, RC-09);
  - contract rejection semantics: a malformed input raises a
    ``ContractValidationFailure`` and NEVER becomes an Outcome Fact (§13);
  - trust-domain SHAPE: ``source -> {adapter_callback | human_operator}``
    (design §8) — the shape only, authentication is 3.4.4 / 3.4.5.

WHAT THIS STEP DELIBERATELY DOES NOT DO (deferred — design §2 / §15):
  - NO ``external_state -> outcome_status`` MAPPING. That is 3.4.3-B. This
    module does not import ``OUTCOME_STATUSES`` and defines no mapping
    function, so it is STRUCTURALLY incapable of emitting an outcome word.
    ``external_state`` is validated for SHAPE (present, non-blank) and
    otherwise preserved RAW. A dispatch word ("succeeded" / "failed") passed
    as ``external_state`` stays exactly that — it can never be turned into
    ``confirmed_success`` / ``confirmed_failure`` here (D3.4-04 / RC-06).
  - NO database, NO repository, NO ``execution_outcome`` INSERT, NO session.
    ``validate_observation`` is a PURE function (the discipline of
    ``app.services.outcomes.derivation`` / ``app.services.executions.state``).
  - NO HTTP / webhook / endpoint / callback transport (3.4.4).
  - NO adapter read path / no external-system query (3.4.5).
  - NO authentication / credential check — the trust domain is a SHAPE only.
  - NO ``execution_id -> existing-chain`` mapping (design §13
    ``UnmappableExecutionId`` needs the DB, so it is 3.4.4 / 3.4.5). Here
    ``execution_id`` is validated STRUCTURALLY: present and a real UUID.
  - NO retry / compensation / approval / fan-out / execution (RC-01).

Vocabulary single-source: the ingress vocabulary (``webhook`` /
``manual_reconcile``) is imported from
``app.models.execution_outcome.OUTCOME_SOURCES``; the adapter-identity
vocabulary from ``app.services.executions.registry.ADAPTER_NAMES``. Neither
is duplicated here (no magic list). The OUTCOME STATUS vocabulary is
deliberately NOT imported — this layer never produces an outcome state.

Sanitized errors: rejection messages name the FIELD and the vocabulary, but
never echo a raw ``external_reference`` / ``external_state`` value (they are
external-system handles / private state — the same non-echo discipline the
executor registry applies to secrets). An adapter NAME or a source token is
not a secret, so those are carried on the exception for a stable message.
"""
from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass, fields
from datetime import datetime, timedelta, timezone

from app.models.execution_outcome import OUTCOME_SOURCES
from app.services.executions.registry import ADAPTER_NAMES

#: Bounded clock-skew tolerance for ``observed_at`` (design §10.5, RC-09).
#:
#: A fact time later than ``server_now + MAX_FUTURE_SKEW`` is rejected:
#: derivation orders by ``observed_at DESC`` (3.4.2), so a single
#: excessive-future timestamp would permanently suppress every real
#: observation. The DEFAULT VALUE is 300 seconds (5 minutes) — the "proposed
#: default" frozen in design §10.5, confirmed for the implementation step by
#: the user (2026-09-03). It is a NAMED, CENTRAL, TESTED constant, never a
#: scattered magic number. The boundary is INCLUSIVE: ``observed_at`` equal
#: to ``now + MAX_FUTURE_SKEW`` is accepted, strictly greater is rejected.
#:
#: No lower ("too old") bound is introduced on purpose: a past timestamp
#: cannot poison the DESC ordering (it simply loses to newer facts), so a
#: minimum would be an unjustified constant. "Invalid timestamp" here means
#: non-datetime / naive / excessive-future — not "historically implausible".
MAX_FUTURE_SKEW = timedelta(seconds=300)

#: The two identity trust domains (design §8, RC-07). They NEVER merge: a
#: ``webhook`` fact is recorded by an adapter callback identity (machine); a
#: ``manual_reconcile`` fact by an authenticated human operator. 3.4.3-A
#: fixes the SHAPE only — the actual authentication lands in 3.4.4 / 3.4.5.
TRUST_DOMAIN_ADAPTER_CALLBACK = "adapter_callback"
TRUST_DOMAIN_HUMAN_OPERATOR = "human_operator"

#: ``source -> trust domain`` (frozen two-word mapping, design §8). The keys
#: are exactly ``OUTCOME_SOURCES``; a source outside this map is rejected by
#: ``validate_observation`` before a trust domain is ever asked for.
SOURCE_TRUST_DOMAIN = {
    "webhook": TRUST_DOMAIN_ADAPTER_CALLBACK,
    "manual_reconcile": TRUST_DOMAIN_HUMAN_OPERATOR,
}


class ContractValidationFailure(Exception):
    """Base class of every Reconciliation Contract rejection (design §13).

    A ``ContractValidationFailure`` means the INPUT does not satisfy the
    contract, so NO Outcome Fact is produced — the observation is refused
    (audit-only), never stored. This is the ``R`` row of design §7: it is
    NEVER ``reconciliation_failed`` (that requires a qualified reconcile
    action that could not read external state) and NEVER ``unknown`` (that
    requires a legitimate-but-ambiguous external state). Refusing first is
    this layer's job; the storage CHECK constraints are the last integrity
    line, not a substitute (design §13 "先拒哲学").
    """


class MissingExecutionId(ContractValidationFailure):
    """``execution_id`` absent or not a UUID (design §4). STRUCTURAL check
    only: whether the id maps to an EXISTING execution chain
    (``UnmappableExecutionId``, design §13) needs the database and is
    therefore 3.4.4 / 3.4.5 — not this pure contract layer."""


class UnknownAdapter(ContractValidationFailure):
    """``adapter`` is not a known adapter identity (design §4). Carries the
    offending ``adapter`` so callers can render a stable message; an adapter
    NAME is not a secret (same transparency as the executor registry)."""

    def __init__(self, message: str, adapter: object | None = None):
        super().__init__(message)
        self.adapter = adapter


class MissingExternalReference(ContractValidationFailure):
    """``external_reference`` absent / empty (design §9.2, RC-05). This is a
    Contract Validation Failure — NEVER downgraded to ``reconciliation_failed``:
    without the handle that ties the observation to the external object, the
    reconcile action is not even qualified to run (design §7 R-not-B)."""


class MissingExternalState(ContractValidationFailure):
    """``external_state`` absent / blank / not a str-or-mapping — the SHAPE
    check (design §4). This is NOT the mapping failure
    (``UnrecognizedExternalState``, design §13): deciding whether a PRESENT
    ``external_state`` maps onto the five outcome words is 3.4.3-B. Here a
    well-shaped-but-unmapped state is preserved RAW — never rejected for
    being unrecognized and never guessed to ``unknown`` (§0 铁律)."""


class InvalidObservedAt(ContractValidationFailure):
    """``observed_at`` is not a timezone-aware datetime within the bounded
    future skew (design §10, RC-09): a non-datetime, a naive datetime, or a
    time later than ``now + MAX_FUTURE_SKEW``."""


class InvalidSource(ContractValidationFailure):
    """``source`` is not one of the two frozen ingress channels (``webhook`` /
    ``manual_reconcile``, design §8). Carries the offending ``source`` for a
    stable message; no third channel exists (D3.4-03)."""

    def __init__(self, message: str, source: object | None = None):
        super().__init__(message)
        self.source = source


@dataclass(frozen=True)
class ExternalObservation:
    """The frozen INPUT contract (design §4, RC-02): six required fields
    describing one raw observation of what an external system says about one
    execution. Immutable (frozen) — validation NEVER mutates its input; it
    produces a separate ``NormalizedObservation``.

    ``external_state`` is typed ``str | Mapping`` because an adapter may
    report a bare status word OR a small structured payload; 3.4.3-A only
    checks its SHAPE and preserves it RAW (mapping to an outcome word is
    3.4.3-B).
    """

    execution_id: uuid.UUID
    adapter: str
    external_reference: str
    external_state: str | Mapping
    observed_at: datetime
    source: str


@dataclass(frozen=True)
class NormalizedObservation:
    """The OUTPUT of a successful contract validation (design §5 A, minus the
    ``outcome_status`` that 3.4.3-B adds). Immutable (frozen).

    It DELIBERATELY HAS NO ``outcome_status`` field: this layer validates and
    normalizes the observation, it does NOT decide the external effect. The
    absence of that field is the structural guarantee that a dispatch word can
    never be laundered into an outcome word here (D3.4-04 / RC-06, design §6).
    ``trust_domain`` records the identity SHAPE (design §8) so downstream steps
    resolve the recorder without ever merging the two domains.
    """

    execution_id: uuid.UUID
    adapter: str
    external_reference: str
    external_state: str | Mapping
    observed_at: datetime
    source: str
    trust_domain: str


#: The six required field names, in validation order. Single source: the
#: dataclass itself, so the order can never drift from the type. Drives the
#: fail-fast, deterministic validation sequence in ``validate_observation``.
CONTRACT_FIELDS = tuple(field.name for field in fields(ExternalObservation))


def trust_domain_for(source: str) -> str:
    """The identity trust domain a ``source`` belongs to (design §8). Pure
    lookup over the frozen two-word map. An unknown source is a caller bug —
    ``validate_observation`` rejects it first — so a bare ``KeyError`` is
    acceptable here; validate the source before asking for its domain."""
    return SOURCE_TRUST_DOMAIN[source]


def _normalize_observed_at(observed_at: object, *, now: datetime) -> datetime:
    """Validate + normalize the fact time (design §10, RC-09). PURE.

    Rejects with ``InvalidObservedAt``:
      - a non-datetime (including ``None``);
      - a NAIVE datetime (``tzinfo is None``, or a ``tzinfo`` whose
        ``utcoffset`` is ``None``) — naive time is semantically ambiguous
        (local? UTC?) and is refused fail-closed, never silently assumed to
        be UTC or local (§10.2);
      - a time later than ``now + MAX_FUTURE_SKEW`` (§10.5) — a future fact
        would permanently suppress real observations under the
        ``observed_at DESC`` derivation order.

    On success returns the SAME INSTANT re-expressed in UTC
    (``astimezone(timezone.utc)``): the representation changes, the moment
    does not (§10.3). Precision is preserved, never truncated (§10.6);
    equal-second ties are broken downstream by ``id DESC`` (3.4.2), so the
    contract manufactures no fake precision.
    """
    if not isinstance(observed_at, datetime):
        raise InvalidObservedAt(
            "observed_at must be a datetime (fact time, not ingest time); "
            f"got a non-datetime value of type {type(observed_at).__name__}"
        )
    if observed_at.tzinfo is None or observed_at.tzinfo.utcoffset(observed_at) is None:
        raise InvalidObservedAt(
            "observed_at must be timezone-aware; a naive datetime is refused "
            "(ambiguous local-vs-UTC), never assumed to be UTC or local (§10.2)"
        )
    normalized = observed_at.astimezone(timezone.utc)
    if normalized > now + MAX_FUTURE_SKEW:
        raise InvalidObservedAt(
            "observed_at is too far in the future: it must not exceed server "
            f"time + {int(MAX_FUTURE_SKEW.total_seconds())}s bounded skew "
            "(§10.5) — a future fact would suppress real observations under "
            "observed_at DESC derivation"
        )
    return normalized


def validate_observation(
    observation: ExternalObservation,
    *,
    now: datetime | None = None,
) -> NormalizedObservation:
    """Validate + normalize one ``ExternalObservation`` against the frozen
    Reconciliation Contract (design §4-§13). PURE: no DB, no session, no
    HTTP, no adapter call, no side effect, no mutation of the input.

    Returns a ``NormalizedObservation`` on success. On ANY contract violation
    raises a ``ContractValidationFailure`` subclass — the observation is
    REFUSED and produces NO Outcome Fact (design §13, R row). Fields are
    checked fail-fast in ``CONTRACT_FIELDS`` order, so a repeated call on the
    same input is deterministic (same result, or same exception type).

    ``now`` is the injectable reference clock for the bounded-future check
    (defaults to the current UTC time). Tests inject a fixed ``now`` for a
    deterministic boundary; production callers omit it.

    This function NEVER maps ``external_state`` to an outcome word — that is
    3.4.3-B. A well-shaped observation always yields a
    ``NormalizedObservation`` with ``external_state`` preserved RAW and no
    ``outcome_status`` anywhere.
    """
    reference_now = now if now is not None else datetime.now(timezone.utc)

    # 1. execution_id — STRUCTURAL: present and a real UUID. (Mapping to an
    #    EXISTING chain needs the DB -> 3.4.4 / 3.4.5, design §13.)
    execution_id = observation.execution_id
    if not isinstance(execution_id, uuid.UUID):
        raise MissingExecutionId(
            "execution_id is required and must be a UUID identifying the "
            "execution chain this observation belongs to (§4)"
        )

    # 2. adapter — a known adapter identity (single source: registry). Strict
    #    exact match after trimming; NO case folding (the canonical identities
    #    are lower-case, and a contract input is fail-closed, not lenient).
    adapter = observation.adapter
    adapter_normalized = adapter.strip() if isinstance(adapter, str) else ""
    if adapter_normalized not in ADAPTER_NAMES:
        raise UnknownAdapter(
            "adapter must be a known adapter identity "
            f"({', '.join(ADAPTER_NAMES)}); got an unrecognized value",
            adapter=adapter_normalized or None,
        )

    # 3. external_reference — required, non-empty (design §9.2, RC-05).
    #    Missing -> reject, NEVER reconciliation_failed. The raw value is
    #    never echoed (it is an external-system handle).
    external_reference = observation.external_reference
    reference_normalized = (
        external_reference.strip() if isinstance(external_reference, str) else ""
    )
    if not reference_normalized:
        raise MissingExternalReference(
            "external_reference is required (§4 / §9): without the handle "
            "that ties this observation to the external object it is refused "
            "— NEVER stored as reconciliation_failed (RC-05)"
        )

    # 4. external_state — SHAPE only (design §4). Present and non-blank (str)
    #    / non-empty (mapping); otherwise preserved RAW. NEVER mapped to an
    #    outcome word here (3.4.3-B) and NEVER guessed to unknown (§0 铁律).
    external_state = observation.external_state
    if isinstance(external_state, str):
        if not external_state.strip():
            raise MissingExternalState(
                "external_state is required and must not be blank (§4)"
            )
    elif isinstance(external_state, Mapping):
        if not external_state:
            raise MissingExternalState(
                "external_state is required and must not be an empty "
                "mapping (§4)"
            )
    else:
        raise MissingExternalState(
            "external_state is required and must be a str or a mapping (§4); "
            f"got type {type(external_state).__name__}"
        )

    # 5. observed_at — aware, UTC-normalized, bounded future (design §10).
    observed_at = _normalize_observed_at(observation.observed_at, now=reference_now)

    # 6. source — one of the two frozen ingress channels (design §8); it also
    #    fixes the trust domain of the (future) recorder. Strict exact match
    #    after trimming; NO case folding.
    source = observation.source
    source_normalized = source.strip() if isinstance(source, str) else ""
    if source_normalized not in OUTCOME_SOURCES:
        raise InvalidSource(
            "source must be one of the two frozen ingress channels "
            f"({', '.join(sorted(OUTCOME_SOURCES))}); got an unrecognized "
            "value — no third channel exists (D3.4-03)",
            source=source_normalized or None,
        )

    return NormalizedObservation(
        execution_id=execution_id,
        adapter=adapter_normalized,
        external_reference=reference_normalized,
        external_state=external_state,
        observed_at=observed_at,
        source=source_normalized,
        trust_domain=trust_domain_for(source_normalized),
    )
