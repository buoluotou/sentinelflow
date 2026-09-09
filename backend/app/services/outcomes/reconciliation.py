"""Reconciliation Contract — Phase 3.4.3-A (Contract Types + Validation)
+ 3.4.3-B (External State Mapping).

This module is the pure contract layer of the Reconciliation Contract frozen in
docs/design/phase3.4-reconciliation-contract.md (Design Freeze ``a125f1e``).
It answers two questions, in two sealed steps:

    3.4.3-A  given a raw ``ExternalObservation`` about what an external system
             says happened to one execution, is it a WELL-FORMED contract input
             — and if so, what is its normalized, validated form?
    3.4.3-B  given an ALREADY-VALIDATED ``adapter`` + ``external_state``, which
             outcome word does the external system's OWN state denote?

Pipeline position (design §14)::

    External State
          |  [3.4.3-A THIS MODULE]  ExternalObservation -> validation ->
          |                         NormalizedObservation (or reject)
          |  [3.4.3-B THIS MODULE]  adapter + external_state -> outcome_status
          |                         (normalize_external_state, or reject)
    Outcome Fact (append-only, execution_outcome)
          |  [3.4.2 derivation]     observed_at DESC, id DESC -> derived state

WHAT THIS MODULE DOES:
  3.4.3-A (Contract Types + Validation):
  - domain types: ``ExternalObservation`` (input) / ``NormalizedObservation``
    (output), both immutable;
  - contract validation of the six required fields (RC-02);
  - ``observed_at`` normalization to UTC + rejection of naive / non-datetime /
    excessive-future timestamps (design §10, RC-09);
  - contract rejection semantics: a malformed input raises a
    ``ContractValidationFailure`` and NEVER becomes an Outcome Fact (§13);
  - trust-domain SHAPE: ``source -> {adapter_callback | human_operator}``
    (design §8) — the shape only, authentication is 3.4.4 / 3.4.5.
  3.4.3-B (External State Mapping):
  - ``normalize_external_state(adapter, external_state)`` — a PURE,
    adapter-specific map of an ALREADY-VALIDATED external state onto the outcome
    vocabulary (design §6), returning an immutable ``StateMapping``;
  - per-adapter EVIDENCED vocabularies (``ADAPTER_STATE_VOCABULARIES``): only
    states that existing adapter code / the frozen design evidence are frozen;
    an adapter with no verifiable vocabulary stays EMPTY (a documented gap for
    the 3.4.5 read path), never filled with a plausible-looking guess;
  - ``UnrecognizedExternalState``: a state outside the evidenced vocabulary is
    REFUSED (no fact), NEVER downgraded to ``unknown`` (§0 铁律 / §十).

WHAT THIS MODULE DELIBERATELY DOES NOT DO (deferred — design §2 / §15):
  - NO ``reconciliation_failed``. That word means "the reconcile action ran but
    could not READ external state" (design §7-B / O1) — a READ-FAILURE path
    (3.4.5). ``normalize_external_state`` is only ever called WITH a state in
    hand, so it can NEVER emit that word: ``MAPPABLE_OUTCOME_STATUSES`` is
    ``OUTCOME_STATUSES`` minus it, and ``StateMapping.__post_init__`` enforces
    the exclusion structurally (§四).
  - NO fabricated adapter states (user §十六). ``validate_observation`` (A)
    preserves ``external_state`` RAW and never maps it; ``normalize_external_state``
    (B) maps ONLY code/design-evidenced states and REFUSES the rest. A dispatch
    word ("succeeded" / "failed") is in NO adapter's evidenced vocabulary, so it
    can never become ``confirmed_success`` / ``confirmed_failure`` (D3.4-04 /
    RC-06 / §五) — it is refused as unrecognized.
  - NO database, NO repository, NO ``execution_outcome`` INSERT / UPDATE, NO
    session. BOTH ``validate_observation`` and ``normalize_external_state`` are
    PURE functions (the discipline of ``app.services.outcomes.derivation`` /
    ``app.services.executions.state``).
  - NO HTTP / webhook / endpoint / callback transport (3.4.4).
  - NO adapter read path / no external-system query / no adapter call: B is
    ``state -> outcome`` ONLY, NEVER ``adapter -> HTTP -> state -> outcome``
    (3.4.5).
  - NO authentication / credential check — the trust domain is a SHAPE only.
  - NO ``execution_id -> existing-chain`` mapping (design §13
    ``UnmappableExecutionId`` needs the DB, so it is 3.4.4 / 3.4.5). Here
    ``execution_id`` is validated STRUCTURALLY: present and a real UUID.
  - NO retry / compensation / approval / fan-out / execution (RC-01).

Vocabulary single-source: the ingress vocabulary (``webhook`` /
``manual_reconcile``) and the OUTCOME STATUS vocabulary are both imported from
``app.models.execution_outcome`` (``OUTCOME_SOURCES`` / ``OUTCOME_STATUSES``);
the adapter-identity vocabulary from
``app.services.executions.registry.ADAPTER_NAMES``. None is duplicated here (no
magic list). 3.4.3-A never produced an outcome word; 3.4.3-B maps onto them and
imports ``OUTCOME_STATUSES`` to GUARANTEE every emitted word is a frozen one
(and never ``reconciliation_failed``). The per-adapter external-state words are
NOT imported from the adapters — they are re-frozen here with inline evidence
citations, and a test cross-checks the Wazuh set against
``wazuh._CONFIRMED_AGENT_STATUSES`` so the link can never silently drift.

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

from app.models.execution_outcome import OUTCOME_SOURCES, OUTCOME_STATUSES
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


class UnrecognizedExternalState(ContractValidationFailure):
    """``external_state`` is present and well-shaped (it passed 3.4.3-A) but its
    VALUE is outside the adapter's evidenced vocabulary — the 3.4.3-B mapping
    contract does not accept it (design §6 归一化闸 / §13). This completes the §13
    rejection family 3.4.3-A began: ``MissingExternalState`` above is the SHAPE
    check, this is the MAPPING check.

    THE §0 铁律: an unrecognized state is NEVER downgraded to ``unknown`` (that
    word is reserved for a RECOGNIZED-but-ambiguous legitimate state) and NEVER
    to ``reconciliation_failed`` (that requires a qualified reconcile that could
    not READ the state). It is REFUSED — NO Outcome Fact. Carries the ``adapter``
    (not a secret) but NEVER echoes the raw ``external_state`` value (external
    private data — the same non-echo discipline as the rest of this family)."""

    def __init__(self, message: str, adapter: object | None = None):
        super().__init__(message)
        self.adapter = adapter


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


# ===========================================================================
# Phase 3.4.3-B — External State Mapping (design §6)
# ===========================================================================
#
# 3.4.3-A answered "is this a well-formed observation?". 3.4.3-B answers the
# NEXT question: given an ALREADY-VALIDATED ``adapter`` + ``external_state``,
# which outcome word does the external system's OWN state denote? This is
# ``state -> outcome`` ONLY — NEVER ``adapter -> HTTP -> state -> outcome`` (the
# read path is 3.4.5).
#
# THE GOVERNING CONSTRAINT (user 2026-09-03 §十六, design §6): DO NOT FABRICATE.
# A state word is frozen into a vocabulary ONLY when existing adapter code (or
# the frozen design) evidences it. Where an adapter has no verifiable external
# terminal-state vocabulary, its table stays EMPTY and every state is refused as
# ``UnrecognizedExternalState`` — the concrete enumeration lands with the 3.4.5
# read path, never invented here. "宁可返回 mapping rejection，不要猜测."
#
# STILL DEFERRED: NO ``reconciliation_failed`` (that is the read-failure verdict,
# 3.4.5 — a mapper is only ever called WITH a state in hand, so it can never
# mean "could not read the state"); NO HTTP / webhook / adapter read client /
# polling (3.4.4 / 3.4.5); NO DB / repository / INSERT / UPDATE (still PURE);
# NO retry / compensation / execution (RC-01).

#: The outcome words ``normalize_external_state`` may produce — the frozen five
#: MINUS ``reconciliation_failed`` (design §6/§7, user §四). That fifth word is
#: the READ-FAILURE verdict ("ran a reconcile, could not read external state",
#: O1) produced by the 3.4.5 read-failure path, never by an external_state
#: semantic mapping. Single source: ``OUTCOME_STATUSES`` (never a magic list).
MAPPABLE_OUTCOME_STATUSES = OUTCOME_STATUSES - {"reconciliation_failed"}


@dataclass(frozen=True)
class AdapterStateVocabulary:
    """ONE adapter's evidenced external-state -> outcome-word mapping (design §6
    "per-adapter 私有状态词表"). Explicit, auditable, testable — never an if/elif
    chain over raw strings (user §十二).

    Each frozenset holds the external state words whose semantics denote that
    outcome. An EMPTY set is a DELIBERATE, DOCUMENTED GAP (no code evidence) —
    NOT an oversight; filling one requires 3.4.5 read-path evidence, never a
    plausible-looking guess (the专项 tests pin these empties so they cannot be
    silently fabricated).

    ``case_insensitive`` / ``state_key`` encode the ONLY normalizations an
    adapter's OWN code evidences (§十三): Wazuh lower-cases ``agent_status``
    (wazuh.py:246) and reads it from ``body["agent_status"]`` (wazuh.py:243), so
    both are code-specified for Wazuh and for NO other adapter. Neither trims —
    wazuh.py does not trim, so the mapping does not either.
    """

    adapter: str
    terminal_success_states: frozenset[str]
    terminal_failure_states: frozenset[str]
    pending_states: frozenset[str]
    ambiguous_states: frozenset[str]
    case_insensitive: bool = False
    state_key: str | None = None
    evidence: str = ""


#: The per-adapter vocabularies. Keys are EXACTLY ``ADAPTER_NAMES`` (a test pins
#: this — every validated adapter has a table, and no table exists for a
#: non-adapter). Evidence citations are inline; the anti-fabrication rule governs
#: every entry.
ADAPTER_STATE_VOCABULARIES: dict[str, AdapterStateVocabulary] = {
    "wazuh": AdapterStateVocabulary(
        adapter="wazuh",
        # G1-B/G1-C SECURITY REMEDIATION (new forward commit; 8b89fe7 / B0 / B0.1
        # untouched — history is read-only). The former external-state vocabulary
        # {completed,confirmed,done,success,ok} / running / unknown was fabricated
        # from a FICTIONAL "agent_status IS the effect status" reading of a
        # synchronous dispatch response, and is falsified by B0 §4 (agent_status is
        # NOT a command-level effect; "ok" is a task-acceptance false friend). G1-A
        # proved it LIVE-reachable via BOTH the webhook path (webhook.py:149) AND
        # the manual path (manual_persist.py:204, injected-reader), producing
        # untrusted Outcome facts (CONFIRMED UNSAFE — an unsafe code path proven
        # reachable, NOT a claimed production incident). All four sets are EMPTIED
        # to fail-closed (refuse -> UnrecognizedExternalState -> 422 / zero fact)
        # INDEPENDENT of production-version confirmation (decoupled from G2). This
        # de-anchors the INBOUND effect mapping only: the OUTBOUND dispatch constant
        # wazuh.py:97-99 ``_CONFIRMED_AGENT_STATUSES`` is a separate concern and is
        # NOT modified here. Any future re-population requires version-qualified
        # command-level effect evidence + an independent Design Freeze (B0 §18);
        # there is NO auto-reopen mechanism — an empty vocab refuses regardless of
        # whether a Reader is registered or a production version is configured.
        terminal_success_states=frozenset(),
        terminal_failure_states=frozenset(),
        pending_states=frozenset(),
        ambiguous_states=frozenset(),
        case_insensitive=False,
        state_key=None,
        evidence=(
            "G1-B/G1-C: no trusted command-level effect vocabulary for ANY "
            "verified Wazuh version; fail-closed (refuse) until real "
            "command-effect read evidence exists (G1-A CONFIRMED UNSAFE; "
            "decoupled from G2 version)"
        ),
    ),
    "shuffle": AdapterStateVocabulary(
        adapter="shuffle",
        # GAP (design §6/§7, user §七): Shuffle is TRIGGER-ONLY — E4 freezes
        # ``succeeded == "workflow trigger confirmed"``, explicitly NOT "workflow
        # fully completed" (shuffle.py:8-12, 250). The adapter parses only the
        # synchronous dispatch response (``success:true`` + external_execution_id);
        # it has NO read path and NO workflow terminal-state vocabulary, so
        # external_execution_id must NEVER imply confirmed_success and NO Shuffle
        # state word can be frozen without fabrication. The concrete vocabulary
        # lands with the 3.4.5 read path (design §6: "随 3.4.5 adapter read path
        # 一起落地"). Every Shuffle external_state is therefore unrecognized.
        terminal_success_states=frozenset(),
        terminal_failure_states=frozenset(),
        pending_states=frozenset(),
        ambiguous_states=frozenset(),
        case_insensitive=False,
        state_key=None,
        evidence=(
            "GAP: no verifiable workflow terminal-state vocabulary "
            "(3.4.5 read path)"
        ),
    ),
    "thehive": AdapterStateVocabulary(
        adapter="thehive",
        # M2-R §2 SECURITY REMEDIATION (new forward commit; 117ab6b — which added
        # the M2 §5 ``case_created`` word — is untouched, history is read-only).
        # M2 §5 froze EXACTLY ONE synthesized word here, ``case_created``, reasoning
        # that native TheHive never emits it and the callback token defaults empty.
        # M2 Final Review falsified that as a SECURITY GATE: this vocabulary is
        # PATH-AGNOSTIC — ``normalize_external_state(adapter, external_state)``
        # (frozen 2-param) is reached by BOTH the LIVE webhook PUSH path
        # (webhook.py) AND the manual_reconcile PULL path, and ``map_external_state``
        # is sealed to a single delegation with NO source / trust_domain branch. So
        # with a VALID ``THEHIVE_CALLBACK_TOKEN``, a schema- and correlation-valid
        # webhook body carrying the bare string ``case_created`` maps to
        # ``confirmed_success`` WITHOUT ever passing the trusted reader — the exact
        # G1-A defect class (an unsafe mapping proven LIVE-reachable). The frozen
        # general contract STRUCTURALLY cannot express source isolation (a source
        # param, an ``if`` branch, or a second table each violate a seal), so per the
        # reviewer's Amendment clause this applies the G1-C precedent: ALL FOUR SETS
        # EMPTIED -> fail-closed. ``case_created`` is now unforgeable because it
        # maps to NOTHING on ANY path (``UnrecognizedExternalState`` -> 422 / ZERO
        # fact). The reader STILL emits ``case_created`` at the READER level
        # (identity + correlation + creation conjunction, isolation-tested) but the
        # mapping REFUSES it until a trusted-reader SOURCE-ISOLATION channel is
        # designed + approved (see the M2-R Amendment). NO second mapping table, NO
        # caller-controllable verified flag. Version scope TheHive 4.1.24-1 (git
        # ``b6649bb``) / ScalliGraph ``2c2a7a4``; wazuh (G1-C) / shuffle / mock
        # vocabularies are UNCHANGED.
        terminal_success_states=frozenset(),
        terminal_failure_states=frozenset(),
        pending_states=frozenset(),
        ambiguous_states=frozenset(),
        case_insensitive=False,
        state_key=None,
        evidence=(
            "M2-R §2 FAIL-CLOSED (forward commit; 117ab6b untouched): the M2 §5 "
            "synthesized 'case_created' word is REMOVED from this path-agnostic "
            "vocabulary — the frozen 2-param mapping contract cannot express source "
            "isolation, so in this shared table the word was forgeable from the LIVE "
            "webhook inbound path (valid callback token + schema/correlation-valid "
            "body), the G1-A defect class. The reader still emits case_created "
            "(isolation-tested) but the mapping now REFUSES it on EVERY path (zero "
            "fact) until a trusted-reader source-isolation channel is approved (M2-R "
            "Amendment). Version scope TheHive 4.1.24-1=b6649bb/ScalliGraph 2c2a7a4; "
            "wazuh/shuffle/mock unchanged."
        ),
    ),
    "mock": AdapterStateVocabulary(
        adapter="mock",
        # UNSUPPORTED BY DESIGN (user §六, design §9): Mock has ZERO outbound
        # traffic and NO external system (mock.py:4-6), so it can never produce an
        # external outcome. This is PERMANENT — not a 3.4.5 gap. Any Mock
        # external_state is refused as unrecognized (no external effect exists to
        # observe).
        terminal_success_states=frozenset(),
        terminal_failure_states=frozenset(),
        pending_states=frozenset(),
        ambiguous_states=frozenset(),
        case_insensitive=False,
        state_key=None,
        evidence="no external outcome by design (Mock is offline DryRun)",
    ),
}


@dataclass(frozen=True)
class StateMapping:
    """The PURE result of mapping one validated external_state onto the outcome
    vocabulary (user §十四: a domain result, NOT a DB write). Immutable.

    ``outcome_status`` is guaranteed to be one of ``MAPPABLE_OUTCOME_STATUSES`` —
    ``__post_init__`` refuses any non-outcome word (a typo in a vocabulary branch)
    and refuses ``reconciliation_failed`` STRUCTURALLY (§四: a state-mapping can
    never be the read-failure verdict). ``observed_state`` preserves the RAW
    extracted word (§十三), ``normalized_state`` the form actually matched, and
    ``mapping_reason`` the auditable why (design §5: detail = mapping notes).
    """

    adapter: str
    outcome_status: str
    observed_state: str
    normalized_state: str
    mapping_reason: str

    def __post_init__(self):
        if self.outcome_status not in OUTCOME_STATUSES:
            # Defensive (mirrors derivation.derive_outcome_state): a mapping must
            # only ever emit a frozen outcome word. The four branches hardcode
            # literals, so this fires only on an internal typo — never on input.
            raise ValueError(
                "StateMapping.outcome_status must be a frozen outcome word "
                "(design §6); got an out-of-vocabulary value"
            )
        if self.outcome_status not in MAPPABLE_OUTCOME_STATUSES:
            # The only OUTCOME_STATUSES member that is not mappable is
            # reconciliation_failed — the read-failure verdict (3.4.5), never a
            # state-mapping product (§四). Enforced structurally, not by comment.
            raise ValueError(
                "normalize_external_state can never produce "
                "reconciliation_failed — that is the read-failure path (design "
                "§7-B / O1, 3.4.5), not an external_state mapping (§四)"
            )


def _extract_state_word(
    vocab: AdapterStateVocabulary, external_state: object
) -> str | None:
    """Pull the state WORD out of a validated ``external_state`` (design §4:
    ``str | Mapping``). PURE; returns None when no word can be evidenced. The raw
    payload is NEVER modified (§十三).

    - a bare ``str`` IS the state word (returned RAW — the adapter's own
      normalization is applied by the caller, not here);
    - a ``Mapping`` yields ``mapping[state_key]`` when the adapter evidences a key
      (Wazuh ``agent_status``, wazuh.py:243) and that value is a ``str``;
    - anything else (a Mapping with no evidenced key / a missing key / a non-str
      value) -> None -> ``UnrecognizedExternalState``.
    """
    if isinstance(external_state, str):
        return external_state
    if isinstance(external_state, Mapping):
        if vocab.state_key is None:
            return None
        value = external_state.get(vocab.state_key)
        return value if isinstance(value, str) else None
    return None


def normalize_external_state(
    adapter: str, external_state: str | Mapping
) -> StateMapping:
    """Map one ALREADY-VALIDATED ``external_state`` onto the outcome vocabulary,
    adapter-specifically (design §6). PURE: no DB, no HTTP, no ORM, no executor,
    no adapter call, no side effect, no mutation of the input (user §十一).

    INPUT CONTRACT (user §三): the caller ran 3.4.3-A ``validate_observation``
    first, so ``adapter`` is a known identity and ``external_state`` is present
    and well-shaped. This function does NOT re-run A's validator; an ``adapter``
    absent from ``ADAPTER_STATE_VOCABULARIES`` is a caller bug (``KeyError``) —
    the same philosophy as ``trust_domain_for`` on an unvalidated source.

    OUTPUT: a ``StateMapping`` whose ``outcome_status`` ∈
    ``MAPPABLE_OUTCOME_STATUSES`` (never ``reconciliation_failed``). An
    ``external_state`` outside the adapter's evidenced vocabulary raises
    ``UnrecognizedExternalState`` — NO Outcome Fact, NEVER guessed to ``unknown``
    (user §十 / §0 铁律). Deterministic: the same ``(adapter, external_state)``
    always yields the same result or the same exception type.

    THE ANTI-FABRICATION RULE (user §十六): only code/design-evidenced states are
    frozen. G1-C EMPTIED the fabricated Wazuh ``agent_status`` set (see the inline
    Wazuh note). M2 §5 then added EXACTLY ONE word — TheHive's synthesized
    ``case_created`` — but M2-R §2 EMPTIED it again (see the inline TheHive note):
    this vocabulary is PATH-AGNOSTIC, so a source-isolated reader-only signal cannot
    live in it without being forgeable from the LIVE webhook path, and the frozen
    2-param contract cannot express source isolation. The result is that NO adapter
    (Wazuh / Shuffle / TheHive / Mock) has an evidenced external-state vocabulary
    and EVERY reported state is unrecognized, pending a trusted-reader source-
    isolation Amendment. An unrecognized state is REFUSED
    (``UnrecognizedExternalState``) — NEVER guessed to ``unknown`` and NEVER
    ``reconciliation_failed``.
    """
    vocab = ADAPTER_STATE_VOCABULARIES[adapter]
    word = _extract_state_word(vocab, external_state)
    if word is None:
        raise UnrecognizedExternalState(
            f"{adapter} reported an external_state this contract cannot map "
            "onto the outcome vocabulary: no evidenced state word could be "
            "extracted (design §6 / §13). Refused — NEVER guessed to unknown, "
            "NEVER reconciliation_failed, NO Outcome Fact.",
            adapter=adapter,
        )
    # Adapter-specific normalization ONLY where the adapter's own code evidences
    # it (§十三): Wazuh lower-cases agent_status (wazuh.py:246). Never a trim.
    candidate = word.lower() if vocab.case_insensitive else word
    if candidate in vocab.terminal_success_states:
        outcome_status = "confirmed_success"
    elif candidate in vocab.terminal_failure_states:
        outcome_status = "confirmed_failure"
    elif candidate in vocab.pending_states:
        outcome_status = "pending"
    elif candidate in vocab.ambiguous_states:
        outcome_status = "unknown"
    else:
        raise UnrecognizedExternalState(
            f"{adapter} reported an external_state outside its evidenced "
            "vocabulary (design §6 归一化闸 / §13 UnrecognizedExternalState). "
            "Refused — an unrecognized state is NEVER downgraded to unknown and "
            "NEVER to reconciliation_failed; NO Outcome Fact is produced.",
            adapter=adapter,
        )
    return StateMapping(
        adapter=adapter,
        outcome_status=outcome_status,
        observed_state=word,
        normalized_state=candidate,
        mapping_reason=(
            f"{adapter} external state matched the {outcome_status} vocabulary "
            f"[{vocab.evidence}]"
        ),
    )
