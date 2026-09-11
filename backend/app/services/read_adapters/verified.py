"""Trusted Reader PROOF types + the single creation-effect verifier.

WHERE THIS LIVES — AND WHY. The M2-R source-isolation Amendment
(``docs/design/phase3.4.5-m2-r-thehive-source-isolation-amendment.md``) stopped at
DESIGN-ONLY: the 2-parameter ``normalize_external_state`` mapping is
PATH-AGNOSTIC, so the synthesized ``case_created`` word could be forged from the
LIVE webhook inbound path (a valid callback token + a schema/correlation-valid body
carrying the bare string) — the G1-A defect class. M2-R fail-closed that by
EMPTYING the thehive vocabulary, so ``case_created`` now maps to NOTHING on EVERY
path (zero fact). That is safe but it also means a verified creation could
not be confirmed from ANY source.

M3 (this module + ``outcomes/verified_proof.py`` + ``TheHiveReadAdapter.read_creation``)
opens the SOURCE-ISOLATED channel the Amendment designed, per the user's formal
ruling recorded in Amendment :

— a TYPED INTERNAL proof (``VerifiedReadResult`` / ``VerifiedCreationEffect``)
used ONLY by the internal trusted read service. An arbitrary
``raw_evidence`` Mapping is NOT an authorization credential, and the PUBLIC ``AdapterReadResult`` is NOT extended (its field set is hard-sealed
to ``{external_state, observed_at, raw_evidence}`` by
``test_adapter_read_contract.py``).
— strict correlation lives in the PULL-only read-orchestration / proof-
verification layer, using a ``ReadCorrelationContext`` the PLATFORM derives
from IMMUTABLE history. The ``AdapterReadRequest`` is NOT extended
(its field set is hard-sealed to ``{execution_id, adapter,
external_reference}``).

THE THREE BINDING CONSTRAINTS THIS MODULE HONORS:

1. AN INTERNAL TYPE IS NOT A MAGIC CREDENTIAL. A ``dataclass`` cannot stop
arbitrary code from constructing a same-named object. The real security boundary
is the CONTROLLED CALL CHAIN, not the type name: this verifier is reachable ONLY
from ``outcomes/verified_proof.reconcile_verified_execution`` (an authenticated-
operator PULL orchestration); the proof data comes ONLY from a platform-controlled
source (a factory-authorized trusted reader's real ``GET`` + facts derived from
the immutable ``execution_log``); the reconcile request body is EMPTY with
``extra="forbid"`` so a client cannot inject ANY proof/context/verified field; NO
route accepts a client-constructed ``VerifiedReadResult`` / ``VerifiedCreationEffect``
/ ``ReadCorrelationContext``; and the webhook path is a SEPARATE function graph
that never reaches this verifier. "Do not import" is NOT the only defense — the
call-chain reachability is (proven by AST + runtime tests in the M3 suite).
2. HISTORY IS NEVER FABRICATED. ``ReadCorrelationContext`` carries ONLY facts that
really exist in the immutable dispatch chain + the A pre-dispatch binding.
Amendment source-verified that the target INSTANCE / TENANT binding DOES NOT
EXIST in ``ExecutionLog`` nor in the TheHive 4.1.24-1 ``OutputCase``, so the A
binding records ``target_instance`` / ``target_tenant`` as ``None`` and
``instance_binding`` / ``tenant_binding`` stay ``None`` (UNKNOWN) for ALL real history
— NEVER back-filled from the binding's config-declared endpoint / version, NEVER from
the CURRENT config. Gate 5 therefore FAILS CLOSED for every real historical execution.
3. VERSION CONFIG IS NOT A LIVENESS PROOF. ``THEHIVE_EXPECTED_VERSION == 4.1.24-1``
only proves an operator CONFIGURED that expectation; it does NOT prove the remote
server actually runs it. Nothing here treats a config string as a live proof.

PURE, SIDE-EFFECT FREE. This module is declarative types + constants + TWO pure
adjudicators: ``verify_creation_effect`` (the six-gate creation verdict) and, since
B, ``assess_identity_evidence``. It imports NO sqlalchemy, NO HTTP, NO
``app.models``, NO ``app.services.outcomes``, NO ``app.services.executions`` — only
stdlib and the pure A1 read-contract request shape. The DB-owning derivation /
orchestration / persistence live in ``outcomes/verified_proof.py`` (which MAY own a
transaction); the dependency direction is one-way (outcomes -> this pure module),
never the reverse.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol, runtime_checkable

from app.services.manual_reconcile.read.base import AdapterReadRequest

#
# The approved creation action + approval status (gate 6)
#
# The ONLY TheHive action this platform dispatches (``executions.thehive.THEHIVE_ACTIONS``
# = ``{"escalate_to_incident}``). Gate 6 requires the immutable dispatch chain's
# server-snapshotted ``action`` to EQUAL this — a case Resolved / a task Completed /
# a Cortex job / any other effect is NEVER this action's creation effect (Amendment
# "case created != case resolved"). Declared here (not imported from the WRITE
# side) to keep the read/proof layer physically isolated from ``app.services.executions``
# ; an M3 Component test pins this string is a member of the frozen
# ``THEHIVE_ACTIONS`` so the two can never silently drift.
APPROVED_CREATION_ACTION = "escalate_to_incident"

# The approval status gate 6 requires on the chain's linked ``AIResponseApproval``.
# A dispatch that was never ``approved`` (requested / rejected / absent) is NEVER a
# verified creation effect — the reference must come from an APPROVED escalate.
APPROVED_APPROVAL_STATUS = "approved"

# The proof scope stamped into the whitelisted Outcome detail: declares this
# ``confirmed_success`` arrived through the trusted creation-proof channel, NOT the
# shared (empty) external-state vocabulary.
PROOF_SCOPE_VERIFIED_CREATION = "verified_creation"


#
# Gate identities + fail-closed reason codes
#
# The six conjunctive gates, in evaluation order. EVERY one must pass for a
# ``VerifiedCreationEffect``; the FIRST failure yields a ``CreationRefusal`` carrying
# its gate + a SAFE STATIC reason code (never a secret, never a raw reference value).
GATE_IDENTITY = "identity"
GATE_CORRELATION = "correlation"
GATE_CREATION_TIME = "creation_time"
GATE_TIME_ORDER = "time_order"
GATE_INSTANCE_TENANT = "instance_tenant"
GATE_APPROVED_ACTION = "approved_action"

# gate 1 — IDENTITY
REASON_NO_STRING_RESOURCE_ID = "no_string_resource_id"
REASON_RESOURCE_ID_MISMATCH = "resource_id_mismatch"
REASON_REFERENCE_UNKNOWN = "reference_unknown"
# gate 2 — CORRELATION
REASON_MISSING_EXECUTION_CORRELATION_TAG = "missing_execution_correlation_tag"
# gate 3 — CREATION-TIME
REASON_MISSING_CREATED_AT = "missing_created_at"
# gate 4 — TIME-ORDER
REASON_DISPATCH_STARTED_AT_UNKNOWN = "dispatch_started_at_unknown"
REASON_TERMINAL_RECORDED_AT_UNKNOWN = "terminal_recorded_at_unknown"
REASON_CREATED_BEFORE_DISPATCH = "created_before_dispatch"
REASON_CREATED_OUT_OF_WINDOW = "created_out_of_window"
REASON_DISPATCH_CREATED_AT_UNKNOWN = "dispatch_created_at_unknown"
REASON_DISPATCH_CREATED_AT_MISMATCH = "dispatch_created_at_mismatch"
# gate 5 — INSTANCE / TENANT
REASON_INSTANCE_BINDING_UNKNOWN = "instance_binding_unknown"
REASON_INSTANCE_MISMATCH = "instance_mismatch"
REASON_TENANT_BINDING_UNKNOWN = "tenant_binding_unknown"
REASON_TENANT_MISMATCH = "tenant_mismatch"
# gate 6 — APPROVED ACTION + dispatch-time approval snapshot + execution-snapshot consistency
REASON_UNAPPROVED_ACTION = "unapproved_action"
REASON_APPROVAL_NOT_APPROVED = "approval_not_approved"
REASON_APPROVAL_SNAPSHOT_INCONSISTENT = "approval_snapshot_inconsistent"
REASON_REFERENCE_NOT_FROM_TERMINAL_SUCCESS = "reference_not_from_terminal_success"


#
# Bounded time window (gate 4) — DEFENSE-IN-DEPTH, NOT an authoritative number
#
# Bounded clock-skew tolerance for the "created before dispatch" sanity check.
#
# WHY THIS VALUE. This is NOT the
# authoritative creation bound — the AUTHORITATIVE gate-4 check is the EXACT match
# against ``dispatch_created_at_millis`` (the ``createdAt`` the platform PERSISTED
# into the immutable terminal ``succeeded`` row's ``raw_response`` at dispatch time).
# A live-read ``createdAt`` that does not EQUAL that immutable value is refused
# (``dispatch_created_at_mismatch``) with NO window involved. This skew bound is a
# DEFENSE-IN-DEPTH sanity check that independently rejects an absurd ``createdAt``
# (the reviewer's ten-year-old re-tagged-case probe) EVEN IF the exact-match source
# fact were somehow absent. Its magnitude mirrors the platform's existing frozen
# bounded-skew precedent ``reconciliation.MAX_FUTURE_SKEW``:
# SentinelFlow stamps the ``succeeded`` row's ``created_at`` (``dispatch_time``)
# AFTER the synchronous ``POST /api/case`` returns, so a legitimate ``createdAt``
# precedes ``dispatch_time`` by well under a second; 300s is a generous cross-clock
# (SentinelFlow host vs TheHive host) NTP-skew tolerance, never a claim about the
# real creation window.
MAX_DISPATCH_CLOCK_SKEW = timedelta(seconds=300)

# Bounded forward window for the "created out of window" sanity check.
#
# Same discipline as ``MAX_DISPATCH_CLOCK_SKEW``: a DEFENSE-IN-DEPTH bound, NOT the
# authoritative gate (the exact immutable ``dispatch_created_at_millis`` match is).
# A case is created DURING the synchronous ``POST``, so its ``createdAt`` cannot be
# meaningfully LATER than the ``dispatch_time`` row-stamp that follows the response;
# more than 300s of forward skew (the ``MAX_FUTURE_SKEW`` precedent) is an absurd
# future-dated ``createdAt`` (a probe) and is refused. It is NEVER used to gain a
# sorting advantage for a missing/early time.
MAX_CREATION_WINDOW = timedelta(seconds=300)


def created_at_to_datetime(value: object) -> datetime | None:
    """Convert an ``OutputCase.createdAt`` (epoch MILLISECONDS) to an aware UTC
datetime, or ``None`` when it is absent / malformed / absurd. PURE.

This is the M3 proof-layer canonical converter. It is SEMANTICALLY IDENTICAL to
``read_adapters.thehive._created_at_to_datetime`` (the M2 read-path helper,
preserved byte-identical so the sealed ``read()`` never changes); an M3 Component
test pins the two agree on a matrix (epoch millis / bool / non-number / out-of-range
/ None) so the proof layer and the read path can never drift. ScalliGraph
serializes a ``Date`` as ``JsNumber(d.getTime)`` (milliseconds); a ``bool`` is NOT
a timestamp (``isinstance(True, int)`` is True in Python, so it is excluded);
``datetime.fromtimestamp`` can raise on an out-of-range value, and any failure
yields ``None``.
"""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return datetime.fromtimestamp(value / 1000.0, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def created_at_millis(value: object) -> int | None:
    """The RAW epoch-milliseconds ``createdAt`` as an ``int``, or ``None`` when it is
absent / a bool / a non-integer / malformed. PURE.

Gate 4's AUTHORITATIVE exact match compares the live-read ``createdAt`` against the
immutable ``dispatch_created_at`` on these RAW INTEGERS (not the converted
datetimes), so the decisive check is independent of any datetime-conversion
precision concern: the same external case always re-serves the SAME immutable
``createdAt`` millis, and a different (historical / cross-instance) case never does.
A ``float`` millis is refused (ScalliGraph emits an integer ``JsNumber`` for a
``Date``; a float is not a faithful creation timestamp).
"""
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


#
# The typed observation a TRUSTED reader returns
#
@dataclass(frozen=True, slots=True)
class VerifiedReadResult:
    """The TYPED observation an internal TRUSTED reader returns from ``read_creation``.

It is a faithful OBSERVATION, never a VERDICT: the reader reports WHAT IT SAW on
the single ``GET`` and ``verify_creation_effect`` adjudicates it against the
platform-derived immutable ``ReadCorrelationContext``. Fields:

resource_id -- the fetched string ``_id`` (fallback ``id``) EXACTLY as observed,
even when it does NOT match the persisted reference (so gate 1 can refuse
with the precise ``resource_id_mismatch`` reason). ``None`` when no string
id was present.
correlation_tag_present -- whether the resource's ``tags`` carried THIS
execution's ``sentinelflow:execution:{id}`` tag (the reader computes it with
the single-source-of-truth tag helper; the verifier trusts the reader's
observation because the reader is a platform-controlled, factory-authorized
component, NOT client input).
external_created_at / external_created_at_millis -- the authoritative EXTERNAL
creation time (``OutputCase.createdAt``) as an aware UTC datetime AND its raw
epoch-millis. ``None`` when absent / invalid (gate 3 refuses).
case_number -- the audit-only human ``caseId`` (an ``int``), NEVER the reference
and NEVER required; ``None`` when absent / non-int / a bool.
observed_instance / observed_tenant -- the instance / tenant identity the read
ACTUALLY hit. TheHive 4.1.24-1 ``OutputCase`` carries NEITHER, so the real reader ALWAYS sets both ``None`` -> gate 5 fails
CLOSED. Only a future forward-binding-capable reader could populate them; a test double simulates that shape.

Immutable (+ slots). Carries NO credential, NO raw response body, NO
outcome word.
"""

    resource_id: str | None
    correlation_tag_present: bool
    external_created_at: datetime | None
    external_created_at_millis: int | None
    case_number: int | None
    observed_instance: str | None
    observed_tenant: str | None


@runtime_checkable
class TrustedCreationReader(Protocol):
    """The internal trusted-reader capability.

A reader the PULL-only proof orchestration may hand an ``AdapterReadRequest`` to
for a TYPED creation observation. ``isinstance`` against this ``runtime_checkable``
Protocol checks ONLY the presence of ``read_creation`` — the TRUST does NOT come
from the type name (a dataclass / Protocol cannot stop arbitrary code from
implementing it). It comes from the CONTROLLED CALL CHAIN: the orchestration is
reachable only from an authenticated-operator PULL entrypoint, and the reader
instance is obtained from the settings-driven factory whose THREE fail-closed gates
(well-formed base URL + an INDEPENDENT read-only key + an EXACT certified-version
match) are the real trust anchor (``read_adapters.registry``). The public
``ReadAdapter.read`` verb is UNCHANGED; ``read_creation`` is an ADDITIONAL internal
read verb on the concrete reader (it is a READ, never a write verb, so the
write-verb-absence seal is untouched).
"""

    def read_creation(self, request: AdapterReadRequest) -> VerifiedReadResult:
        """One ``GET`` -> the typed creation observation (never a mutation, never a
retry, never a verdict)."""
        ...


#
# The platform-derived immutable correlation context
#
@dataclass(frozen=True, slots=True)
class ReadCorrelationContext:
    """The IMMUTABLE dispatch facts the PLATFORM derives from the historical
``execution_log`` chain — the strict-correlation half the ``AdapterReadRequest`` does NOT carry.

Built ONLY by ``outcomes/verified_proof.derive_read_correlation_context`` from a
read-only SELECT of the chain + the immutable PRE-DISPATCH BINDING carried in
the ``dispatched`` row's detail; NEVER from an HTTP request body, NEVER from the
current config. Fields whose immutable fact DOES NOT EXIST stay ``None`` (UNKNOWN)
and are NEVER back-filled (constraint #2). D splits the time semantics and moves
gate 6 onto the DISPATCH-TIME approval snapshot:

execution_id / adapter / external_reference -- the correlated chain identity +
the adapter (``detail["executor"]`` of the first row) + the persisted STRING
resource reference (``detail["case_id"]`` of the terminal ``succeeded`` row).
approved_action -- the server-snapshotted ``action`` column (``escalate_to_incident``);
NEVER accepted from a request body.
approval_status_at_dispatch -- the linked approval's status CAPTURED IN THE BINDING
BEFORE the external request. Gate 6 uses THIS dispatch-time snapshot,
NEVER the live ``approval.status`` re-read at reconcile time. ``None`` when no
binding exists (old history) -> gate 6 fails closed.
bound_approval_id / bound_action / bound_target -- the binding's execution snapshot
of the approved approval_id / action / target. Gate 6 cross-checks them against
the chain's immutable ``chain_approval_id`` / ``approved_action`` / ``chain_target``
so a tampered / cross-execution binding is refused. ``None`` with no binding.
chain_approval_id / chain_target -- the chain's immutable ``approval_id`` / ``target``
columns (the requested row), the cross-check counterparts of the bound_* snapshot.
dispatch_started_at -- the REAL dispatch START: when the platform BEGAN the
external request, from the binding (recorded BEFORE the request). ``None`` when no
binding exists (old history) -> gate 4 fails closed. This is NEVER the terminal
row's ``created_at``.
terminal_recorded_at -- the immutable SERVER ``created_at`` of the TERMINAL row: when
the platform RECORDED the terminal state AFTER the response. The gate-4 upper
bound. ``None`` if absent (gate 4 fails closed).
dispatch_created_at / dispatch_created_at_millis -- the EXTERNAL ``createdAt`` the
platform PERSISTED into the terminal ``succeeded`` row's ``raw_response`` at
dispatch time (the authoritative gate-4 exact-match source). ``None`` if the
immutable fact is absent (gate 4 fails closed — NEVER re-derived from the live
read, NEVER from config).
instance_binding / tenant_binding -- the target instance / tenant the dispatch was
BOUND to, read from the binding's ``target_instance`` / ``target_tenant``.
TheHive 4.1.24-1 records ``None`` (no authoritative dispatch-time identity source)
and old history has no binding, so they are ``None`` (UNKNOWN) for ALL real
executions and gate 5 FAILS CLOSED — NEVER back-filled from the
binding's config-declared endpoint / version, NEVER from the current config.
reference_from_terminal_success -- whether ``external_reference`` came from a
terminal ``succeeded`` row (gate 6: the reference must be the persisted result
of the corresponding execution, never a fabricated handle).

Immutable (+ slots). Carries NO credential, NO operator, NO callback token.
"""

    execution_id: uuid.UUID
    adapter: str
    external_reference: str | None
    approved_action: str | None
    # D gate 6 — the DISPATCH-TIME approval snapshot (from the binding), NEVER live.
    approval_status_at_dispatch: str | None
    # D gate 6 — the binding's execution snapshot, cross-checked against the chain.
    bound_approval_id: str | None
    bound_action: str | None
    bound_target: str | None
    # D gate 6 — the chain's immutable counterparts of the bound_* snapshot.
    chain_approval_id: str | None
    chain_target: str | None
    # D gate 4 — the REAL dispatch START (binding) vs the TERMINAL RECORD time.
    dispatch_started_at: datetime | None
    terminal_recorded_at: datetime | None
    dispatch_created_at: datetime | None
    dispatch_created_at_millis: int | None
    instance_binding: str | None
    tenant_binding: str | None
    reference_from_terminal_success: bool


#
# The verifier's two verdicts
#
# Module-private MINT SEAL. ``verify_creation_effect`` is the ONLY place this sentinel is
# stamped into a ``VerifiedCreationEffect``; ``_persist_verified_creation_outcome`` checks
# ``effect.is_sealed()`` BEFORE writing a ``confirmed_success``.
#
# NOT A MAGIC CREDENTIAL. A determined caller can reach
# ``verified._VERIFIER_SEAL`` and forge a sealed effect — a Python attribute is never an
# unforgeable token, and this module does NOT claim otherwise. The seal is a STRUCTURAL
# consistency layer that makes persist ACTIVELY refuse a PLAIN hand-constructed effect (the
# C boundary fix: persist no longer trusts the TYPE NAME alone). The REAL boundary is the
# CONTROLLED CALL CHAIN, proven by AST in the isolation suite: ``VerifiedCreationEffect`` has
# EXACTLY ONE construction site (``verify_creation_effect``) and the private persist has
# EXACTLY ONE caller (``reconcile_verified_execution``).
#
# ANTI-MISUSE, NOT AUTHORIZATION. The seal + the private
# persist are INTERNAL misuse-guards ONLY: they stop an ACCIDENTAL plain-object persist, they
# are NOT an authentication / authorization mechanism and NEVER replace one. There is NO
# production router on this channel today (the sealed registry stays empty — proven in the
# isolation suite), so there is no external entry to guard yet. WHEN a trusted proof entry is
# ever wired it MUST reuse the EXISTING operator identity + RBAC + the Manual Reconcile
# permission, and its Reader MUST come from the TRUSTED REGISTRY FACTORY — NEVER injected by
# a request body or an arbitrary caller. A Python type, a boolean flag or this seal is NEVER
# an external identity credential; authorization stays a SERVICE-LAYER responsibility,
# UPSTREAM of ``is_sealed()`` — the seal is the last structural check, never the first line
# of trust.
_VERIFIER_SEAL = object()


@dataclass(frozen=True, slots=True)
class VerifiedCreationEffect:
    """The POSITIVE verdict: ALL SIX conjunctive gates passed, so the trusted read
INDEPENDENTLY proves THIS approved execution created THIS case.

This is the ONLY thing that authorizes a ``confirmed_success`` Outcome Fact on the
source-isolated channel — and it is produced ONLY by ``verify_creation_effect``
from a platform-derived ``ReadCorrelationContext`` + a trusted ``VerifiedReadResult``.
It is NOT constructible from an HTTP body (no route accepts one) and NOT reachable
from the webhook path.

C MINT SEAL. ``verify_creation_effect`` stamps the module-private ``_VERIFIER_SEAL``
into ``seal``; ``_persist_verified_creation_outcome`` REFUSES an effect whose
``is_sealed()`` is False, so a PLAIN hand-constructed ``VerifiedCreationEffect`` can no
longer be fed straight to persist to write ``confirmed_success``. The seal is NOT a magic credential (constraint #1) — the real boundary is
the AST-proven single construction site + single persist caller.

Carries ONLY what the whitelisted persistence detail needs: the correlated
identity, the authoritative EXTERNAL creation time (-> the fact's ``observed_at``,
``observed_at_kind="external"``), the audit-only case number, and the two gate-5
verification BOOLEANS (``instance_verified`` / ``tenant_verified``) — NEVER the raw
instance / tenant VALUES. Immutable.
"""

    execution_id: uuid.UUID
    adapter: str
    external_reference: str
    external_created_at: datetime
    case_number: int | None
    instance_verified: bool
    tenant_verified: bool
    # C mint seal — the module-private ``_VERIFIER_SEAL``, stamped ONLY by
    # ``verify_creation_effect``. A plain hand-built effect carries something else and
    # ``is_sealed()`` is False. NOT a secret, NOT a magic credential (constraint #1).
    seal: object

    def is_sealed(self) -> bool:
        """Whether THIS effect was minted by ``verify_creation_effect`` (the ONLY place the
private ``_VERIFIER_SEAL`` is stamped). ``_persist_verified_creation_outcome`` checks
this BEFORE writing, so persist never trusts the TYPE NAME alone (constraint #1)."""
        return self.seal is _VERIFIER_SEAL


@dataclass(frozen=True, slots=True)
class CreationRefusal:
    """The NEGATIVE verdict: at least one gate FAILED, so the read does NOT prove a
verified creation.

A refusal produces ZERO Outcome Fact and is NEVER ``confirmed_failure`` (the case
may exist but be unprovable as THIS execution's effect, or may have been created
then re-tagged / deleted — a refused proof is not proof of failure) and NEVER
``reconciliation_failed`` (that is the read-TRANSPORT-failure verdict, a separate
path). ``gate`` / ``reason`` are SAFE STATIC codes for diagnostics; they echo NO
secret and NO raw reference value. Immutable.
"""

    gate: str
    reason: str


def verify_creation_effect(
    context: ReadCorrelationContext, observed: VerifiedReadResult
) -> VerifiedCreationEffect | CreationRefusal:
    """THE single trusted creation-effect verifier. PURE: no DB, no HTTP, no side effect, no mutation of either input.

Cross-checks a trusted reader's OBSERVATION (``observed``) against the PLATFORM-
derived IMMUTABLE dispatch facts (``context``) through the SIX conjunctive gates of
Amendment , in order. The FIRST failing gate yields a ``CreationRefusal`` (its
gate + a safe static reason); ALL SIX passing yields a ``VerifiedCreationEffect``.
This function is the crux of the source-isolation channel: it is the ONLY place a
``confirmed_success`` can be authorized, and it can only be fed a context the
platform built from immutable history and an observation a trusted reader returned
— NEVER a client-supplied proof.

THE SIX GATES:

1. IDENTITY — the observed string ``resource_id`` is a non-empty str EQUAL to the
persisted ``external_reference`` (the terminal ``succeeded`` row's ``case_id``).
2. CORRELATION — the observed resource carried THIS execution's correlation tag.
3. CREATION-TIME — an authoritative external ``createdAt`` was observed (a valid
aware datetime), never a server-observation substitute.
4. TIME-ORDER — ``createdAt`` is not absurdly before the REAL dispatch START
(``dispatch_started_at``, from the binding — NOT the terminal ``created_at``), not
absurdly after the TERMINAL-RECORD time (``terminal_recorded_at``), and — the
AUTHORITATIVE, decisive check — its RAW epoch-millis EQUALS the immutable
``dispatch_created_at_millis`` the platform persisted at dispatch time. The 300s
skew bounds are DEFENSE-IN-DEPTH, NEVER the authoritative creation window; the
EXACT match kills the ten-year-old re-tagged-case probe with NO arbitrary window.
5. INSTANCE / TENANT — the observed instance / tenant EQUAL the dispatch-time
bindings. For ALL real history both bindings are
UNKNOWN (``None`` — TheHive 4.1.24-1 records none, old history has no binding)
-> FAIL CLOSED; the real 4.1.24-1 reader also observes ``None`` -> a second
fail-closed. NO confirmed_success is reachable for real history until lands.
6. APPROVED ACTION — the immutable dispatch ``action`` is the approved
``escalate_to_incident``; the binding's execution snapshot (approval_id / action /
target) EQUALS the chain's immutable approved facts; the DISPATCH-TIME approval
snapshot (``approval_status_at_dispatch``, NEVER the live status) is ``approved``;
and the reference came from a terminal ``succeeded`` row (never a fabricated handle).

A missing immutable fact (``dispatch_time`` / ``dispatch_created_at_millis`` /
``instance_binding`` / ``tenant_binding``) is NEVER treated as a pass and NEVER
back-filled from config — it fails the relevant gate closed (constraint #2).
"""
    # gate 1: IDENTITY ----------------------------------------------------
    resource_id = observed.resource_id
    if not isinstance(resource_id, str) or not resource_id:
        return CreationRefusal(GATE_IDENTITY, REASON_NO_STRING_RESOURCE_ID)
    if not isinstance(context.external_reference, str) or not context.external_reference:
        # The platform could not derive an immutable reference -> fail closed (never
        # accept an observed id with nothing to match it against).
        return CreationRefusal(GATE_IDENTITY, REASON_REFERENCE_UNKNOWN)
    if resource_id != context.external_reference:
        # A DIFFERENT case answered (cross-instance / historical same-number) -> never
        # this execution's effect.
        return CreationRefusal(GATE_IDENTITY, REASON_RESOURCE_ID_MISMATCH)

    # gate 2: CORRELATION -------------------------------------------------
    if observed.correlation_tag_present is not True:
        return CreationRefusal(
            GATE_CORRELATION, REASON_MISSING_EXECUTION_CORRELATION_TAG
        )

    # gate 3: CREATION-TIME -----------------------------------------------
    created = observed.external_created_at
    if not isinstance(created, datetime) or created.tzinfo is None:
        # Absent / invalid / naive -> no authoritative external creation time. The
        # verifier NEVER substitutes a server-observation time.
        return CreationRefusal(GATE_CREATION_TIME, REASON_MISSING_CREATED_AT)

    # gate 4: TIME-ORDER --
    # The REAL dispatch START (when the platform BEGAN the POST, from the immutable
    # pre-dispatch binding) and the TERMINAL-RECORD time (when the terminal row was
    # stamped AFTER the response) BOUND the request lifecycle. The external createdAt
    # must fall inside [dispatch_started_at - skew, terminal_recorded_at + skew] — NOT a
    # symmetric window around the terminal stamp (the M3 conflation D fixes: the
    # terminal created_at is NEVER passed off as the request start).
    dispatch_started_at = context.dispatch_started_at
    if not isinstance(dispatch_started_at, datetime) or dispatch_started_at.tzinfo is None:
        return CreationRefusal(GATE_TIME_ORDER, REASON_DISPATCH_STARTED_AT_UNKNOWN)
    terminal_recorded_at = context.terminal_recorded_at
    if not isinstance(terminal_recorded_at, datetime) or terminal_recorded_at.tzinfo is None:
        return CreationRefusal(GATE_TIME_ORDER, REASON_TERMINAL_RECORDED_AT_UNKNOWN)
    # 4a. not absurdly BEFORE the REAL dispatch start (defense-in-depth skew bound;
    # independently kills the ten-year-old re-tagged probe).
    if created < dispatch_started_at - MAX_DISPATCH_CLOCK_SKEW:
        return CreationRefusal(GATE_TIME_ORDER, REASON_CREATED_BEFORE_DISPATCH)
    # 4b. not absurdly AFTER the terminal record (defense-in-depth forward window).
    if created > terminal_recorded_at + MAX_CREATION_WINDOW:
        return CreationRefusal(GATE_TIME_ORDER, REASON_CREATED_OUT_OF_WINDOW)
    # 4c. AUTHORITATIVE exact match against the immutable dispatch-time createdAt. The
    # 300s skew bounds above are DEFENSE-IN-DEPTH, NEVER the authoritative creation
    # window — this exact epoch-millis equality is decisive.
    if context.dispatch_created_at_millis is None:
        return CreationRefusal(GATE_TIME_ORDER, REASON_DISPATCH_CREATED_AT_UNKNOWN)
    if observed.external_created_at_millis != context.dispatch_created_at_millis:
        return CreationRefusal(GATE_TIME_ORDER, REASON_DISPATCH_CREATED_AT_MISMATCH)

    # gate 5: INSTANCE / TENANT --
    if context.instance_binding is None:
        return CreationRefusal(GATE_INSTANCE_TENANT, REASON_INSTANCE_BINDING_UNKNOWN)
    if observed.observed_instance is None or observed.observed_instance != context.instance_binding:
        return CreationRefusal(GATE_INSTANCE_TENANT, REASON_INSTANCE_MISMATCH)
    if context.tenant_binding is None:
        return CreationRefusal(GATE_INSTANCE_TENANT, REASON_TENANT_BINDING_UNKNOWN)
    if observed.observed_tenant is None or observed.observed_tenant != context.tenant_binding:
        return CreationRefusal(GATE_INSTANCE_TENANT, REASON_TENANT_MISMATCH)

    # gate 6: APPROVED ACTION + dispatch-time approval snapshot + execution-snapshot
    # consistency ----------------------
    # 6a. the immutable dispatch action is the approved creation action.
    if context.approved_action != APPROVED_CREATION_ACTION:
        return CreationRefusal(GATE_APPROVED_ACTION, REASON_UNAPPROVED_ACTION)
    # 6b. the pre-dispatch BINDING's execution snapshot (action / target / approval_id)
    # MUST equal the chain's immutable approved facts — the binding corresponds to
    # THIS approved recommendation, not a tampered / cross-execution one.
    if context.bound_action != context.approved_action:
        return CreationRefusal(GATE_APPROVED_ACTION, REASON_APPROVAL_SNAPSHOT_INCONSISTENT)
    if context.bound_target != context.chain_target:
        return CreationRefusal(GATE_APPROVED_ACTION, REASON_APPROVAL_SNAPSHOT_INCONSISTENT)
    if context.bound_approval_id != context.chain_approval_id:
        return CreationRefusal(GATE_APPROVED_ACTION, REASON_APPROVAL_SNAPSHOT_INCONSISTENT)
    # 6c. the DISPATCH-TIME approval snapshot (captured BEFORE the external request) MUST
    # be ``approved`` — the authoritative fact, NOT the live status re-read now.
    if context.approval_status_at_dispatch != APPROVED_APPROVAL_STATUS:
        return CreationRefusal(GATE_APPROVED_ACTION, REASON_APPROVAL_NOT_APPROVED)
    # 6d. the reference came from a terminal succeeded row (never a fabricated handle).
    if context.reference_from_terminal_success is not True:
        return CreationRefusal(
            GATE_APPROVED_ACTION, REASON_REFERENCE_NOT_FROM_TERMINAL_SUCCESS
        )

    # ALL SIX GATES PASSED -> the verified creation effect ----------------
    return VerifiedCreationEffect(
        execution_id=context.execution_id,
        adapter=context.adapter,
        external_reference=resource_id,
        external_created_at=created,
        case_number=observed.case_number,
        # gate 5 passed, so both bindings matched an authenticated dispatch-time fact.
        instance_verified=True,
        tenant_verified=True,
        # C: the ONE AND ONLY mint site of the private seal — persist refuses an effect
        # that does not carry it, so a plain hand-built object can never reach confirmed_success.
        seal=_VERIFIER_SEAL,
    )


#
# B: the read-side IDENTITY / VERSION evidence seam
#
# WHY THIS EXISTS. Gate 5 (INSTANCE / TENANT) fails CLOSED for every real historical
# execution because TheHive 4.1.24-1 exposes NO authoritative dispatch-time instance /
# tenant binding. A added the DISPATCH-side binding (it records
# target_instance / target_tenant as None for 4.1.24-1 — no authoritative source existed).
# B is the READ-side half: forensically identify and probe the
# AUTHORITATIVE version / instance / organisation / permission interfaces the EXACT
# certified version supports, and assess the evidence FAIL-CLOSED. SOURCE FORENSICS
# (TheHive 4.1.24-1 = git b6649bb / ScalliGraph 2c2a7a4; /api/ -> the v0 default router,
# TheHiveRouter.scala:25) establishes:
#
# GET /api/status (v0 StatusCtrl, PUBLIC — entrypoint("status"){...} with NO
# .auth* chain, ScalliGraph Entrypoint.scala:153) returns
# versions.TheHive / versions.Scalligraph from the running JARs'
# getImplementationVersion — a REAL RUNTIME version observation,
# NOT the config-declared THEHIVE_EXPECTED_VERSION. The SAME body
# ALSO carries config.protectDownloadsWith (the attachment-ZIP
# password — a SECRET), so a probe MUST extract ONLY the version
# field and NEVER return / log / persist the raw body.
# GET /api/user/current (v0 UserCtrl.current, AUTHENTICATED — .authRoTransaction, 401 if
# the read-only key is invalid) returns OutputUser.organisation
# (String) + roles (Set[String]) — the READER's OWN organisation
# (tenant context) and RBAC roles.
# GET /api/system DOES NOT EXIST in the 4.1.24-1 source (zero matches) — it is a
# CANDIDATE only and is NEVER assumed (the task's explicit rule).
# GET /api/case/{id} OutputCase (v0/v1) carries NO organisation field, and TheHive's
# visibility model returns 200 for a case OWNED *OR SHARED* into
# the reader's organisation (a 404 merges absent + tenant-invisible).
#
# THE HONEST CONCLUSION (why gate 5 STAYS fail-closed even with this seam). The reader's OWN
# organisation (/api/user/current) is NOT the CASE's owner, and a 200 on /api/case/{id} proves
# only VISIBILITY, never ownership; /api/status exposes NO stable instance identity. So for
# 4.1.24-1 NEITHER a case-owned tenant NOR a bindable instance identity is observable —
# Amendment -B B2's precondition ("the target version's OutputCase contains organisation")
# is UNMET. This seam therefore UPGRADES the version assertion from config-declaration to a
# runtime observation and establishes the reader's authenticated tenant context, but it NEVER
# fabricates a gate-5 binding: assess_identity_evidence ALWAYS returns instance / tenant = None
# for 4.1.24-1, so it can NEVER unlock confirmed_success on its own. A base URL or a config
# string is NEVER treated as a real identity.

# SAFE STATIC probe-outcome kinds (never a secret, never a raw value). ``observed`` = a real
# read-only GET returned the field; ``unavailable`` = the probe failed OR the field was absent
# > INSUFFICIENT evidence (fail-closed).
IDENTITY_PROBE_OBSERVED = "observed"
IDENTITY_PROBE_UNAVAILABLE = "unavailable"

# SAFE STATIC reasons the gate-5 binding STAYS None / the evidence is insufficient. The deepest
# structural blocker (4.1.24-1) is that the CASE-owned organisation is unobservable, so even a
# fully-observed version + reader organisation can NEVER bind the case's tenant / instance.
IDENTITY_REASON_VERSION_UNOBSERVED = "version_unobserved"
IDENTITY_REASON_VERSION_NOT_CERTIFIED = "version_not_certified"
IDENTITY_REASON_READER_ORG_UNOBSERVED = "reader_organisation_unobserved"
IDENTITY_REASON_CASE_OWNER_UNOBSERVABLE = "case_owner_organisation_unobservable"


@dataclass(frozen=True, slots=True)
class IdentityEvidence:
    """B: the TYPED OBSERVATION a read-side identity/version probe returns — the read-side counterpart of ``VerifiedReadResult``. NEVER a VERDICT
(``assess_identity_evidence`` adjudicates), NEVER a credential, NEVER a raw response body.

observed_version -- ``versions.TheHive`` from ``GET /api/status`` (the AUTHORITATIVE
RUNTIME version), or ``None`` when the probe failed / the field was absent.
observed_reader_organisation -- ``organisation`` from ``GET /api/user/current`` (the
READER's OWN tenant context, authenticated by the read-only key), or ``None``.
observed_reader_roles -- the reader's ``roles`` (RBAC evidence), sorted; ``()`` when absent.
version_probe / organisation_probe -- SAFE STATIC ``IDENTITY_PROBE_*`` kinds recording
whether each GET actually observed its field (diagnostics; never a secret).

Immutable (+ slots). It carries NO attachment password, NO base URL as identity,
NO case-owned tenant (unobservable in 4.1.24-1).
"""

    observed_version: str | None
    observed_reader_organisation: str | None
    observed_reader_roles: tuple[str, ...]
    version_probe: str
    organisation_probe: str


@dataclass(frozen=True, slots=True)
class IdentityAssessment:
    """B: the FAIL-CLOSED adjudication of an ``IdentityEvidence`` against the certified
version. PURE, side-effect free.

version_matches_certified -- the OBSERVED runtime version EQUALS ``CERTIFIED_THEHIVE_VERSION``
(a real liveness observation, DISTINCT from the config-declaration; False when the
version was unobserved or mismatched — a base URL / config string NEVER counts).
reader_organisation_known -- a real reader organisation was OBSERVED (the reader's tenant
context + RBAC are authenticated). This is the READER's org, NOT the case's owner.
gate5_instance_binding / gate5_tenant_binding -- ALWAYS ``None`` for TheHive 4.1.24-1: the
CASE-owned instance / tenant is UNOBSERVABLE (OutputCase has no organisation; /api/status
has no stable instance id), so gate 5 STAYS fail-closed REGARDLESS of probe success. NEVER
back-filled from the base URL, the config string, or the reader's own organisation.
reason -- a SAFE STATIC ``IDENTITY_REASON_*`` code naming the deepest blocker.

Immutable (+ slots).
"""

    version_matches_certified: bool
    reader_organisation_known: bool
    gate5_instance_binding: str | None
    gate5_tenant_binding: str | None
    reason: str


def assess_identity_evidence(
    evidence: IdentityEvidence, *, certified_version: str
) -> IdentityAssessment:
    """B PURE assessor: adjudicate read-side identity/version evidence FAIL-CLOSED. No DB, no HTTP, no side effect, no mutation of the input.

A base URL / config string is NEVER a real identity: ``version_matches_certified`` requires
the version to have been OBSERVED from ``/api/status`` AND to EQUAL ``certified_version``;
``reader_organisation_known`` requires the organisation to have been OBSERVED from
``/api/user/current``. The gate-5 instance / tenant binding is ALWAYS ``None`` for TheHive
4.1.24-1 — this assessor
NEVER unlocks gate 5; it records the version-liveness upgrade + the reader's tenant context
and states WHY the binding stays closed.
"""
    version = evidence.observed_version
    version_observed = isinstance(version, str) and bool(version)
    version_matches = version_observed and version == certified_version
    org = evidence.observed_reader_organisation
    org_known = isinstance(org, str) and bool(org)

    # Deepest-blocker reason, in order: version liveness, then the reader organisation, then the
    # STRUCTURAL case-owner unobservability that ALWAYS keeps gate 5 closed for 4.1.24-1.
    if not version_observed:
        reason = IDENTITY_REASON_VERSION_UNOBSERVED
    elif not version_matches:
        reason = IDENTITY_REASON_VERSION_NOT_CERTIFIED
    elif not org_known:
        reason = IDENTITY_REASON_READER_ORG_UNOBSERVED
    else:
        reason = IDENTITY_REASON_CASE_OWNER_UNOBSERVABLE

    return IdentityAssessment(
        version_matches_certified=version_matches,
        reader_organisation_known=org_known,
        # ALWAYS None for 4.1.24-1 -> gate 5 stays fail-closed.
        gate5_instance_binding=None,
        gate5_tenant_binding=None,
        reason=reason,
    )
