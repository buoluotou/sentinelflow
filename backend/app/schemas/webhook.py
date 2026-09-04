"""Pydantic schema of the webhook callback inbound body (Phase 3.4.4-B,
Webhook Gate 2 — Schema).

Position in the frozen four-gate webhook inbound pipeline:

    External System -> HTTP Webhook
        -> Gate 1 Authentication    (3.4.4-A, sealed f35852b)
        -> Gate 2 Schema            (THIS MODULE, 3.4.4-B)
        -> Gate 3 Correlation       (3.4.4-C)
        -> Gate 4 Semantic Mapping  (3.4.4-D)
        -> Outcome Fact Append      (3.4.4-E)

The client expresses OBSERVATION DATA ONLY: the four facts an external system
reports about one execution (``execution_id`` / ``external_reference`` /
``external_state`` / ``observed_at``). Everything that establishes TRUST and
PROVENANCE is a server-side construct and is deliberately NOT a client field:

  - ``source`` is ALWAYS ``"webhook"`` — the frozen ingress channel
    (``OUTCOME_SOURCES``, design §6); a client can never select
    ``"manual_reconcile"`` (spec §5);
  - ``adapter`` is ALWAYS the authenticated callback identity resolved by
    Gate 1 (3.4.4-A ``authenticate_callback``) — never a body field, so a
    client can never claim to be another adapter or become the trust root
    (spec §6);
  - ``operator`` is NEVER accepted — the future Outcome Fact's recorder is
    ``"adapter:{authenticated}"`` (design §7), never a client string
    (spec §7).

``extra="forbid"`` is the schema-level guard that turns ANY smuggled field
(``source`` / ``adapter`` / ``operator`` / ``outcome_status`` / ...) into a
422 at the boundary, before the Reconciliation Contract ever runs — the same
fact-smuggling discipline ``ExecuteRequest`` applies to execution intent.

This module is a PURE input boundary (spec §19): it performs NO database
query, NO correlation, NO external-state mapping, NO persistence. It types and
preserves the raw payload, then hands a well-formed ``ExternalObservation`` to
the 3.4.3-A contract (``validate_observation``), which owns ALL semantic
validation (empty ``external_reference``, naive / future ``observed_at``,
unknown ``adapter`` / ``source``). Schema = type + presence; Contract =
semantics — the two never duplicate each other (spec §9 / §10).
"""
import uuid
from collections.abc import Mapping
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.services.outcomes.reconciliation import ExternalObservation

#: The frozen webhook ingress channel (``OUTCOME_SOURCES``, design §6). The
#: server constructs it in ``to_external_observation``; a client can never
#: supply or override it (spec §5). A test cross-checks this literal against
#: ``OUTCOME_SOURCES`` so the channel name can never silently drift.
WEBHOOK_SOURCE = "webhook"


class WebhookCallbackRequest(BaseModel):
    """Body of ``POST /api/v1/webhooks/{adapter}`` — the raw external
    observation, nothing more.

    Four client-supplied facts, each TYPED here but NOT semantically validated
    (that is the 3.4.3-A contract's job — spec §9 / §10):

      - ``execution_id``: a UUID (FORMAT only — whether the chain EXISTS is
        Gate 3 Correlation, 3.4.4-C, spec §13);
      - ``external_reference``: a required string (PRESENCE only — an empty /
        whitespace value is refused downstream by ``validate_observation``,
        never by a second business rule here, spec §9);
      - ``external_state``: ``str | Mapping``, preserved RAW — no ``lower()`` /
        ``trim()`` / ``upper()`` / coercion; mapping it onto an outcome word is
        Gate 4's job (3.4.4-D), never this schema's, spec §8 / §14;
      - ``observed_at``: a datetime (TYPE only — timezone-awareness, UTC
        normalization and the bounded-future check all belong to
        ``validate_observation``; this schema copies no second timestamp rule,
        spec §10).

    ``extra="forbid"`` rejects ``source`` / ``adapter`` / ``operator`` / any
    unknown field as a 422 (spec §5 / §6 / §7 / §16).
    """

    model_config = ConfigDict(extra="forbid")

    execution_id: uuid.UUID
    external_reference: str
    external_state: str | Mapping
    observed_at: datetime


def to_external_observation(
    request: WebhookCallbackRequest, *, adapter: str
) -> ExternalObservation:
    """The explicit Schema -> Contract conversion boundary (spec §11).

    Builds the frozen 3.4.3-A ``ExternalObservation`` from a validated request
    PLUS the server-side trusted identity:

      - ``adapter`` is keyword-only and REQUIRED — it is the authenticated
        callback identity from Gate 1 (3.4.4-A), NEVER a body field, so the
        client can never become the trust root (spec §6);
      - ``source`` is ALWAYS ``WEBHOOK_SOURCE`` ("webhook") — the client can
        never select ``"manual_reconcile"`` (spec §5);
      - ``operator`` is not an ``ExternalObservation`` field at all — the
        future fact's recorder is derived server-side from the authenticated
        adapter (spec §7), never from the body.

    PURE conversion: it copies the four raw fields through UNCHANGED
    (``external_state`` preserved exactly as parsed) and performs NO
    validation, NO DB access, NO mapping. Semantic validation is the NEXT step
    (``validate_observation``), which the caller wires this output into — this
    function deliberately does not call it, so the schema layer stays a pure
    input boundary (spec §19).
    """
    return ExternalObservation(
        execution_id=request.execution_id,
        adapter=adapter,
        external_reference=request.external_reference,
        external_state=request.external_state,
        observed_at=request.observed_at,
        source=WEBHOOK_SOURCE,
    )
