"""Pydantic schema of the webhook callback inbound body.

Position in the four-gate webhook inbound pipeline:

External System -> HTTP Webhook
-> Gate 1 Authentication
-> Gate 2 Schema            (this module)
-> Gate 3 Correlation
-> Gate 4 Semantic Mapping
-> Outcome Fact Append

The client expresses observation data only: the four facts an external system
reports about one execution (``execution_id`` / ``external_reference`` /
``external_state`` / ``observed_at``). Everything that establishes trust and
provenance is a server-side construct and is not a client field:

- ``source`` is always ``"webhook"`` — the ingress channel
(``OUTCOME_SOURCES``); a client can never select ``"manual_reconcile"``;
- ``adapter`` is always the authenticated callback identity resolved by
Gate 1 (``authenticate_callback``) — never a body field, so a client can
never claim to be another adapter or become the trust root;
- ``operator`` is never accepted — the Outcome Fact's recorder is
``"adapter:{authenticated}"``, never a client string.

``extra="forbid"`` is the schema-level guard that turns any smuggled field
(``source`` / ``adapter`` / ``operator`` / ``outcome_status`` / ...) into a
422 at the boundary, before the reconciliation contract ever runs — the same
fact-smuggling discipline ``ExecuteRequest`` applies to execution intent.

Each gate's rejection carries a fixed HTTP status, assigned in the router and
never in the domain layer: 401 for an authentication failure, 404 for an
unsupported adapter or a correlation failure, 422 for a contract or mapping
rejection, and 500 for a persistence failure. The ack ``{"accepted": true}``
is returned only once the fact is committed, and the response never carries
the ORM object, the ``external_state``, or a credential.

This module is a pure input boundary: it performs no database query, no
correlation, no external-state mapping, no persistence. It types and preserves
the raw payload, then hands a well-formed ``ExternalObservation`` to the
contract (``validate_observation``), which owns all semantic validation (empty
``external_reference``, naive or future ``observed_at``, unknown ``adapter`` /
``source``). Schema = type + presence; contract = semantics — the two never
duplicate each other.
"""
import uuid
from collections.abc import Mapping
from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.services.outcomes.reconciliation import ExternalObservation

# The webhook ingress channel (``OUTCOME_SOURCES``). The server constructs it
# in ``to_external_observation``; a client can never supply or override it. A
# test cross-checks this literal against ``OUTCOME_SOURCES`` so the channel
# name can never silently drift.
WEBHOOK_SOURCE = "webhook"


class WebhookCallbackRequest(BaseModel):
    """Body of ``POST /api/v1/webhooks/{adapter}`` — the raw external
observation, nothing more.

Four client-supplied facts, each typed here but not semantically validated
(that is the contract's job):

- ``execution_id``: a UUID (format only — whether the chain exists is
Gate 3 correlation);
- ``external_reference``: a required string (presence only — an empty or
whitespace value is refused downstream by ``validate_observation``,
never by a second business rule here);
- ``external_state``: ``str | Mapping``, preserved raw — no ``lower()`` /
``trim()`` / ``upper()`` / coercion; mapping it onto an outcome word is
Gate 4's job, never this schema's;
- ``observed_at``: a datetime (type only — timezone-awareness, UTC
normalization and the bounded-future check all belong to
``validate_observation``; this schema copies no second timestamp rule).

``extra="forbid"`` rejects ``source`` / ``adapter`` / ``operator`` and any
unknown field as a 422.
"""

    model_config = ConfigDict(extra="forbid")

    execution_id: uuid.UUID
    external_reference: str
    external_state: str | Mapping
    observed_at: datetime


def to_external_observation(
    request: WebhookCallbackRequest, *, adapter: str
) -> ExternalObservation:
    """The explicit schema-to-contract conversion boundary.

Builds the ``ExternalObservation`` from a validated request plus the
server-side trusted identity:

- ``adapter`` is keyword-only and required — it is the authenticated
callback identity from Gate 1, never a body field, so the client can
never become the trust root;
- ``source`` is always ``WEBHOOK_SOURCE`` ("webhook") — the client can
never select ``"manual_reconcile"``;
- ``operator`` is not an ``ExternalObservation`` field at all — the
fact's recorder is derived server-side from the authenticated adapter,
never from the body.

Pure conversion: it copies the four raw fields through unchanged
(``external_state`` preserved exactly as parsed) and performs no
validation, no DB access, no mapping. Semantic validation is
``validate_observation``, which the caller wires this output into; this
function does not call it, so the schema layer stays a pure input
boundary.
"""
    return ExternalObservation(
        execution_id=request.execution_id,
        adapter=adapter,
        external_reference=request.external_reference,
        external_state=request.external_state,
        observed_at=request.observed_at,
        source=WEBHOOK_SOURCE,
    )
