"""Pydantic schemas of the Manual Reconcile request and response.

Manual Reconcile is the pull-side counterpart of the webhook push path: a
webhook lets an external system report an outcome, while Manual Reconcile lets
an authenticated operator ask the platform to read the external system's
current state for one past execution and append what it finds as an Outcome
Fact (``source="manual_reconcile"``).

Authenticated operator -> POST /api/v1/executions/{id}/reconcile
-> Operator RBAC          (reuse ``authenticate_operator``)
-> Request schema         (this module)
-> Correlation
-> External reference
-> ReadAdapterRegistry
-> ReadAdapter.read
-> Read-failure handling
-> Validation / mapping
-> Outcome Fact append
-> Derivation

The request body is empty because a Manual Reconcile client expresses no
observation data. A webhook client supplies ``external_reference`` /
``external_state`` / ``observed_at`` because it is the external system
reporting a fact; this client only authenticates (Authorization header) and
names the execution in the path. Everything else is derived server-side:

- ``execution_id`` comes from the path, never the body;
- ``operator`` is the authenticated identity (``authenticate_operator`` ->
``Operator.name``), never a client string; the webhook's
``adapter:{identity}`` recorder rule does not apply to this human trust
domain;
- ``source`` is always ``"manual_reconcile"``, fixed by the server;
- ``adapter`` / ``external_reference`` are extracted read-only from the
historical ``execution_log`` dispatch fact, never declared by the client;
- the external state itself is read from the external system, never asserted
by the client.

``extra="forbid"`` is therefore the schema-level guard that turns any smuggled
field (``execution_id`` / ``adapter`` / ``operator`` / ``source`` /
``external_reference`` / ``external_state`` / ``observed_at`` / ``api_key`` /
``authorization`` / any credential) into a 422 at the boundary: a client can
never inject a fake observation, pick its own identity, or select the ingress
channel. The recommended body is the empty object ``{}``.

``ManualReconcileResponse`` documents the success envelope the pipeline returns
for a committed Outcome Fact. The route Like ``schemas/webhook.py``, this module is a pure input/output boundary: no
database query, no correlation, no external read, no state mapping, no
persistence. Schema = type + presence; the contract owns all semantics.
"""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

# The Manual Reconcile ingress channel (``OUTCOME_SOURCES``). The server fixes
# it; a client can never supply or override it, and a webhook can never spoof
# it (locked by test_webhook_security.py). Declared here so the response
# envelope's ``source`` has one authoritative literal.
MANUAL_RECONCILE_SOURCE = "manual_reconcile"


class ManualReconcileRequest(BaseModel):
    """Body of ``POST /api/v1/executions/{execution_id}/reconcile`` — empty.

A Manual Reconcile client expresses no observation data: the execution is
named in the path, the operator identity comes from the Authorization
header, and everything else is derived server-side. This model has no
fields and ``extra="forbid"``, so any body field — ``operator`` /
``source`` / ``adapter`` / ``external_reference`` / ``external_state`` /
``observed_at`` / ``execution_id`` / ``outcome_status`` / ``api_key`` /
``authorization`` / ``token`` / ``password`` / anything unknown — is a 422
at the boundary, before the pipeline ever runs. The recommended body is
``{}``.

The same fact-smuggling discipline ``ExecuteRequest`` applies to execution
intent and ``WebhookCallbackRequest`` applies to a callback's provenance
fields applies here in inverted form: where the webhook body carries the
four observation facts, the reconcile body carries none, because the
platform (not the client) is the one about to observe.
"""

    model_config = ConfigDict(extra="forbid")


class ManualReconcileResponse(BaseModel):
    """Success envelope of a Manual Reconcile that appended an Outcome Fact.

Fields:

- ``accepted``: a fact was appended;
- ``execution_id``: the trusted identity correlation confirmed exists
(never the raw client value);
- ``adapter``: the adapter read, extracted from ``execution_log``
(``detail["executor"]``), never client-declared;
- ``outcome_status``: this observation's mapped outcome word;
- ``observed_at``: the fact time — the external reliable timestamp when
there is one, otherwise the server observation time;
- ``source``: always ``"manual_reconcile"``;
- ``derived_outcome_status``: the derived current state over the fact
series, never stored, computed on read;
- ``observed_at_kind``: ``"external"`` or ``"server-observation"``, so a
caller can tell a read timestamp from our own.

A rejection has no fact to describe, so it never produces this envelope.
"""

    accepted: bool
    execution_id: uuid.UUID
    adapter: str
    outcome_status: str
    observed_at: datetime
    source: str
    derived_outcome_status: str
    observed_at_kind: str
