"""Pydantic schemas of the Manual Reconcile request / response (Phase 3.4.5-A2-A).

Position in the frozen PULL-side reconcile pipeline (design §4 of the Manual
Reconcile doc). Manual Reconcile is the pull-side counterpart of the webhook
push-side path: a webhook lets an EXTERNAL SYSTEM report an outcome; a Manual
Reconcile lets an AUTHENTICATED HUMAN OPERATOR ask the platform to GO READ the
external system's current state for one past execution and append what it finds
as an Outcome Fact (``source="manual_reconcile"``).

    Authenticated Operator -> POST /api/v1/executions/{id}/reconcile
        -> Operator RBAC          (3.4.5-A2-A, THIS STEP — reuse authenticate_operator)
        -> Request Schema         (3.4.5-A2-A, THIS MODULE)
        -> Correlation            (3.4.5-A2-B)
        -> External Reference     (3.4.5-A2-B)
        -> ReadAdapterRegistry    (3.4.5-A2-C)
        -> ReadAdapter.read       (3.4.5-A2-C)
        -> Read Failure handling  (3.4.5-A2-D)
        -> 3.4.3 Validation/Map   (3.4.5-A2-E)
        -> Outcome Fact Append    (3.4.5-A2-E)
        -> Derivation             (3.4.5-A2-E)

THE REQUEST IS EMPTY BY DESIGN (spec §6 / §7 / §8). This is the single sharpest
difference from the webhook body. A webhook client legitimately supplies
OBSERVATION DATA (``external_reference`` / ``external_state`` / ``observed_at``)
because it IS the external system reporting a fact. A Manual Reconcile client
supplies NOTHING of the sort — it only authenticates (Authorization header) and
names the execution (``execution_id`` in the PATH). Every other value the future
fact needs is derived SERVER-SIDE:

  - ``execution_id`` comes from the PATH, never the body;
  - ``operator`` is the AUTHENTICATED identity (``authenticate_operator`` ->
    ``Operator.name``), never a client string (spec §7) — the webhook's
    ``adapter:{identity}`` recorder rule is NOT copied here;
  - ``source`` is ALWAYS ``"manual_reconcile"``, fixed by the server (spec §8);
  - ``adapter`` / ``external_reference`` are extracted read-only from the
    historical ``execution_log`` dispatch fact (spec §10, A2-B), never declared
    by the client;
  - the external state itself is READ from the external system (A2-C), never
    asserted by the client.

``extra="forbid"`` is therefore the schema-level guard that turns ANY smuggled
field (``execution_id`` / ``adapter`` / ``operator`` / ``source`` /
``external_reference`` / ``external_state`` / ``observed_at`` / ``api_key`` /
``authorization`` / any credential) into a 422 at the boundary — a client can
never inject a fake observation, pick its own identity, or select the ingress
channel. The recommended body is the empty object ``{}``.

THE RESPONSE (design §4.4 — semantics FROZEN, field names finalized when the
success path lands in 3.4.5-A2-E). ``ManualReconcileResponse`` documents the
success envelope the pipeline will return once an Outcome Fact is committed. In
3.4.5-A2-A the route NEVER returns it: an authorized operator gets an honest
HTTP 501 (Not Implemented) placeholder, never a 200 ``accepted`` and never a
fabricated reconciliation success (spec §36). The schema is defined now so the
API boundary is explicit and so the smuggle-guard on the request can be tested
against a stable contract.

This module is a PURE input/output boundary (mirrors ``schemas/webhook.py``):
NO database query, NO correlation, NO external read, NO state mapping, NO
persistence. Schema = type + presence; the 3.4.3 contract owns ALL semantics.
"""
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict

#: The frozen Manual Reconcile ingress channel (``OUTCOME_SOURCES``, design §6).
#: The server fixes it; a client can never supply or override it (spec §8), and
#: a webhook can never spoof it (locked by test_webhook_security.py). Declared
#: here so the response envelope's ``source`` has one authoritative literal.
MANUAL_RECONCILE_SOURCE = "manual_reconcile"


class ManualReconcileRequest(BaseModel):
    """Body of ``POST /api/v1/executions/{execution_id}/reconcile`` — EMPTY.

    A Manual Reconcile client expresses NO observation data (spec §6). The
    execution is named in the PATH; the operator identity comes from the
    Authorization header; everything else is derived server-side. This model
    has ZERO fields and ``extra="forbid"``, so ANY body field — ``operator`` /
    ``source`` / ``adapter`` / ``external_reference`` / ``external_state`` /
    ``observed_at`` / ``execution_id`` / ``outcome_status`` / ``api_key`` /
    ``authorization`` / ``token`` / ``password`` / anything unknown — is a 422
    at the boundary, before the pipeline ever runs. The recommended body is
    ``{}``.

    This is the SAME fact-smuggling discipline ``ExecuteRequest`` applies to
    execution intent and ``WebhookCallbackRequest`` applies to a callback's
    provenance fields — inverted: where the webhook body carries the four
    observation facts, the reconcile body carries none, because the platform
    (not the client) is the one about to observe.
    """

    model_config = ConfigDict(extra="forbid")


class ManualReconcileResponse(BaseModel):
    """Success envelope of a Manual Reconcile that appended an Outcome Fact
    (design §4.4 — semantics frozen; populated from 3.4.5-A2-E onward).

    Fields express the §4.4 success contract:

      - ``accepted``: a fact was appended (the §4.4 "是否 append" bit);
      - ``execution_id``: the TRUSTED identity correlation confirmed exists
        (never the raw client value);
      - ``adapter``: the adapter read, extracted from ``execution_log``
        (``detail["executor"]``), never client-declared;
      - ``outcome_status``: THIS observation's mapped outcome word (3.4.3-B);
      - ``observed_at``: the fact time (external reliable timestamp, else the
        server observation time — spec §19);
      - ``source``: ALWAYS ``"manual_reconcile"`` (spec §8);
      - ``derived_outcome_status``: the 3.4.2 derived current state over the
        fact series (never stored, computed on read — spec §20);
      - ``observed_at_kind``: ``"external"`` or ``"server-observation"``
        (spec §9 / §19), so a caller can tell a read timestamp from our own.

    3.4.5-A2-A NOTE: the route NEVER returns this yet — A2-A establishes the
    secured seam only and answers 501 (Not Implemented) for an authorized
    operator. This schema exists now to make the frozen boundary explicit; the
    exact field SET is finalized when the success path lands (A2-E), per §4.4's
    "字段名实现期定".
    """

    accepted: bool
    execution_id: uuid.UUID
    adapter: str
    outcome_status: str
    observed_at: datetime
    source: str
    derived_outcome_status: str
    observed_at_kind: str
