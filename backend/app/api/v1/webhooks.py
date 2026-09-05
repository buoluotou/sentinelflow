"""Adapter Callback Webhook — Gate 1 authentication (3.4.4-A) + endpoint wiring (3.4.4-E).

The FIRST of four frozen inbound gates (design §5 of the Outcome Lifecycle
doc and §15 of the Reconciliation Contract):

    External System -> HTTP Webhook
        -> Gate 1 Authentication    (THIS MODULE, 3.4.4-A)
        -> Gate 2 Schema            (3.4.4-B)
        -> Gate 3 Correlation       (3.4.4-C)
        -> Gate 4 Semantic Mapping  (3.4.4-D)
        -> Outcome Fact Append      (3.4.4-E)

Gate 1 (``authenticate_callback``) answers ONE question and nothing else:

    "Is this HTTP callback from a trusted external adapter?"

Trust domain (design §8 / D3.4-07): an inbound callback authenticates with
an ADAPTER CALLBACK credential (``<ADAPTER>_CALLBACK_TOKEN``) that is
COMPLETELY SEPARATE from the human credential guarding the write paths. The
two trust domains never merge and never fall back to one another — a
callback is never authenticated by a human write-path token, and a human is
never authenticated by a callback token. This module therefore builds its
own tiny constant-time check instead of borrowing any existing identity
machinery.

Adapter binding (spec §6 / §8): the trusted adapter identity comes from the
SERVER-SIDE ROUTE (``/webhooks/{adapter}``) and that adapter's OWN configured
token — NEVER from anything in the request body. A callback posted to
``/webhooks/wazuh`` is authenticated against ``WAZUH_CALLBACK_TOKEN`` only; a
Shuffle token can never authenticate the Wazuh route.

Secret discipline (spec §12, frozen): the callback token is compared in
CONSTANT TIME (``secrets.compare_digest``) and NEVER appears in a log, a
response, an exception string, an object repr or the database. EVERY
authentication failure — missing / malformed / wrong / unconfigured token —
collapses to ONE uniform 401 with a static detail, so a response can never
disclose whether a token exists, which adapter it belongs to, or anything
about its value (length / prefix / suffix).

3.4.4-E scope: Gate 1 (``authenticate_callback``) is UNCHANGED and byte-frozen;
the endpoint below now WIRES the full inbound pipeline. It adds the Gate-2 body
(``WebhookCallbackRequest``), folds in the server-side trusted adapter via
``to_external_observation``, delegates Gates 2-4 plus the append-only Outcome
Fact INSERT to ``app.services.outcomes.webhook``, maps each domain rejection to
its frozen HTTP status (401 auth / 404 unsupported-adapter + correlation / 422
contract + mapping / 500 persistence), and returns the frozen ack
``{"accepted": true}`` only once the fact is committed (spec §11 / §12 / §32).
HTTP mapping lives HERE, never in the domain (spec §12). The router itself
carries NO persistence surface — the service owns the transaction — and never
echoes the ORM, the external_state, or any credential (spec §16 / §25). The
Shuffle/TheHive fail-closed mapping behaviour is inherited unchanged: a refused
state is a 422, never a fabricated fact.
"""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.schemas.webhook import WebhookCallbackRequest, to_external_observation
from app.services.outcomes.correlation import UnmappableExecutionId
from app.services.outcomes.reconciliation import ContractValidationFailure
from app.services.outcomes.webhook import (
    OutcomePersistenceError,
    persist_callback_outcome,
)

router = APIRouter(prefix="/webhooks", tags=["webhooks"])

#: The adapters that OWN an inbound callback channel, each bound to its own
#: server-side token setting. This is a SECURITY allow-list, frozen
#: EXPLICITLY (never derived dynamically): registering a new adapter
#: elsewhere does NOT silently open a callback channel here — each channel
#: is opted in by name. ``mock`` is deliberately ABSENT: it is an offline
#: DryRun with no external callback identity, so it is never a webhook
#: channel (spec §5 / §17). Any adapter not in this map (``mock`` included)
#: resolves to an unsupported route.
CALLBACK_TOKEN_SETTINGS: dict[str, str] = {
    "shuffle": "SHUFFLE_CALLBACK_TOKEN",
    "wazuh": "WAZUH_CALLBACK_TOKEN",
    "thehive": "THEHIVE_CALLBACK_TOKEN",
}

#: The adapters that own a callback channel (the allow-list keys). Pinned by
#: the structural tests to exactly the three recognized external adapters.
CALLBACK_ADAPTERS: frozenset[str] = frozenset(CALLBACK_TOKEN_SETTINGS)

#: ONE uniform authentication-failure detail (spec §9). Static by design: it
#: carries NO token, NO adapter name, NO "does a token exist" hint, and NO
#: length / prefix / suffix — nothing an attacker can discriminate on. Every
#: failure shape (missing / malformed / non-Bearer / wrong / unconfigured)
#: returns exactly this string with a 401.
CALLBACK_AUTH_FAILURE_DETAIL = "callback authentication failed"

#: Unsupported callback channel (e.g. ``mock``, or any unknown adapter): a
#: 404, NOT a 401 — the route exists for recognized adapters only, and this
#: discloses NO credential metadata (the caller chose the adapter in the URL,
#: so "no such channel" leaks nothing about any token).
CALLBACK_UNSUPPORTED_ADAPTER_DETAIL = "unsupported callback adapter"

#: Correlation failure (Gate 3, spec §12 / §31): the execution_id is
#: well-formed but maps to NO existing chain -> 404. STATIC detail: it echoes
#: no execution_id, no external_state, no credential.
CALLBACK_CORRELATION_FAILURE_DETAIL = "execution correlation failed"

#: Contract / semantic-mapping rejection (spec §12 / §31): a Gate-2 contract
#: violation or a Gate-4 refused state -> 422 (the Gate-2 body TYPE check is
#: FastAPI's own automatic 422). STATIC detail — leaks nothing about the
#: refused value, never the external_state, never a credential.
CALLBACK_VALIDATION_FAILURE_DETAIL = "callback validation failed"

#: Outcome Fact persistence failure (spec §10 / §12 / §31): the append failed
#: and the service rolled the transaction back -> 500. NEVER accepted=true,
#: NEVER a reconciliation state. STATIC detail, no DB internals, no credential.
CALLBACK_PERSISTENCE_FAILURE_DETAIL = "outcome persistence failed"


def _extract_bearer(authorization: str | None) -> str | None:
    """Extract the Bearer credential from the Authorization header.

    Returns None when the header is missing, is not a ``Bearer `` scheme, or
    carries an empty credential. The caller collapses every one of those to
    the SAME uniform 401, so the shape of a malformed header can never be
    distinguished from a wrong token. The extracted value is used ONLY for a
    constant-time comparison — it is never stored, returned, logged or echoed.
    """
    if not authorization or not authorization.startswith("Bearer "):
        return None
    candidate = authorization[len("Bearer "):]
    return candidate if candidate else None


def authenticate_callback(
    adapter: str,
    authorization: str | None = Header(default=None),
) -> str:
    """Gate 1 — authenticate ONE inbound adapter callback (spec §6-§10).

    ``adapter`` is the SERVER-SIDE route binding (``/webhooks/{adapter}``),
    never a body field. Resolution order:

      1. the route adapter must OWN a callback channel (the allow-list);
         anything else — ``mock`` included — is a 404 unsupported route;
      2. the Bearer credential must be present and well-formed;
      3. that adapter's ``<ADAPTER>_CALLBACK_TOKEN`` must be configured
         (empty stays fail-closed);
      4. the credential must match it in CONSTANT TIME.

    Steps 2-4 collapse to ONE uniform 401 (``CALLBACK_AUTH_FAILURE_DETAIL``),
    so no failure shape leaks whether a token exists, which adapter it belongs
    to, or anything about its value. On success returns the TRUSTED adapter
    identity (``shuffle`` / ``wazuh`` / ``thehive``) — a plain server-side
    string carrying NO credential. Persistence (3.4.4-E) renders it as
    ``adapter:{identity}``; this step writes NO fact.
    """
    setting_name = CALLBACK_TOKEN_SETTINGS.get(adapter)
    if setting_name is None:
        # Unsupported callback channel (mock / unknown). 404 — no credential
        # metadata is disclosed; the caller chose this adapter in the URL.
        raise HTTPException(
            status_code=404, detail=CALLBACK_UNSUPPORTED_ADAPTER_DETAIL
        )
    token = _extract_bearer(authorization)
    if token is None:
        # Missing / malformed / non-Bearer header: uniform 401.
        raise HTTPException(
            status_code=401, detail=CALLBACK_AUTH_FAILURE_DETAIL
        )
    expected = getattr(settings, setting_name, "")
    # Constant-time compare. Encoding BOTH sides to UTF-8 bytes first means a
    # malformed non-ASCII credential can never raise inside compare_digest
    # (which rejects non-ASCII str) — so every bad credential collapses to the
    # SAME uniform 401, never a 500. An unconfigured channel (expected == "")
    # is fail-closed here too and stays indistinguishable from a wrong token:
    # the short-circuit raises the identical 401 (spec §4 / §9).
    if not expected or not secrets.compare_digest(
        token.encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(
            status_code=401, detail=CALLBACK_AUTH_FAILURE_DETAIL
        )
    return adapter


@router.post("/{adapter}", status_code=200)
def receive_adapter_callback(
    payload: WebhookCallbackRequest,
    authenticated_adapter: str = Depends(authenticate_callback),
    db: Session = Depends(get_db),
) -> dict[str, bool]:
    """POST /api/v1/webhooks/{adapter} — the full 3.4.4-E inbound wiring.

    Gate 1 (``authenticate_callback``, a dependency) runs FIRST and short-
    circuits a bad callback to a uniform 401 / 404 before the body is ever
    considered. Then, in the frozen order (spec §13):

      - Gate 2 Schema: FastAPI validates ``payload`` against
        ``WebhookCallbackRequest`` (extra / missing / mistyped -> its own 422);
        ``to_external_observation`` folds in the SERVER-SIDE trusted adapter +
        the frozen ``webhook`` source (never a body field, spec §5 / §6);
      - Gates 2-4 + the append-only Outcome Fact INSERT are delegated to
        ``persist_callback_outcome`` (the service owns the transaction, so this
        router carries no persistence surface);
      - the frozen ack ``{"accepted": true}`` is returned ONLY after the fact
        is committed (spec §11 / §32) — never 201 / 204, never the ORM, never
        the external_state, never a credential (spec §16 / §25).

    HTTP mapping lives HERE (spec §12): ``UnmappableExecutionId`` (Gate 3, a
    ``ContractValidationFailure`` subclass) -> 404 and is caught BEFORE its
    base; any other ``ContractValidationFailure`` (Gate 2 contract / Gate 4
    refused state) -> 422; ``OutcomePersistenceError`` (rolled-back DB failure)
    -> 500. Every detail is STATIC, so a rejection leaks nothing about the
    refused value.
    """
    observation = to_external_observation(payload, adapter=authenticated_adapter)
    try:
        persist_callback_outcome(db, observation)
    except UnmappableExecutionId as exc:
        raise HTTPException(
            status_code=404, detail=CALLBACK_CORRELATION_FAILURE_DETAIL
        ) from exc
    except ContractValidationFailure as exc:
        raise HTTPException(
            status_code=422, detail=CALLBACK_VALIDATION_FAILURE_DETAIL
        ) from exc
    except OutcomePersistenceError as exc:
        raise HTTPException(
            status_code=500, detail=CALLBACK_PERSISTENCE_FAILURE_DETAIL
        ) from exc
    return {"accepted": True}
