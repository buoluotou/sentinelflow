"""Adapter Callback Webhook — Gate 1 authentication and endpoint wiring.

The first of four inbound gates:

External System -> HTTP Webhook
-> Gate 1 Authentication    (THIS MODULE)
-> Gate 2 Schema
-> Gate 3 Correlation
-> Gate 4 Semantic Mapping
-> Outcome Fact Append

Gate 1 (``authenticate_callback``) answers one question:

"Is this HTTP callback from a trusted external adapter?"

Trust domain: an inbound callback authenticates with an adapter callback
credential (``<ADAPTER>_CALLBACK_TOKEN``) that is completely separate from the
human credential guarding the write paths. The two trust domains never merge
and never fall back to one another — a callback is never authenticated by a
human write-path token, and a human is never authenticated by a callback
token. This module therefore builds its own small constant-time check instead
of borrowing any existing identity machinery.

Adapter binding: the trusted adapter identity comes from the server-side route
(``/webhooks/{adapter}``) and that adapter's own configured token — never from
anything in the request body. A callback posted to ``/webhooks/wazuh`` is
authenticated against ``WAZUH_CALLBACK_TOKEN`` only; a Shuffle token can never
authenticate the Wazuh route.

Secret discipline: the callback token is compared in constant time
(``secrets.compare_digest``) and never appears in a log, a response, an
exception string, an object repr or the database. Every authentication
failure — missing / malformed / wrong / unconfigured token — collapses to one
uniform 401 with a static detail, so a response can never disclose whether a
token exists, which adapter it belongs to, or anything about its value
(length / prefix / suffix).

The endpoint below wires the full inbound pipeline. It adds the Gate-2 body
(``WebhookCallbackRequest``), folds in the server-side trusted adapter via
``to_external_observation``, delegates Gates 2-4 plus the append-only Outcome
Fact INSERT to ``app.services.outcomes.webhook``, maps each domain rejection to
its HTTP status (401 auth / 404 unsupported-adapter + correlation / 422
contract + mapping / 500 persistence), and returns the ack
``{"accepted": true}`` only once the fact is committed. HTTP mapping lives
here, never in the domain. The router itself carries no persistence surface —
the service owns the transaction — and never echoes the ORM, the
external_state, or any credential. A refused state is a 422 and appends no
fact.
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

# The adapters that own an inbound callback channel, each bound to its own
# server-side token setting. This is a security allow-list, written out
# rather than derived: registering a new adapter elsewhere does not open a
# callback channel here — each channel is opted in by name. ``mock`` is
# absent because it is an offline DryRun with no external callback identity,
# so it is never a webhook channel. Any adapter not in this map (``mock``
# included) resolves to an unsupported route.
CALLBACK_TOKEN_SETTINGS: dict[str, str] = {
    "shuffle": "SHUFFLE_CALLBACK_TOKEN",
    "wazuh": "WAZUH_CALLBACK_TOKEN",
    "thehive": "THEHIVE_CALLBACK_TOKEN",
}

# The adapters that own a callback channel (the allow-list keys). Pinned by
# the structural tests to exactly the three recognized external adapters.
CALLBACK_ADAPTERS: frozenset[str] = frozenset(CALLBACK_TOKEN_SETTINGS)

# One uniform authentication-failure detail: static, so it carries no token,
# no adapter name, no hint about whether a token exists, and no length /
# prefix / suffix — nothing an attacker can discriminate on. Every failure
# shape (missing / malformed / non-Bearer / wrong / unconfigured) returns
# exactly this string with a 401.
CALLBACK_AUTH_FAILURE_DETAIL = "callback authentication failed"

# Unsupported callback channel (``mock``, or any unknown adapter): a 404
# rather than a 401 — the route exists for recognized adapters only, and this
# discloses no credential metadata. The caller chose the adapter in the URL,
# so "no such channel" leaks nothing about any token.
CALLBACK_UNSUPPORTED_ADAPTER_DETAIL = "unsupported callback adapter"

# Correlation failure (Gate 3): the execution_id is well-formed but maps to
# no existing chain -> 404. Static detail: it echoes no execution_id, no
# external_state, no credential.
CALLBACK_CORRELATION_FAILURE_DETAIL = "execution correlation failed"

# Contract / semantic-mapping rejection: a Gate-2 contract violation or a
# Gate-4 refused state -> 422 (the Gate-2 body type check is FastAPI's own
# automatic 422). Static detail — it leaks nothing about the refused value,
# never the external_state, never a credential.
CALLBACK_VALIDATION_FAILURE_DETAIL = "callback validation failed"

# Outcome Fact persistence failure: the append failed and the service rolled
# the transaction back -> 500, never accepted=true, never a reconciliation
# state. Static detail, no DB internals, no credential.
CALLBACK_PERSISTENCE_FAILURE_DETAIL = "outcome persistence failed"


def _extract_bearer(authorization: str | None) -> str | None:
    """Extract the Bearer credential from the Authorization header.

Returns None when the header is missing, is not a ``Bearer `` scheme, or
carries an empty credential. The caller collapses every one of those to
the same uniform 401, so the shape of a malformed header can never be
distinguished from a wrong token. The extracted value is used only for a
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
    """Gate 1 — authenticate one inbound adapter callback.

``adapter`` is the server-side route binding (``/webhooks/{adapter}``),
never a body field. Resolution order:

1. the route adapter must own a callback channel (the allow-list);
anything else — ``mock`` included — is a 404 unsupported route;
2. the Bearer credential must be present and well-formed;
3. that adapter's ``<ADAPTER>_CALLBACK_TOKEN`` must be configured
(empty stays fail-closed);
4. the credential must match it in constant time.

Checks 2-4 collapse to one uniform 401, so no failure shape leaks whether
a token exists, which adapter it belongs to, or anything about its value.
On success returns the trusted adapter identity (``shuffle`` / ``wazuh`` /
``thehive``) — a plain server-side string carrying no credential.
Persistence renders it as ``adapter:{identity}``; this step writes no fact.
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
    # Constant-time compare. Encoding both sides to UTF-8 bytes first means a
    # malformed non-ASCII credential can never raise inside compare_digest
    # (which rejects non-ASCII str) — so every bad credential collapses to the
    # same uniform 401, never a 500. An unconfigured channel (empty expected
    # token) is fail-closed here too and stays indistinguishable from a wrong
    # token: the short-circuit raises the identical 401.
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
    """POST /api/v1/webhooks/{adapter} — the full inbound wiring.

Gate 1 (``authenticate_callback``, a dependency) runs first and short-
circuits a bad callback to a uniform 401 / 404 before the body is ever
considered. Then, in order:

- Gate 2 Schema: FastAPI validates ``payload`` against
``WebhookCallbackRequest`` (extra / missing / mistyped -> its own 422);
``to_external_observation`` folds in the server-side trusted adapter
and the ``webhook`` source (never a body field);
- Gates 2-4 and the append-only Outcome Fact INSERT are delegated to
``persist_callback_outcome`` (the service owns the transaction, so this
router carries no persistence surface);
- the ack ``{"accepted": true}`` is returned only after the fact is
committed — never 201 / 204, never the ORM, never the external_state,
never a credential.

HTTP mapping lives here: ``UnmappableExecutionId`` (Gate 3, a
``ContractValidationFailure`` subclass) -> 404 and is caught before its
base; any other ``ContractValidationFailure`` (Gate 2 contract / Gate 4
refused state) -> 422; ``OutcomePersistenceError`` (rolled-back DB failure)
-> 500. Every detail is static, so a rejection leaks nothing about the
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
