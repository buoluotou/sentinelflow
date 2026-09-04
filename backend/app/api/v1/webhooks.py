"""Adapter Callback Authentication — Webhook inbound Gate 1 (Phase 3.4.4-A).

The FIRST of four frozen inbound gates (design §5 of the Outcome Lifecycle
doc and §15 of the Reconciliation Contract):

    External System -> HTTP Webhook
        -> Gate 1 Authentication    (THIS MODULE, 3.4.4-A)
        -> Gate 2 Schema            (3.4.4-B)
        -> Gate 3 Correlation       (3.4.4-C)
        -> Gate 4 Semantic Mapping  (3.4.4-D)
        -> Outcome Fact Append      (3.4.4-E)

This module answers ONE question and nothing else:

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

3.4.4-A scope: AUTHENTICATION ONLY. This module deliberately implements no
request-body schema, no correlation, no external-state mapping and no
persistence (spec §3 / §14). The endpoint below is a minimal stub returning
the frozen success ack ``{"accepted": true}`` once — and only once — Gate 1
passes. Gates 2-4 and the Outcome Fact append arrive in 3.4.4-B..E, and the
Shuffle/TheHive fail-closed mapping behaviour is inherited unchanged.
"""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Header, HTTPException

from app.core.config import settings

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
    authenticated_adapter: str = Depends(authenticate_callback),
) -> dict[str, bool]:
    """POST /api/v1/webhooks/{adapter} — the 3.4.4-A minimal stub.

    Gate 1 ONLY: authenticate the callback, then return the frozen success
    ack ``{"accepted": true}`` (spec §14, frozen decision #2). Deliberately
    NO request-body schema, NO correlation, NO external-state mapping and NO
    persistence (spec §3) — those are 3.4.4-B..E. Any Gate 1 failure raises
    inside ``authenticate_callback`` BEFORE this body runs, so an
    unauthenticated callback never reaches the ack.

    ``authenticated_adapter`` is the server-side trusted identity resolved by
    Gate 1 (consumed from 3.4.4-E onward). It is intentionally NOT echoed in
    the response: the ack stays minimal and credential-free.
    """
    return {"accepted": True}
