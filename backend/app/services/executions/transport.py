"""Shared HTTP transport discipline for REAL external adapters (RC2-R §3.5).

WHY THIS EXISTS. ``urllib.request.urlopen`` follows 3xx redirects automatically
and — critically — FORWARDS the ``Authorization`` header to the redirect
target, INCLUDING a cross-host one. For a credential-bearing outbound call that
is both a leak (CWE-522: a compromised or misconfigured proxy could 302 the
request to an attacker host and harvest the credential) AND a target-binding
violation: the durable binding names ONE endpoint, so silently following a 3xx
would make the REAL target diverge from the bound one.

WHAT IT DOES. ``NoRedirectHandler`` overrides ``redirect_request`` to return
``None``, which makes urllib raise ``HTTPError`` for every 3xx instead of
following it. The adapters' existing HTTP-error translation then maps the 3xx
to a fail-closed ``adapter_error`` — the request is NEVER re-issued, NEVER
forwarded cross-host, and NEVER retargeted away from the bound endpoint.

RELATION TO THE THEHIVE ADAPTER. ``thehive.py`` carries its own private
``_NoRedirectHandler`` / ``_build_opener`` pair (M4-F §3) and is deliberately
left byte-identical (it is the lab-certified write adapter; RC2-R does not
touch it). This module is the shared helper for the OTHER real adapters
(Shuffle / Wazuh), so their default transport is no-redirect too.

TLS verification and base-URL validation are UNCHANGED: ``build_opener``
installs the default verifying handlers; only the redirect handler is
replaced. There is NO retry layer here — one call, one decision.
"""
from __future__ import annotations

import urllib.request


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse to follow ANY 3xx: returning ``None`` makes urllib raise
    ``HTTPError`` for the redirect response instead of re-issuing the request
    (and never forwards the ``Authorization`` header to another host)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def build_no_redirect_opener() -> urllib.request.OpenerDirector:
    """The production opener for real adapters: default handlers (verifying
    TLS) with the redirect handler REPLACED by :class:`NoRedirectHandler`.
    ``.open(request, timeout=...)`` matches the ``urlopen`` call shape the
    adapters use as their ``transport`` seam."""
    return urllib.request.build_opener(NoRedirectHandler)
