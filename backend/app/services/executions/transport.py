"""Shared HTTP transport discipline for real external adapters.

``urllib.request.urlopen`` follows 3xx redirects automatically and forwards
the ``Authorization`` header to the redirect target, including a cross-host
one. For a credential-bearing outbound call that is both a leak (CWE-522: a
compromised or misconfigured proxy could 302 the request to an attacker host
and harvest the credential) and a target-binding violation: the durable
binding names one endpoint, so following a 3xx would make the real target
diverge from the bound one.

``NoRedirectHandler`` overrides ``redirect_request`` to return ``None``, which
makes urllib raise ``HTTPError`` for every 3xx instead of following it. The
adapters' HTTP-error translation then maps the 3xx to a fail-closed
``adapter_error``: the request is never re-issued, never forwarded cross-host,
and never retargeted away from the bound endpoint.

``thehive.py`` carries its own private ``_NoRedirectHandler`` /
``_build_opener`` pair and is left byte-identical; this module is the shared
helper for the other real adapters (Shuffle / Wazuh), so their default
transport is no-redirect too.

TLS verification and base-URL validation are unchanged: ``build_opener``
installs the default verifying handlers; only the redirect handler is
replaced. There is no retry layer here — one call, one decision.
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
