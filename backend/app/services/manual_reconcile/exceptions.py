"""Read-adapter exception family (Phase 3.4.5-A1, design §8/§10/§16).

Structurally parallel to the WRITE side's ``app.services.executions.exceptions``
(``ExecutorError`` / ``ExecutorConfigError``): a lightweight, dependency-free
domain-exception module for the READ / Reconcile side. One concern, one family.

It is deliberately NOT part of the 3.4.3 ``ContractValidationFailure`` family.
Importing that base would drag SQLAlchemy (``app.models.execution_outcome``) and
the whole write-adapter stack (``app.services.executions.registry`` -> the
 Shuffle/Wazuh/TheHive modules -> ``urllib.request``) into this PURE read layer,
violating the A1 no-DB / no-HTTP import surface (design §12/§13/§16). A
ContractValidationFailure means "the INPUT is malformed"; ``UnsupportedAdapterRead``
means "the platform has NO reader for this adapter" — a registry-capability
rejection, the exact read-side mirror of the write side's ``ExecutorConfigError``
("the registry refuses to fake support"). Different concern, different family —
consistent with how the repo already separates ``ExecutorError`` from
``ContractValidationFailure``.

This module has ZERO imports on purpose: it must stay importable without pulling
any DB / HTTP / executor coupling into the read layer.
"""


class ReadAdapterError(Exception):
    """Base class of all read-adapter-layer errors (never silent failures).

    The read-side counterpart of ``ExecutorError``. Every rejection raised while
    resolving or invoking a read adapter derives from this, so the 3.4.5-A2
    Manual Reconcile pipeline can catch one base and translate it to a
    ``rejected`` (no Outcome Fact) response.
    """


class UnsupportedAdapterRead(ReadAdapterError):
    """The ReadAdapterRegistry has NO concrete reader for this adapter identity.

    Raised for: an unknown adapter name, ``mock`` (no external system, never
    reconcilable — design §14), or a REAL adapter whose read path is still an
    Evidence Gap (``shuffle`` / ``wazuh`` / ``thehive`` in 3.4.5-A1 — design
    §16). It is the read-side mirror of the write side's ``ExecutorConfigError``:
    the registry REFUSES to fake a reader (design §8/§15/§17).

    Semantics (frozen): this is a REJECTION — NO Outcome Fact is produced, NO
    external system is contacted, NO external state is fabricated. It is NEVER
    ``reconciliation_failed`` (that requires a qualified reconcile action that
    actually attempted a read and failed at transport level — impossible when no
    reader exists) and NEVER ``confirmed_failure`` (design §10/§11).

    Carries the offending ``adapter`` NAME so callers can render a stable message
    (an adapter name is not a secret — the same transparency the executor
    registry applies). It NEVER echoes an ``external_reference`` (an
    external-system handle — the non-echo discipline of the 3.4.3 family).
    """

    def __init__(self, message: str, adapter: object | None = None):
        super().__init__(message)
        self.adapter = adapter


class ReadTransportError(ReadAdapterError):
    """A reader EXISTED and was INVOKED, but the external read failed in transit.

    The SIBLING of ``UnsupportedAdapterRead`` under ``ReadAdapterError`` — and the
    two are STRICTLY disjoint (design §6, the crux of 3.4.5-A2-D):

      - ``UnsupportedAdapterRead`` = NO reader exists for the adapter (a
        CAPABILITY failure) -> a REJECTION: HTTP 404, ZERO Outcome Facts, NEVER
        ``reconciliation_failed``.
      - ``ReadTransportError`` = a reader existed, ``read()`` was actually called,
        and that call failed at the TRANSPORT layer (timeout / connection refused
        / DNS / HTTP 5xx / adapter unavailable — design §7) -> the Manual
        Reconcile service maps it to ``reconciliation_failed`` and appends ONE
        Outcome Fact (design §8).

    A concrete reader MAY raise this domain type explicitly, or it MAY raise a
    builtin transport error (``TimeoutError`` / ``ConnectionError`` / ``OSError``)
    — the A1 ``ReadAdapter.read`` contract documents both, and the A2-D service
    catches the UNION so either shape closes to the SAME ``reconciliation_failed``
    verdict. Because it derives from ``ReadAdapterError`` (NOT from a builtin) and
    is a SIBLING — never a parent — of ``UnsupportedAdapterRead``, catching it can
    NEVER swallow a capability rejection (design §6: capability != transport).

    Carries an OPTIONAL ``category`` — a SAFE static classification (``timeout`` /
    ``connection_failure`` / ``transport_error`` / ``adapter_unavailable``, design
    §10) the service renders into the Outcome Fact detail. It NEVER carries a
    callback token, operator token, adapter API key, Authorization header,
    password, or raw external payload: the service records ONLY this static
    category, never ``str(exc)`` (design §25).

    Zero imports, like the rest of this family (design §19 — the read layer stays
    importable without any DB / HTTP / executor coupling).
    """

    def __init__(self, message: str, category: str | None = None):
        super().__init__(message)
        self.category = category
