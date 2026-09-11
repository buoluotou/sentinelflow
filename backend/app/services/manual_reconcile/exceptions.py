"""Read-adapter exception family.

Structurally parallel to the write side's ``app.services.executions.exceptions``
(``ExecutorError`` / ``ExecutorConfigError``): a lightweight, dependency-free
domain-exception module for the read / reconcile side. One concern, one family.

It is not part of the ``ContractValidationFailure`` family. Importing that base
would drag SQLAlchemy (``app.models.execution_outcome``) and the whole
write-adapter stack (``app.services.executions.registry`` -> the
Shuffle/Wazuh/TheHive modules -> ``urllib.request``) into this pure read layer,
breaking the no-DB / no-HTTP import surface. A ``ContractValidationFailure`` means
"the input is malformed"; ``UnsupportedAdapterRead`` means "the platform has no
reader for this adapter" — a registry-capability rejection, the read-side mirror
of the write side's ``ExecutorConfigError``. Different concern, different family —
consistent with how the repo already separates ``ExecutorError`` from
``ContractValidationFailure``.

This module has no imports on purpose: it must stay importable without pulling
any DB / HTTP / executor coupling into the read layer.
"""


class ReadAdapterError(Exception):
    """Base class of all read-adapter-layer errors.

The read-side counterpart of ``ExecutorError``. Every rejection raised while
resolving or invoking a read adapter derives from this, so the Manual Reconcile
pipeline can catch one base and translate it to a ``rejected`` (no Outcome
Fact) response.
"""


class UnsupportedAdapterRead(ReadAdapterError):
    """The ReadAdapterRegistry has no concrete reader for this adapter identity.

Raised for: an unknown adapter name, ``mock`` (no external system, never
reconcilable), or an adapter whose read path has no runtime evidence yet
(``shuffle`` / ``wazuh`` / ``thehive``). It is the read-side mirror of the
write side's ``ExecutorConfigError``: the registry does not fake a reader.

Semantics: this is a rejection — no Outcome Fact is produced, no external
system is contacted, no external state is fabricated. It is never
``reconciliation_failed`` (that requires a reconcile action that attempted a
read and failed at transport level — impossible when no reader exists) and
never ``confirmed_failure``.

Carries the offending ``adapter`` name so callers can render a stable message
(an adapter name is not a secret — the same transparency the executor
registry applies). It never echoes an ``external_reference`` (an
external-system handle — the non-echo discipline of the contract family).
"""

    def __init__(self, message: str, adapter: object | None = None):
        super().__init__(message)
        self.adapter = adapter


class ReadTransportError(ReadAdapterError):
    """A reader existed and was invoked, but the external read failed in transit.

The sibling of ``UnsupportedAdapterRead`` under ``ReadAdapterError`` — and the
two are strictly disjoint:

- ``UnsupportedAdapterRead`` = no reader exists for the adapter (a
capability failure) -> a rejection: HTTP 404, zero Outcome Facts, never
``reconciliation_failed``.
- ``ReadTransportError`` = a reader existed, ``read()`` was actually called,
and that call failed at the transport layer (timeout / connection refused
/ DNS / HTTP 5xx / adapter unavailable) -> the Manual Reconcile service
maps it to ``reconciliation_failed`` and appends one Outcome Fact.

A concrete reader may raise this domain type explicitly, or it may raise a
builtin transport error (``TimeoutError`` / ``ConnectionError`` / ``OSError``)
— the ``ReadAdapter.read`` contract documents both, and the service catches
the union so either shape closes to the same ``reconciliation_failed``
verdict. Because it derives from ``ReadAdapterError`` (not from a builtin) and
is a sibling — never a parent — of ``UnsupportedAdapterRead``, catching it can
never swallow a capability rejection: capability is not transport.

Carries an optional ``category`` — a static classification (``timeout`` /
``connection_failure`` / ``transport_error`` / ``adapter_unavailable``) the
service renders into the Outcome Fact detail. It never carries a callback
token, operator token, adapter API key, Authorization header, password, or raw
external payload: the service records only this static category, never
``str(exc)``.

Zero imports, like the rest of this family: the read layer stays importable
without any DB / HTTP / executor coupling.
"""

    def __init__(self, message: str, category: str | None = None):
        super().__init__(message)
        self.category = category
