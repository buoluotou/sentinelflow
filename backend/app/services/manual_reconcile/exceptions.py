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
