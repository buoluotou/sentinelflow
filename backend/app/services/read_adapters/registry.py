"""Settings-driven READ-adapter registry factory (Phase 3.4.5-M2 §5).

This is the PRODUCTION-WIRING mechanism for concrete read adapters — the
READ-side mirror of ``app.services.executions.registry.create_executor``. It
builds a ``ReadAdapterRegistry`` from ``Settings``, registering a concrete reader
ONLY for an adapter whose credentials are actually configured, and failing CLOSED
(an EMPTY registry -> every reconcile rejects 404 ``UnsupportedAdapterRead``) when
they are not.

RELATIONSHIP TO THE SEALED ``default_read_adapter_registry()`` (read this — it is
the crux of the M2 §5 placement). ``app.services.manual_reconcile.read.registry
.default_read_adapter_registry()`` is the 3.4.5-A1 SEALED production default: it
is EMPTY, and ``test_adapter_read_contract.py::TestEvidenceGap`` locks it empty
(``registered_adapters() == ()`` and EVERY adapter — including ``thehive`` —
``is_supported(...) is False``). Its own contract states a concrete reader
registers there "ONLY when 3.4.5-B/C/D lands WITH REAL EXTERNAL EVIDENCE". This
factory is a SEPARATE, ADDITIVE function: it NEVER mutates the sealed default and
NEVER registers into it. It returns a FRESH registry a caller may pass explicitly
to ``reconcile_execution(..., registry=...)`` (the sanctioned constructor-
injection seam, spec §22).

M2 §5 WIRING STATUS — HONEST (LAB BLOCKED). The TheHive read contract is
SOURCE-certified (TheHive 4.1.24-1 = ``b6649bb`` / ScalliGraph ``2c2a7a4``), but
there is NO real TheHive runtime on this host (no container runtime /虚拟化 /
sufficient memory — see the M2 Lab feasibility finding), so the design's
production-registration precondition ("real external evidence") is UNMET. The
router (``app.api.v1.reconcile``) is therefore DELIBERATELY left calling
``reconcile_execution(db, execution_id, operator)`` with NO registry, so it still
resolves the SEALED EMPTY ``default_read_adapter_registry()`` and production
behavior is UNCHANGED (every adapter rejects 404). This factory + the
``TheHiveReadAdapter`` are delivered and ISOLATION-TESTED (unit + service-level
explicit injection) so the reader is production-READY; a FUTURE phase WITH a real
Lab wires the router by changing that one call to
``reconcile_execution(db, execution_id, operator,
registry=create_read_adapter_registry(settings))`` and re-certifying against the
live runtime. Wiring it NOW — without runtime evidence — would (a) break the
sealed ``TestEvidenceGap`` empty-registry invariant the design gates on real
evidence, and (b) break the 60-site ``_inject_registry`` cross-layer seam that
relies on the router passing no registry. Neither is authorized by M2.

ADAPTER-AGNOSTIC (unlike the WRITE side). The write registry keys off
``EXECUTION_ADAPTER`` (Single-Active-Adapter). The READ side must NOT: a Manual
Reconcile targets a PAST execution whose adapter was recorded in history
(``detail["executor"]``), which may differ from the CURRENT ``EXECUTION_ADAPTER``.
So a reader is registered purely on ITS OWN credentials being present, never on
the active write selection.

TOLERANT, NOT STRICT. A missing or malformed adapter configuration is SKIPPED
(caught ``ExecutorConfigError`` -> no reader for that adapter), NEVER raised: an
unconfigured adapter simply has no reader, so its reconcile fails closed at
``registry.get`` (404), and one adapter's misconfiguration can never 500 every
reconcile or block another adapter's reader.

NO HTTP, NO DB, NO read is ISSUED here: this module only assembles credential-
bearing reader OBJECTS; the actual ``GET`` happens inside ``read()`` at reconcile
time. Credentials ride the 3.2.2 Secret Boundary (``credentials_from_settings``),
never this factory's own logic.
"""
from __future__ import annotations

from app.core.config import Settings, settings
from app.services.executions.exceptions import ExecutorConfigError
from app.services.executions.secrets import credentials_from_settings
from app.services.manual_reconcile.read.base import ReadAdapter
from app.services.manual_reconcile.read.registry import ReadAdapterRegistry
from app.services.read_adapters.thehive import TheHiveReadAdapter


def _thehive_readers(
    source: Settings, *, transport: object | None = None
) -> list[ReadAdapter]:
    """The TheHive reader iff THEHIVE_BASE_URL + THEHIVE_API_KEY are configured.

    Empty config -> ``[]`` (no reader -> reconcile rejects 404, fail-closed).
    Malformed config (a bad URL shape) -> ``[]`` too (caught
    ``ExecutorConfigError``): NEVER raise, so one adapter's misconfiguration can
    never 500 the reconcile route. ``transport`` is the test/deployment seam
    forwarded to the reader (production ``None`` -> the default urllib opener).
    """
    base_url = str(getattr(source, "THEHIVE_BASE_URL", "") or "").strip()
    api_key = str(getattr(source, "THEHIVE_API_KEY", "") or "").strip()
    if not base_url or not api_key:
        return []
    try:
        credentials = credentials_from_settings("thehive", source)
    except ExecutorConfigError:
        return []
    timeout = getattr(source, "THEHIVE_TIMEOUT_SECONDS", 30.0)
    return [
        TheHiveReadAdapter(
            credentials, timeout=timeout, transport=transport  # type: ignore[arg-type]
        )
    ]


def create_read_adapter_registry(
    settings_obj: Settings | None = None, *, transport: object | None = None
) -> ReadAdapterRegistry:
    """Build the settings-driven read-adapter registry (M2 §5).

    Returns a FRESH ``ReadAdapterRegistry`` holding a concrete reader for every
    adapter whose credentials are configured (today: TheHive only — Shuffle /
    Wazuh readers are future 3.4.5-B/C work). NEVER mutates the sealed
    ``default_read_adapter_registry()``. ``settings_obj`` defaults to the process
    ``settings`` resolved AT CALL TIME (so a test may pass an explicit Settings).

    This factory is NOT wired into the reconcile router in M2 (LAB BLOCKED — see
    the module docstring); it is the delivered, tested, production-READY wiring
    mechanism for the phase that has real runtime evidence.
    """
    source = settings_obj if settings_obj is not None else settings
    readers: list[ReadAdapter] = []
    readers.extend(_thehive_readers(source, transport=transport))
    return ReadAdapterRegistry(readers)
