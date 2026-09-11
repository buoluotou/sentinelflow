"""Settings-driven read-adapter registry factory.

This is the production wiring mechanism for concrete read adapters — the read-side
mirror of ``app.services.executions.registry.create_executor``. It builds a
``ReadAdapterRegistry`` from ``Settings``, registering a concrete reader only for
an adapter that is fully authorized, and fails closed (an empty registry, so every
reconcile rejects 404 ``UnsupportedAdapterRead``) when it is not. TheHive
authorization requires three fail-closed gates — a well-formed base URL, an
independent read-only key (never the create-capable write key) and an exact
certified-version match — so mere URL + key presence never auto-authorizes a
reader (see ``_thehive_readers``).

Relationship to the sealed ``default_read_adapter_registry()``.
``app.services.manual_reconcile.read.registry.default_read_adapter_registry()`` is
the sealed production default: it is empty, and
``test_adapter_read_contract.py::TestEvidenceGap`` locks it empty
(``registered_adapters() == ()`` and every adapter — including ``thehive`` —
``is_supported(...) is False``). Its own contract states that a concrete reader is
registered there only with real external evidence. This factory is a separate,
additive function: it never mutates the sealed default and never registers into
it. It returns a fresh registry a caller may pass explicitly to
``reconcile_execution(..., registry=...)`` (the sanctioned constructor-injection
seam).

Wiring status. The TheHive read contract is source-certified (TheHive 4.1.24-1 =
``b6649bb`` / ScalliGraph ``2c2a7a4``), but there is no real TheHive runtime on
this host (no container runtime, virtualisation or sufficient memory), so the
precondition for production registration — real external evidence — is unmet. The
router (``app.api.v1.reconcile``) therefore calls
``reconcile_execution(db, execution_id, operator)`` with no registry, so it still
resolves the sealed empty ``default_read_adapter_registry()`` and production
behavior is unchanged (every adapter rejects 404). This factory and the
``TheHiveReadAdapter`` are delivered and isolation-tested (unit + service-level
explicit injection) so the reader is production-ready; wiring the router means
changing that one call to
``reconcile_execution(db, execution_id, operator,
registry=create_read_adapter_registry(settings))`` and re-certifying against a
live runtime. Wiring it without runtime evidence would break the sealed
``TestEvidenceGap`` empty-registry invariant and the 60-site ``_inject_registry``
cross-layer seam, which relies on the router passing no registry.

Adapter-agnostic (unlike the write side). The write registry keys off
``EXECUTION_ADAPTER`` (single active adapter). The read side must not: a manual
reconcile targets a past execution whose adapter was recorded in history
(``detail["executor"]``), which may differ from the current ``EXECUTION_ADAPTER``.
So a reader is registered purely on its own credentials being present, never on
the active write selection.

Tolerant, not strict. A missing or malformed adapter configuration is skipped (a
caught ``ExecutorConfigError`` means no reader for that adapter), never raised: an
unconfigured adapter simply has no reader, so its reconcile fails closed at
``registry.get`` (404), and one adapter's misconfiguration can never 500 every
reconcile or block another adapter's reader.

No HTTP, no DB, no read is issued here: this module only assembles
credential-bearing reader objects; the actual ``GET`` happens inside ``read()`` at
reconcile time. Credentials ride the secret boundary
(``credentials_from_settings``), never this factory's own logic.
"""
from __future__ import annotations

from app.core.config import Settings, settings
from app.services.executions.exceptions import ExecutorConfigError
from app.services.executions.secrets import (
    AdapterCredentials,
    validate_api_key,
    validate_base_url,
)
from app.services.manual_reconcile.read.base import ReadAdapter
from app.services.manual_reconcile.read.registry import ReadAdapterRegistry
from app.services.read_adapters.thehive import (
    CERTIFIED_THEHIVE_VERSION,
    TheHiveReadAdapter,
)


def _thehive_readers(
    source: Settings, *, transport: object | None = None
) -> list[ReadAdapter]:
    """The TheHive reader iff it is fully authorized — not on mere URL + key
presence.

Three fail-closed gates, all required:
1. ``THEHIVE_BASE_URL`` present and well-formed;
2. ``THEHIVE_READ_API_KEY`` present — an independent read-only credential.
It never falls back to ``THEHIVE_API_KEY`` (the create-capable write
key): a reader must not carry create privilege it never needs (least
privilege);
3. ``THEHIVE_EXPECTED_VERSION`` exactly equals ``CERTIFIED_THEHIVE_VERSION``
(``4.1.24-1``) — an unset or mismatched expectation refuses, so 4.1.24-1
read semantics can never be applied to a different server version by a
one-line wiring change.

Any gate unmet -> ``[]`` (no reader, so the reconcile rejects 404 and fails
closed). Malformed config (a bad URL or key shape) -> ``[]`` too (caught
``ExecutorConfigError``), never raised, so one adapter's misconfiguration can
never 500 the reconcile route. ``transport`` is the test/deployment seam
forwarded to the reader (production ``None`` selects the reader's no-redirect
urllib opener, so a 3xx never carries Authorization cross-host).
"""
    base_url = str(getattr(source, "THEHIVE_BASE_URL", "") or "").strip()
    # Gate 2: an independent read-only key. The write key is not consulted here —
    # no fallback, least privilege.
    read_api_key = str(getattr(source, "THEHIVE_READ_API_KEY", "") or "").strip()
    # Gate 3: the operator-asserted target version.
    expected_version = str(
        getattr(source, "THEHIVE_EXPECTED_VERSION", "") or ""
    ).strip()
    if not base_url or not read_api_key:
        return []
    if expected_version != CERTIFIED_THEHIVE_VERSION:
        return []
    try:
        credentials = AdapterCredentials(
            adapter="thehive",
            base_url=validate_base_url("thehive", base_url),
            api_key=validate_api_key("thehive", read_api_key),
        )
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
    """Build the settings-driven read-adapter registry.

Returns a fresh ``ReadAdapterRegistry`` holding a concrete reader for every
adapter whose credentials are configured (today TheHive only; Shuffle and
Wazuh readers are not written yet). It never mutates the sealed
``default_read_adapter_registry()``. ``settings_obj`` defaults to the process
``settings`` resolved at call time, so a test may pass an explicit Settings.

This factory is not wired into the reconcile router (see the module
docstring); it is the delivered, tested wiring mechanism for a deployment that
has real runtime evidence.
"""
    source = settings_obj if settings_obj is not None else settings
    readers: list[ReadAdapter] = []
    readers.extend(_thehive_readers(source, transport=transport))
    return ReadAdapterRegistry(readers)
