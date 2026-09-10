"""Explicit deployment modes + the production startup gate (RC2 §7 / §20).

TWO MODES, ONE SWITCH. ``DEPLOYMENT_MODE`` (``demo`` | ``production``) makes
the deployment posture EXPLICIT instead of implied:

* **demo** (default) — the simple local UX: loopback binding is the exposure
  control, approval stays tokenless-but-display-only, the offline mock adapter
  is allowed. Nothing changes for evaluation users.
* **production** — FAIL-CLOSED at startup: ``validate_production_mode``
  collects EVERY unsafe setting and refuses to boot with ONE sanitized error
  naming the offending KEYS (never values). The checks cover the RC2 §7/§20
  production prohibitions:

  1. ``OPERATORS_JSON`` authentication is required (the legacy
     ``EXECUTION_TOKEN``-only path is demo folklore, not an identity source);
     the registry must contain at least one approval-capable and one
     execution-capable operator.
  2. PostgreSQL only — SQLite is demo/native-only (its single-writer lock
     cannot carry production concurrency semantics).
  3. A real execution adapter is required — mock execution outcomes must
     never be presented as real.
  4. Compensation / reverse workflows are REFUSED — the C-1 durable
     reservation is implemented but the reverse path is not yet
     production-certified (``EXECUTION_COMPENSATION_EXPERIMENTAL`` and
     ``SHUFFLE_WORKFLOW_REVERSE_*`` must stay off/empty).
  5. ``BIND_HOST`` must stay loopback — TLS + authentication terminate at a
     reverse proxy (see docs/operations/PRODUCTION-EDGE.md); the API port is
     never exposed directly.

The gate runs in the API lifespan BEFORE any adapter validation, so a
production misconfiguration can never half-boot and fail at the first write.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.core.config import Settings

#: The two accepted ``DEPLOYMENT_MODE`` values.
DEMO = "demo"
PRODUCTION = "production"
VALID_DEPLOYMENT_MODES = frozenset({DEMO, PRODUCTION})

#: BIND_HOST values that count as loopback for the production gate.
_LOOPBACK_BIND_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class ProductionModeError(RuntimeError):
    """The production startup gate refused to boot (fail-closed)."""


def deployment_mode(settings: Settings) -> str:
    """The normalized deployment mode; an unknown value is a config error."""
    value = str(getattr(settings, "DEPLOYMENT_MODE", DEMO) or DEMO).strip().lower()
    if value not in VALID_DEPLOYMENT_MODES:
        raise ProductionModeError(
            "DEPLOYMENT_MODE must be one of: demo, production "
            "(got an unrecognized value)"
        )
    return value


def is_production(settings: Settings) -> bool:
    """True when the deployment runs in the fail-closed production mode."""
    return deployment_mode(settings) == PRODUCTION


def validate_production_mode(settings: Settings) -> None:
    """Fail-closed startup gate: refuse production on ANY unsafe setting.

    DEMO mode returns immediately (the simple local UX is unchanged). In
    production the problems are COLLECTED and raised as ONE error naming the
    offending settings KEYS only — values (tokens, URLs, credentials) never
    enter the message.
    """
    if not is_production(settings):
        return

    problems: list[str] = []

    # 1) Authentication boundary (approval + execution + reconcile).
    raw_operators = str(getattr(settings, "OPERATORS_JSON", "") or "").strip()
    if not raw_operators:
        problems.append(
            "OPERATORS_JSON is required (production forbids the legacy "
            "EXECUTION_TOKEN-only auth path)"
        )
    else:
        from app.services.executions.operators import build_registry

        try:
            registry = build_registry(settings)
        except ValueError as exc:
            problems.append(f"OPERATORS_JSON is invalid ({exc})")
        else:
            roles = {operator.role for operator in registry.operators}
            if not any(role.can_approve for role in roles):
                problems.append(
                    "OPERATORS_JSON must include at least one reviewer/admin "
                    "(approval permission)"
                )
            if not any(role.can_execute for role in roles):
                problems.append(
                    "OPERATORS_JSON must include at least one executor/admin "
                    "(execution permission)"
                )

    # 2) Database backend.
    database_url = str(getattr(settings, "DATABASE_URL", "") or "")
    if not database_url.startswith("postgresql"):
        problems.append(
            "DATABASE_URL must be PostgreSQL (SQLite is demo/native only)"
        )

    # 3) Execution adapter (mock outcomes are demo-only).
    adapter = str(getattr(settings, "EXECUTION_ADAPTER", "") or "").strip().lower()
    if adapter in ("", "mock"):
        problems.append(
            "EXECUTION_ADAPTER must be a real adapter (mock execution "
            "outcomes are demo-only)"
        )

    # 4) Unsafe compensation / reverse workflows (not production-certified).
    from app.services.executions.registry import reverse_workflow_map_from_settings

    if getattr(settings, "EXECUTION_COMPENSATION_EXPERIMENTAL", False) or (
        reverse_workflow_map_from_settings(settings)
    ):
        problems.append(
            "compensation / reverse workflows are EXPERIMENTAL and not "
            "production-certified (leave SHUFFLE_WORKFLOW_REVERSE_* empty and "
            "EXECUTION_COMPENSATION_EXPERIMENTAL=false)"
        )

    # 5) Network exposure.
    bind_host = (
        str(getattr(settings, "BIND_HOST", "127.0.0.1") or "127.0.0.1").strip()
    )
    if bind_host not in _LOOPBACK_BIND_HOSTS:
        problems.append(
            "BIND_HOST must stay loopback in production (terminate TLS + "
            "authentication at a reverse proxy; see "
            "docs/operations/PRODUCTION-EDGE.md)"
        )

    if problems:
        raise ProductionModeError(
            "DEPLOYMENT_MODE=production refused to start (fail-closed); "
            "fix: " + "; ".join(problems)
        )

