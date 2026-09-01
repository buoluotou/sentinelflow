"""Operator Identity & Role Registry (Phase 3.3.1).

Static operator registry: Bearer token -> authenticated Operator (name +
role). Identity ALWAYS comes from the Authorization header — the client
can never impersonate an operator by sending a name in the request body.

Registry sources (evaluated in order):
    1. OPERATORS_JSON — JSON array of {token, name, role} objects
    2. Legacy EXECUTION_TOKEN — fallback when OPERATORS_JSON is empty;
       mapped to a synthetic operator named "legacy-execution" with the
       "executor" role (backwards compatible with Phase 3.1 auth).

Role vocabulary (frozen, §3.3.1):
    viewer    — read-only audit access (no execution, no approval)
    reviewer  — approve / reject recommendations (no execution)
    executor  — dispatch executions and compensations
    admin     — full access (executor + configuration)

Token security: tokens are compared with secrets.compare_digest (constant
time) and NEVER enter logs, responses, exception strings, audit detail,
or the database (mirrors the Phase 3.2 adapter-credential discipline).
"""
from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.core.config import Settings


class OperatorRole(str, Enum):
    """Frozen role vocabulary (Phase 3.3.1).

    Roles are ordered by increasing privilege; ``can_execute`` covers
    executor + admin (the two roles allowed to dispatch executions)."""

    VIEWER = "viewer"
    REVIEWER = "reviewer"
    EXECUTOR = "executor"
    ADMIN = "admin"

    @property
    def can_execute(self) -> bool:
        """Whether this role may dispatch executions / compensations."""
        return self in (OperatorRole.EXECUTOR, OperatorRole.ADMIN)


#: All valid role string values (for validation error messages).
VALID_ROLES = frozenset(role.value for role in OperatorRole)

#: The operator name used when the legacy EXECUTION_TOKEN authenticates
#: (backwards-compatible fallback when OPERATORS_JSON is empty).
LEGACY_OPERATOR_NAME = "legacy-execution"


@dataclass(frozen=True)
class Operator:
    """An authenticated operator (token resolved to identity + role).

    Tokens are NEVER stored on the instance — only the resolved identity
    (name + role) survives authentication. This ensures the token cannot
    leak through repr, logging, serialization, or audit detail."""

    name: str
    role: OperatorRole


class OperatorRegistry:
    """Token -> Operator lookup with legacy EXECUTION_TOKEN fallback.

    The registry is built at startup from ``OPERATORS_JSON``; if that is
    empty AND ``EXECUTION_TOKEN`` is set, a single legacy operator is
    accepted (Phase 3.1 backwards compatibility). An empty registry with
    no legacy token keeps every write path fully closed (401)."""

    def __init__(self, operators: list[Operator], tokens: list[str]) -> None:
        #: token -> operator mapping (tokens are the lookup keys, never
        #: stored on Operator instances).
        self._by_token: dict[str, Operator] = dict(zip(tokens, operators))
        #: name -> operator for display / debugging (no token stored).
        self._by_name: dict[str, Operator] = {op.name: op for op in operators}

    # -- lookup ----------------------------------------------------------

    def lookup(
        self, token: str, *, legacy_token: str = ""
    ) -> Operator | None:
        """Resolve a Bearer token to an Operator.

        Returns ``None`` when the token matches no registered operator
        and no legacy fallback applies. The caller (auth dependency)
        raises 401 in that case — the registry itself stays silent."""
        # 1. Registered operators (OPERATORS_JSON).
        for known_token, operator in self._by_token.items():
            if secrets.compare_digest(token, known_token):
                return operator
        # 2. Legacy EXECUTION_TOKEN fallback.
        if legacy_token and secrets.compare_digest(token, legacy_token):
            return Operator(name=LEGACY_OPERATOR_NAME, role=OperatorRole.EXECUTOR)
        return None

    # -- introspection (tests / debug) -----------------------------------

    @property
    def operator_count(self) -> int:
        return len(self._by_token)

    def has_operator(self, name: str) -> bool:
        return name in self._by_name

    def get_by_name(self, name: str) -> Operator | None:
        return self._by_name.get(name)

    def __repr__(self) -> str:
        names = list(self._by_name.keys())
        return f"OperatorRegistry(operators={names})"


# ---------------------------------------------------------------------------
# Module-level factory (lazy, testable)
# ---------------------------------------------------------------------------
_registry: OperatorRegistry | None = None


def build_registry(settings: Settings) -> OperatorRegistry:
    """Build an OperatorRegistry from application settings.

    ``OPERATORS_JSON`` takes precedence; when it is empty AND
    ``EXECUTION_TOKEN`` is set, the registry is empty but the legacy
    token remains available via ``lookup(legacy_token=...)``. When both
    are empty, every write path stays fully closed (401)."""
    operators: list[Operator] = []
    tokens: list[str] = []

    raw = settings.OPERATORS_JSON.strip()
    if raw:
        try:
            entries = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"OPERATORS_JSON is not valid JSON: {exc.msg}"
            ) from exc
        if not isinstance(entries, list):
            raise ValueError("OPERATORS_JSON must be a JSON array")
        seen_tokens: set[str] = set()
        seen_names: set[str] = set()
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ValueError(f"OPERATORS_JSON[{i}] must be an object")
            tok = str(entry.get("token", ""))
            name = str(entry.get("name", ""))
            role_str = str(entry.get("role", ""))
            if not tok:
                raise ValueError(f"OPERATORS_JSON[{i}].token is empty")
            if not name:
                raise ValueError(f"OPERATORS_JSON[{i}].name is empty")
            if role_str not in VALID_ROLES:
                raise ValueError(
                    f"OPERATORS_JSON[{i}].role={role_str!r} is not valid; "
                    f"must be one of: {', '.join(sorted(VALID_ROLES))}"
                )
            if tok in seen_tokens:
                raise ValueError(
                    f"OPERATORS_JSON[{i}].token is a duplicate"
                )
            if name in seen_names:
                raise ValueError(
                    f"OPERATORS_JSON[{i}].name={name!r} is a duplicate"
                )
            seen_tokens.add(tok)
            seen_names.add(name)
            operators.append(Operator(name=name, role=OperatorRole(role_str)))
            tokens.append(tok)

    return OperatorRegistry(operators, tokens)


def get_operator_registry() -> OperatorRegistry:
    """Return the module-level registry (lazy-built from settings)."""
    global _registry
    if _registry is None:
        from app.core.config import settings
        _registry = build_registry(settings)
    return _registry


def reset_operator_registry() -> None:
    """Reset the module-level registry (test seam — forces rebuild from
    current settings on next ``get_operator_registry()`` call)."""
    global _registry
    _registry = None


__all__ = [
    "LEGACY_OPERATOR_NAME",
    "Operator",
    "OperatorRegistry",
    "OperatorRole",
    "VALID_ROLES",
    "build_registry",
    "get_operator_registry",
    "reset_operator_registry",
]
