"""A1 — Adapter Read Contract + Registry.

This step builds ONLY the read-side abstraction future concrete readers plug
into: ``AdapterReadRequest`` / ``AdapterReadResult`` / ``ReadAdapter`` (ABC) /
``ReadAdapterRegistry``, plus the read-adapter exception family. It is the PURE,
read-only, DB-free, HTTP-free, executor-free mirror of the write side.

ZERO real external HTTP, ZERO DB, ZERO executor coupling anywhere in this file's
subject: Shuffle / Wazuh / TheHive concrete readers are Evidence-Gapped and land
in 3.4.5-B/C/D; the Manual Reconcile API + pipeline is 3.4.5-A2. The production
default registry is EMPTY, so EVERY adapter (mock / shuffle / wazuh / thehive /
unknown) resolves to ``UnsupportedAdapterRead`` — a rejection, never a fake.

Coverage map (user-minimum bar, 25 items):
1. ReadAdapter contract shape        14. unsupported creates no fact
2. request immutable                 15. no HTTP
3. result immutable                  16. no DB
4. required execution_id             17. no executor
5. required adapter                  18. no write adapter
6. required external_reference       19. no execute/compensate
7. registry registration             20. deterministic lookup
8. registry lookup                   21. duplicate registration behavior
9. unknown adapter                   22. input immutability
10. mock unsupported                  23. output immutability
11. shuffle unsupported               24. external state remains raw
12. wazuh unsupported                 25. no outcome_status in ReadResult
13. thehive unsupported
"""
from __future__ import annotations

import ast
import dataclasses
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.services.manual_reconcile import (
    AdapterReadRequest,
    AdapterReadResult,
    ReadAdapter,
    ReadAdapterError,
    ReadAdapterRegistry,
    UnsupportedAdapterRead,
    default_read_adapter_registry,
)

_BACKEND_ROOT = Path(__file__).resolve().parents[1]
_READ_PKG = _BACKEND_ROOT / "app" / "services" / "manual_reconcile"

# The ONLY import roots the read layer may use: stdlib shape
# primitives + its own package. Anything else is a leak.
_ALLOWED_STDLIB_ROOTS = {
    "__future__",
    "abc",
    "collections",
    "collections.abc",
    "dataclasses",
    "datetime",
    "typing",
    "uuid",
}
_OWN_PACKAGE_ROOT = "app.services.manual_reconcile"

# Roots that must NEVER appear in the read layer.
_HTTP_ROOTS = {"urllib", "requests", "httpx", "aiohttp", "http"}
_DB_ROOTS = {"sqlalchemy", "alembic", "app.models", "app.db"}
_WRITE_ROOTS = {"app.services.executions"}
_OTHER_FORBIDDEN_ROOTS = {"fastapi", "starlette", "pydantic", "app.api", "app.services.outcomes"}
_FORBIDDEN_ROOTS = _HTTP_ROOTS | _DB_ROOTS | _WRITE_ROOTS | _OTHER_FORBIDDEN_ROOTS

# Modules that must be ABSENT from sys.modules after importing the read layer
# in a CLEAN interpreter.
_RUNTIME_FORBIDDEN_MODULES = (
    "sqlalchemy",
    "urllib.request",
    "requests",
    "httpx",
    "fastapi",
    "starlette",
    "pydantic",
    "app.models.execution_outcome",
    "app.services.executions.base",
    "app.services.executions.registry",
    "app.services.outcomes.reconciliation",
)

# The five outcome words — none may be a field of AdapterReadResult (test #25).
_OUTCOME_WORDS = (
    "confirmed_success",
    "confirmed_failure",
    "pending",
    "unknown",
    "reconciliation_failed",
)


def _read_layer_sources() -> list[Path]:
    """Every .py file shipped in the read layer (recursively)."""
    return sorted(_READ_PKG.rglob("*.py"))


def _import_roots(source: str) -> set[str]:
    """All imported module roots in one source file (Import + ImportFrom)."""
    tree = ast.parse(source)
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:  # relative intra-package imports have module too
                roots.add(node.module)
    return roots


def _is_allowed_root(root: str) -> bool:
    if root in _ALLOWED_STDLIB_ROOTS:
        return True
    return root == _OWN_PACKAGE_ROOT or root.startswith(_OWN_PACKAGE_ROOT + ".")


class _FakeReader(ReadAdapter):
    """Test-only concrete reader.

Exercises registry registration/lookup WITHOUT touching the production
default registry. Lives ONLY in tests — never imported by app code, never
registered into ``default_read_adapter_registry()``.
"""

    def __init__(self, name: str = "fake") -> None:
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def read(self, request: AdapterReadRequest) -> AdapterReadResult:
        # Echoes the RAW request adapter as an external state — no mapping, no
        # outcome word (mapping is 3.4.3-B / A2, never the read contract).
        return AdapterReadResult(
            external_state="observed-running",
            observed_at=None,
            raw_evidence={"requested_adapter": request.adapter},
        )


def _request(**overrides) -> AdapterReadRequest:
    base = {
        "execution_id": uuid.uuid4(),
        "adapter": "wazuh",
        "external_reference": "cmd-123",
    }
    base.update(overrides)
    return AdapterReadRequest(**base)


#
# 1 / 19 — ReadAdapter contract shape: read-only verb surface
#
class TestReadAdapterContract:
    """1/19. the ReadAdapter contract can ONLY read — no write verb exists."""

    def test_read_adapter_is_abstract_and_not_instantiable(self):
        # 1. it is a contract, never a concrete reader.
        with pytest.raises(TypeError):
            ReadAdapter()  # abstract: name + read unimplemented

    def test_read_adapter_verb_surface_is_read_only(self):
        # 19. the SOLE callable verb is ``read``; no write verb exists. Mirrors
        # the house ExecutorCapability surface audit.
        methods = {
            name
            for name, member in vars(ReadAdapter).items()
            if not name.startswith("_") and callable(member)
        }
        assert methods == {"read"}
        for forbidden in (
            "execute",
            "compensate",
            "dispatch",
            "trigger",
            "create_case",
            "send_command",
            "supports",
            "supports_compensation",
        ):
            assert forbidden not in methods

    def test_read_adapter_declares_name_and_read_abstract(self):
        # 1. both the identity property and the read verb are abstract.
        assert ReadAdapter.__abstractmethods__ == frozenset({"name", "read"})

    def test_read_is_not_a_response_executor(self):
        # 6/8. the read contract and the write contract are unrelated types —
        # neither is a subtype of the other (physical isolation, both directions).
        from app.services.executions.base import ResponseExecutor

        assert not issubclass(ReadAdapter, ResponseExecutor)
        assert not issubclass(ResponseExecutor, ReadAdapter)


#
# 2 / 4 / 5 / 6 / 22 — AdapterReadRequest: immutable, three required fields
#
class TestAdapterReadRequest:
    """2/4/5/6/22. the read request is a frozen, three-field, credential-free shape."""

    def test_request_is_frozen(self):
        # 2/22. immutable — a reader can never mutate its input.
        request = _request()
        with pytest.raises(dataclasses.FrozenInstanceError):
            request.adapter = "shuffle"
        with pytest.raises(dataclasses.FrozenInstanceError):
            request.external_reference = "tampered"

    def test_request_field_set_is_exact(self):
        # 4/5/6. exactly the three read-only fields — no credential, no token,
        # no write intent.
        names = {f.name for f in dataclasses.fields(AdapterReadRequest)}
        assert names == {"execution_id", "adapter", "external_reference"}

    def test_request_carries_no_credential_or_write_intent_field(self):
        # 3/9/11. the request never travels with a secret or a write verb.
        names = {f.name for f in dataclasses.fields(AdapterReadRequest)}
        for forbidden in (
            "api_key",
            "token",
            "password",
            "username",
            "credential",
            "authorization",
            "callback_token",
            "operator",
            "write_intent",
            "action",
        ):
            assert forbidden not in names

    @pytest.mark.parametrize("missing", ["execution_id", "adapter", "external_reference"])
    def test_request_requires_each_field(self, missing):
        # 4/5/6. every field is required — omitting one is a construction error.
        kwargs = {
            "execution_id": uuid.uuid4(),
            "adapter": "wazuh",
            "external_reference": "cmd-123",
        }
        del kwargs[missing]
        with pytest.raises(TypeError):
            AdapterReadRequest(**kwargs)


#
# 3 / 23 / 24 / 25 — AdapterReadResult: immutable, raw state, no outcome word
#
class TestAdapterReadResult:
    """3/23/24/25. the read result carries RAW external state, never an outcome word."""

    def test_result_is_frozen(self):
        # 3/23. immutable output.
        result = AdapterReadResult(
            external_state="completed", observed_at=None, raw_evidence={}
        )
        with pytest.raises(dataclasses.FrozenInstanceError):
            result.external_state = "failed"

    def test_result_field_set_is_exact_and_has_no_outcome_status(self):
        # 25. Adapter Read = External State; the outcome vocabulary is Mapping's.
        names = {f.name for f in dataclasses.fields(AdapterReadResult)}
        assert names == {"external_state", "observed_at", "raw_evidence"}
        assert "outcome_status" not in names
        assert "status" not in names

    def test_result_instance_exposes_no_outcome_word(self):
        # 25. no outcome word is an attribute of a result instance.
        result = AdapterReadResult(
            external_state="resolved", observed_at=None, raw_evidence={}
        )
        assert not hasattr(result, "outcome_status")
        for word in _OUTCOME_WORDS:
            assert not hasattr(result, word)

    def test_result_preserves_raw_external_state_string(self):
        # 24. a raw external state word is stored VERBATIM — never mapped.
        raw = "some-private-vendor-state-XYZ"
        result = AdapterReadResult(
            external_state=raw, observed_at=None, raw_evidence={}
        )
        assert result.external_state == raw

    def test_result_preserves_raw_external_state_mapping(self):
        # 24. a structured external state is preserved raw too (str | Mapping).
        raw = {"agent_status": "running", "nested": {"k": "v"}}
        result = AdapterReadResult(
            external_state=raw, observed_at=None, raw_evidence={}
        )
        assert result.external_state == raw

    def test_result_observed_at_may_be_none(self):
        # 9/12 (design). None signals "no reliable external timestamp" — the A2
        # platform then supplies a server observation time. A1 only defines it.
        result = AdapterReadResult(
            external_state="x", observed_at=None, raw_evidence={}
        )
        assert result.observed_at is None
        aware = datetime.now(timezone.utc)
        result2 = AdapterReadResult(
            external_state="x", observed_at=aware, raw_evidence={}
        )
        assert result2.observed_at == aware


#
# 7 / 8 / 20 / 21 — Registry mechanics
#
class TestRegistryMechanics:
    """7/8/20/21. registration, deterministic lookup, duplicate is an error."""

    def test_registration_then_lookup_returns_the_reader(self):
        # 7/8. a registered concrete reader resolves back out.
        reader = _FakeReader("fake")
        registry = ReadAdapterRegistry([reader])
        assert registry.get("fake") is reader
        assert registry.is_supported("fake") is True
        assert registry.registered_adapters() == ("fake",)

    def test_lookup_is_deterministic(self):
        # 20. the same name always resolves to the same reader object.
        reader = _FakeReader("fake")
        registry = ReadAdapterRegistry([reader])
        assert registry.get("fake") is registry.get("fake") is reader

    def test_registered_adapters_preserve_insertion_order(self):
        # 20. deterministic ordering for auditability.
        a, b = _FakeReader("aaa"), _FakeReader("bbb")
        registry = ReadAdapterRegistry([a, b])
        assert registry.registered_adapters() == ("aaa", "bbb")

    def test_duplicate_registration_is_a_construction_error(self):
        # 21. two readers claiming one name is a hard error, never a silent
        # overwrite (one adapter, one reader — no ambiguity).
        with pytest.raises(ValueError, match="duplicate read adapter registration"):
            ReadAdapterRegistry([_FakeReader("dup"), _FakeReader("dup")])

    def test_empty_registry_supports_nothing(self):
        # 7. a registry built with no readers resolves nothing.
        registry = ReadAdapterRegistry()
        assert registry.registered_adapters() == ()
        assert registry.is_supported("anything") is False


#
# 9 / 10 / 11 / 12 / 13 / 14 — Evidence Gap: every adapter is unsupported today
#
class TestEvidenceGap:
    """9-14. the production registry is EMPTY; every adapter rejects, no fact."""

    def test_default_registry_is_empty(self):
        # 15/16. NO concrete reader ships in A1.
        registry = default_read_adapter_registry()
        assert registry.registered_adapters() == ()

    @pytest.mark.parametrize("adapter", ["mock", "shuffle", "wazuh", "thehive"])
    def test_every_real_and_mock_adapter_is_unsupported(self, adapter):
        # 10/11/12/13. Evidence Gap: no reader exists for any of
        # them, so each rejects — the registry never fakes support.
        registry = default_read_adapter_registry()
        assert registry.is_supported(adapter) is False
        with pytest.raises(UnsupportedAdapterRead) as excinfo:
            registry.get(adapter)
        assert excinfo.value.adapter == adapter

    def test_mock_is_unsupported_and_has_no_reader(self, ):
        # 10/14. mock has no external system — never reconcilable,
        # and there is NO MOCK read adapter.
        registry = default_read_adapter_registry()
        with pytest.raises(UnsupportedAdapterRead):
            registry.get("mock")

    @pytest.mark.parametrize("unknown", ["nmap", "metasploit", "", "SHUFFLE", "Wazuh"])
    def test_unknown_adapter_is_unsupported(self, unknown):
        # 9. an unrecognized name rejects too (case-sensitive, no fuzzy match).
        registry = default_read_adapter_registry()
        with pytest.raises(UnsupportedAdapterRead) as excinfo:
            registry.get(unknown)
        assert excinfo.value.adapter == unknown

    def test_unsupported_is_a_read_adapter_error(self):
        # 14. the rejection derives from the read-layer base, so A2 can catch one
        # family and translate it to "rejected, no fact".
        registry = default_read_adapter_registry()
        with pytest.raises(UnsupportedAdapterRead) as excinfo:
            registry.get("wazuh")
        assert isinstance(excinfo.value, ReadAdapterError)
        assert isinstance(excinfo.value, Exception)

    def test_unsupported_returns_no_value_and_creates_no_fact(self):
        # 14. ``get`` on an unsupported adapter raises — it returns NOTHING, so
        # no external state and no Outcome Fact can arise from the rejection.
        registry = default_read_adapter_registry()
        with pytest.raises(UnsupportedAdapterRead):
            registry.get("shuffle")  # the ONLY outcome is the raise

    def test_unsupported_message_never_echoes_external_reference(self):
        # 13 (design). an adapter NAME is not a secret, but an external_reference
        # is an external handle — the rejection message carries only the name.
        registry = default_read_adapter_registry()
        with pytest.raises(UnsupportedAdapterRead) as excinfo:
            registry.get("thehive")
        message = str(excinfo.value)
        assert "thehive" in message
        assert "case_id" not in message
        assert "external_reference" not in message


#
# 15 / 16 / 17 / 18 — import surface: no HTTP, no DB, no executor/write adapter
#
class TestImportSurface:
    """15-18. static AST audit + clean-interpreter runtime proof of purity."""

    def test_read_layer_sources_exist(self):
        # guard: the audit below must actually see the shipped files.
        sources = _read_layer_sources()
        assert sources, "no read-layer sources found — audit would be vacuous"
        names = {p.name for p in sources}
        assert {"__init__.py", "exceptions.py", "base.py", "registry.py"} <= names

    def test_every_import_root_is_allowed(self):
        # 15/16/17/18. every import in the read layer is stdlib
        # shape primitives or its own package — nothing else.
        offenders: dict[str, set[str]] = {}
        for path in _read_layer_sources():
            bad = {
                root
                for root in _import_roots(path.read_text(encoding="utf-8"))
                if not _is_allowed_root(root)
            }
            if bad:
                offenders[str(path.relative_to(_BACKEND_ROOT))] = bad
        assert not offenders, f"read layer imported non-allowed roots: {offenders}"

    def test_no_http_import(self):
        # 15. no HTTP client anywhere in the read layer.
        for path in _read_layer_sources():
            roots = _import_roots(path.read_text(encoding="utf-8"))
            hit = {r for r in roots if r.split(".")[0] in _HTTP_ROOTS}
            assert not hit, f"{path.name} imports HTTP client {hit}"

    def test_no_db_import(self):
        # 16. no SQLAlchemy / model / DB import anywhere in the read layer.
        for path in _read_layer_sources():
            roots = _import_roots(path.read_text(encoding="utf-8"))
            hit = {r for r in roots if r in _DB_ROOTS or r.startswith(tuple(f"{d}." for d in _DB_ROOTS))}
            assert not hit, f"{path.name} imports DB layer {hit}"

    def test_no_executor_or_write_adapter_import(self):
        # 17/18. the read layer never imports the write side (executor / adapters
        # / registry). Physical isolation is enforced at the import surface.
        for path in _read_layer_sources():
            roots = _import_roots(path.read_text(encoding="utf-8"))
            hit = {
                r
                for r in roots
                if r == "app.services.executions"
                or r.startswith("app.services.executions.")
            }
            assert not hit, f"{path.name} imports write side {hit}"

    def test_no_other_forbidden_import(self):
        # 16. no FastAPI / pydantic / outcomes-mapping import either.
        for path in _read_layer_sources():
            roots = _import_roots(path.read_text(encoding="utf-8"))
            hit = {
                r
                for r in roots
                if any(r == f or r.startswith(f + ".") for f in _OTHER_FORBIDDEN_ROOTS)
            }
            assert not hit, f"{path.name} imports forbidden {hit}"

    def test_importing_read_layer_pulls_no_db_no_http_at_runtime(self):
        # 15/16/17/18. RUNTIME proof in a CLEAN interpreter: importing the read
        # layer must not transitively load any DB / HTTP / write / mapping module.
        code = (
            "import sys;"
            "import app.services.manual_reconcile;"
            f"bad=[m for m in {_RUNTIME_FORBIDDEN_MODULES!r} if m in sys.modules];"
            "assert not bad, f'read layer leaked: {bad}'"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(_BACKEND_ROOT),
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, f"purity subprocess failed:\n{proc.stderr}"


#
# 6 / 8 — ResponseExecutor is untouched (no read verb added to the write side)
#
class TestWriteSideUntouched:
    """6/8. the write contract stays write-only — no read() was added to it."""

    def test_response_executor_has_no_read_verb(self):
        from app.services.executions.base import ResponseExecutor

        members = {
            name
            for name, member in vars(ResponseExecutor).items()
            if not name.startswith("_")
        }
        assert "read" not in members
        assert "query" not in members
        # the write verbs remain exactly as sealed.
        assert {"execute", "compensate", "supports", "supports_compensation"} <= members
