"""Fixtures shared by the browser E2E suites in this directory.

pytest discovers fixtures in a conftest or in the test module itself, so the
implementations living in ``harness.py`` are re-exported here. A module may still
override ``stack_seed`` to insert its own rows before uvicorn starts.
"""
from tests.e2e.harness import (  # noqa: F401  (pytest fixtures)
    browser_page,
    browser_type_launch_args,
    stack,
    stack_seed,
)
