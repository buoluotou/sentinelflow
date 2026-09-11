#!/usr/bin/env python3
"""Anti-false-green gate for the browser E2E job.

The browser suite is excluded from the default run and is only collected when
SENTINELFLOW_BROWSER_E2E=1 is set, so a misconfigured job can report green while
running nothing. Skips are equally unacceptable: a missing browser, a busy port
or a missing database must fail the job, not reduce it. This checker turns the
acceptance facts into hard assertions:

collected > 0, passed == collected, skipped == 0, failed == 0, errors == 0

It also requires every suite file to appear in the collection, so dropping a
module (or breaking its import) cannot pass as a smaller green run.

Usage (inside the CI job, after running pytest):

pytest tests/e2e -m browser -q --collect-only | tee /tmp/e2e-collect.txt
pytest tests/e2e -m browser -q                 | tee /tmp/e2e-run.txt
python scripts/ci/check_browser_e2e_result.py /tmp/e2e-collect.txt /tmp/e2e-run.txt

Exit code 0 only when every fact holds; any deviation fails the job.
"""
from __future__ import annotations

import pathlib
import re
import sys

# Every browser suite the job must collect. A missing entry means the module
# failed to import or was dropped, which is not a smaller green run.
EXPECTED_MODULES = (
    "test_execution_browser.py",
    "test_approval_queue_browser.py",
    "test_incident_ai_context_browser.py",
    "test_observability_browser.py",
)


def _count(text: str, word: str) -> int:
    match = re.search(rf"(\d+) {word}", text)
    return int(match.group(1)) if match else 0


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_browser_e2e_result.py <collect-output> <run-output>")
        return 2

    collect_text = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
    run_text = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")

    collected_match = re.search(r"(\d+) tests? collected", collect_text)
    collected = int(collected_match.group(1)) if collected_match else 0

    n_passed = _count(run_text, "passed")
    n_skipped = _count(run_text, "skipped")
    n_failed = _count(run_text, "failed")
    n_errors = _count(run_text, "errors?")

    problems: list[str] = []
    if collected == 0:
        problems.append(
            "collected=0 — the browser suite was not collected (a missing "
            "SENTINELFLOW_BROWSER_E2E=1 leaves tests/e2e excluded)"
        )
    for module in EXPECTED_MODULES:
        if module not in collect_text:
            problems.append(f"{module} was not collected")
    if n_passed != collected:
        problems.append(f"passed={n_passed}, expected {collected} (every collected test)")
    if n_skipped != 0:
        problems.append(
            f"skipped={n_skipped} — a skipped browser test means the stack "
            "degraded instead of running (false green)"
        )
    if n_failed != 0:
        problems.append(f"failed={n_failed}, expected 0")
    if n_errors != 0:
        problems.append(f"errors={n_errors}, expected 0")
    if "no tests ran" in run_text:
        problems.append("pytest reported 'no tests ran'")

    if problems:
        print("BROWSER_E2E_GATE=FAIL")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print(
        "BROWSER_E2E_GATE=OK "
        f"collected={collected} passed={n_passed} skipped=0 failed=0 errors=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
