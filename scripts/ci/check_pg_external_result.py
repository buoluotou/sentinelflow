#!/usr/bin/env python3
"""anti-false-green gate for the PostgreSQL external suite.

WHY. The external suite is guarded by ``SENTINELFLOW_PG_TEST_URL``: without
that env var every test SKIPS, pytest still exits 0, and a misconfigured CI job
would report GREEN while testing nothing. This checker turns the acceptance
facts into hard assertions:

collected = 22, passed = 22, skipped = 0, failed = 0, errors = 0

Usage (inside the CI job, after running pytest):

python -m pytest -m external --collect-only -q <files> | tee /tmp/pg-collect.txt
python -m pytest -m external -q <files>                | tee /tmp/pg-run.txt
python scripts/ci/check_pg_external_result.py /tmp/pg-collect.txt /tmp/pg-run.txt

Exit code 0 only when every fact holds; any deviation (including an
unexpected skip) fails the job.
"""
from __future__ import annotations

import pathlib
import re
import sys

# The acceptance fact: 9 dispatch + 9 compensation +
# 2 audit-ordering + 2 risk/incident.
EXPECTED_COLLECTED = 22


def _count(text: str, word: str) -> int:
    match = re.search(rf"(\d+) {word}", text)
    return int(match.group(1)) if match else 0


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check_pg_external_result.py <collect-output> <run-output>")
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
    if collected != EXPECTED_COLLECTED:
        problems.append(
            f"collected={collected}, expected exactly {EXPECTED_COLLECTED} "
            "(a missing SENTINELFLOW_PG_TEST_URL silently collapses collection)"
        )
    if n_passed != EXPECTED_COLLECTED:
        problems.append(f"passed={n_passed}, expected exactly {EXPECTED_COLLECTED}")
    if n_skipped != 0:
        problems.append(
            f"skipped={n_skipped} — a skipped external test means the real "
            "PostgreSQL suite silently degraded (would be a false green)"
        )
    if n_failed != 0:
        problems.append(f"failed={n_failed}, expected 0")
    if n_errors != 0:
        problems.append(f"errors={n_errors}, expected 0")
    if "no tests ran" in run_text:
        problems.append("pytest reported 'no tests ran'")

    if problems:
        print("PG_EXTERNAL_GATE=FAIL")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print(
        "PG_EXTERNAL_GATE=OK "
        f"collected={collected} passed={n_passed} skipped=0 failed=0 errors=0"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
