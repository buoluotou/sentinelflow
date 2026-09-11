"""Fail when coverage drops below the recorded baseline.

Reads the JSON report pytest-cov writes and checks two things separately: the
whole-package statement coverage, and the statement coverage of the modules that
carry the execution, approval, policy, auth, durability and outcome logic.

The floors are the measured baseline of the default suite rounded down with
headroom, so ordinary churn passes and a real regression does not. Raise them
when the baseline moves; do not lower them to make a build green.

Usage:
check_coverage.py [coverage.json]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

FLOORS = {
    "total": 95.0,
    "app/services/executions/": 93.0,
    "app/services/outcomes/": 92.0,
    "app/services/manual_reconcile/": 95.0,
    "app/services/read_adapters/": 95.0,
    "app/api/v1/": 95.0,
    "app/core/": 92.0,
    "app/services/ai/": 92.0,
}


def _scope_percent(files: dict, prefix: str) -> tuple[int, int, float]:
    statements = missing = 0
    for path, entry in files.items():
        if path.replace("\\", "/").startswith(prefix):
            statements += entry["summary"]["num_statements"]
            missing += entry["summary"]["missing_lines"]
    if not statements:
        return 0, 0, 0.0
    return statements, missing, 100.0 * (statements - missing) / statements


def main(argv: list[str]) -> int:
    report = Path(argv[1] if len(argv) > 1 else "coverage.json")
    if not report.exists():
        print(f"FAIL: {report} not found (run pytest with --cov-report=json)")
        return 1
    data = json.loads(report.read_text(encoding="utf-8"))
    files = data["files"]
    totals = data["totals"]

    print(f"coverage report: {report}")
    print(f"{'scope':<36}{'statements':>11}{'missed':>8}{'cover':>9}{'floor':>8}")
    print("-" * 72)
    failures = []
    rows = [(
        "total",
        totals["num_statements"],
        totals["missing_lines"],
        100.0 * totals["covered_lines"] / totals["num_statements"],
    )]
    for prefix in FLOORS:
        if prefix == "total":
            continue
        rows.append((prefix, *_scope_percent(files, prefix)))

    for name, statements, missing, percent in rows:
        floor = FLOORS[name]
        print(f"{name:<36}{statements:>11}{missing:>8}{percent:>8.1f}%{floor:>7.1f}%")
        if percent < floor:
            failures.append(f"{name}: {percent:.1f}% < floor {floor:.1f}%")

    if failures:
        print("\nFAIL")
        for line in failures:
            print(f"  - {line}")
        return 1
    print("\nPASS: every scope is at or above its floor")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
