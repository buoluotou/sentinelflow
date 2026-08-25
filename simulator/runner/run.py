#!/usr/bin/env python3
"""SentinelFlow Scenario Simulator Runner (Phase 1 Step 6).

Loads scenario definitions from ``simulator/scenarios/*/events.json`` and
replays them against a running SentinelFlow backend:

    scan scenarios -> local validation -> POST /api/v1/alerts
    -> real-time feedback -> GET /api/v1/events summary

Design constraints (frozen in the Step 6 plan):
- stdlib only (no third-party dependencies)
- events are sent AS-IS to POST /api/v1/alerts (the unified entry point);
  the /normalize route is reserved for raw third-party feeds (e.g. Wazuh),
  because fingerprint identity includes ``source`` and must not split
- sequential sending only, no concurrency, no daemon mode
- exit code is non-zero if any send fails

Usage::

    python simulator/runner/run.py --repeat 30 --timestamps now
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "scenarios"
DEFAULT_BASE_URL = "http://127.0.0.1:8000"

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
REQUIRED_EVENT_KEYS = ("source", "event_type", "severity")

# Corporate proxies often intercept localhost traffic (returning 502 etc.);
# the runner always talks to the backend directly.
_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


class ScenarioError(Exception):
    """Raised when a scenario file is missing or fails local validation."""


def discover_scenarios(scenarios_dir: Path, name: str | None = None) -> list[Path]:
    """Return the events.json paths of all scenarios (or one named scenario)."""
    if not scenarios_dir.is_dir():
        raise ScenarioError(f"scenarios directory not found: {scenarios_dir}")

    if name is not None:
        path = scenarios_dir / name / "events.json"
        if not path.is_file():
            raise ScenarioError(f"scenario not found: {name} ({path})")
        return [path]

    paths = sorted(scenarios_dir.glob("*/events.json"))
    if not paths:
        raise ScenarioError(f"no scenarios found under {scenarios_dir}")
    return paths


def load_scenario(path: Path) -> dict:
    """Load and validate the scenario envelope: {scenario, events: [...]}."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScenarioError(f"cannot read scenario file {path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ScenarioError(f"scenario root must be an object: {path}")
    if not isinstance(data.get("events"), list) or not data["events"]:
        raise ScenarioError(f"scenario must contain a non-empty 'events' list: {path}")
    return data


def validate_event(event: dict, scenario_name: str) -> None:
    """Fail fast on events that the backend AlertCreate schema would reject."""
    if not isinstance(event, dict):
        raise ScenarioError(f"[{scenario_name}] event must be an object")
    for key in REQUIRED_EVENT_KEYS:
        value = event.get(key)
        if not isinstance(value, str) or not value:
            raise ScenarioError(f"[{scenario_name}] event missing required key '{key}'")
    severity = event["severity"].lower()
    if severity not in VALID_SEVERITIES:
        raise ScenarioError(
            f"[{scenario_name}] invalid severity '{event['severity']}' "
            f"(expected one of {sorted(VALID_SEVERITIES)})"
        )


def prepare_event(event: dict, timestamps: str) -> dict:
    """Return a send-ready copy of the event.

    ``timestamps == "now"`` rewrites the event timestamp to the current UTC
    time on every call so repeated sends climb the dedup frequency bands;
    ``"file"`` replays the stored timestamp for deterministic reruns.
    """
    prepared = dict(event)
    if timestamps == "now":
        prepared["timestamp"] = datetime.now(timezone.utc).isoformat()
    return prepared


def _request(method: str, url: str, body: bytes | None = None) -> tuple[int, dict]:
    """Perform one HTTP request; always return (status, parsed-json-or-text)."""
    request = urllib.request.Request(url, data=body, method=method)
    request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json")
    try:
        with _NO_PROXY_OPENER.open(request, timeout=30) as response:
            raw = response.read().decode("utf-8")
            status = response.status
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read().decode("utf-8", errors="replace")
        except OSError:
            raw = ""  # server dropped the connection along with the error
        status = exc.code
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return 0, {"error": f"connection failed: {reason}"}
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, {"body": raw}


def send_event(base_url: str, event: dict) -> tuple[int, dict]:
    """POST one event to /api/v1/alerts and return (status, response body)."""
    url = f"{base_url.rstrip('/')}/api/v1/alerts"
    return _request("POST", url, json.dumps(event).encode("utf-8"))


def fetch_events(base_url: str) -> tuple[int, dict]:
    """GET /api/v1/events (max page) for the post-run summary."""
    url = f"{base_url.rstrip('/')}/api/v1/events?size=100"
    return _request("GET", url)


def run(args: argparse.Namespace) -> int:
    """Execute one replay pass; return the process exit code."""
    try:
        paths = discover_scenarios(Path(args.scenarios_dir), args.scenario)
        # Validate everything up front: fail fast before touching the backend.
        scenarios = []
        for path in paths:
            data = load_scenario(path)
            name = data.get("scenario") or path.parent.name
            for event in data["events"]:
                validate_event(event, name)
            scenarios.append((name, data["events"]))
    except ScenarioError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    total = sum(len(events) for _, events in scenarios) * args.repeat
    print(f"SentinelFlow Scenario Runner -> {args.base_url}")
    print(
        f"scenarios={len(scenarios)} events={total} interval={args.interval}s "
        f"timestamps={args.timestamps}"
    )

    sent = failed = 0
    for name, events in scenarios:
        print(f"\n--- scenario: {name} ---")
        for event in events:
            for attempt in range(1, args.repeat + 1):
                status, body = send_event(args.base_url, prepare_event(event, args.timestamps))
                if status == 201:
                    sent += 1
                    print(
                        f"[{name} {attempt}/{args.repeat}] 201 "
                        f"group={body.get('alert_group_id')} "
                        f"event_type={event['event_type']}"
                    )
                else:
                    failed += 1
                    detail = body.get("detail") or body.get("error") or body
                    print(
                        f"[{name} {attempt}/{args.repeat}] FAILED status={status} {detail}",
                        file=sys.stderr,
                    )
                if args.interval > 0 and not (
                    attempt == args.repeat
                    and event is events[-1]
                    and name == scenarios[-1][0]
                ):
                    time.sleep(args.interval)

    print(f"\nsent={sent} failed={failed}")

    status, body = fetch_events(args.base_url)
    if status == 200:
        items = body.get("items", [])
        print(f"\n=== GET /api/v1/events (total={body.get('total')}, showing {len(items)}) ===")
        for item in items:
            print(
                f"  {item.get('title')!r:60} alert_count={item.get('alert_count'):>3} "
                f"risk_score={item.get('risk_score')} risk_level={item.get('risk_level')}"
            )
    else:
        print(f"\nWARNING: GET /api/v1/events returned status={status}", file=sys.stderr)

    return 0 if failed == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinelflow-runner",
        description="Replay SentinelFlow simulator scenarios against the backend API.",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"backend base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--scenario",
        default=None,
        help="scenario directory name, e.g. ssh_failed_login (default: all)",
    )
    parser.add_argument(
        "--repeat", type=int, default=1, help="repetitions per event (default: 1)"
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="seconds between consecutive sends (default: 1.0)",
    )
    parser.add_argument(
        "--timestamps",
        choices=("now", "file"),
        default="now",
        help="'now' rewrites each timestamp to current UTC (default); "
        "'file' replays the stored timestamp deterministically",
    )
    parser.add_argument(
        "--scenarios-dir",
        default=str(SCENARIOS_DIR),
        help="override the scenarios directory (used by tests)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.repeat < 1:
        parser.error("--repeat must be >= 1")
    if args.interval < 0:
        parser.error("--interval must be >= 0")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
