# SentinelFlow Demo Guide

A 10-minute end-to-end walkthrough: from an empty database to a fully triaged incident, using only the simulator and the web console.

## 0. Prerequisites

Backend on port 8000 and frontend on port 5173 (see the [README Quick Start](../README.md#quick-start)). Use a **fresh** database for a clean demo:

```powershell
# Windows PowerShell example (SQLite — no Docker needed)
cd backend
$env:DATABASE_URL="sqlite:///demo.db"
python -m alembic upgrade head
python -m uvicorn app.main:app --port 8000
```

## 1. Empty state

Open `http://localhost:5173/`. The Dashboard shows all-zero metrics — the empty-state contract (every counter `0`, risk distribution all zeros).

## 2. Generate the alert storm

```powershell
python simulator/runner/run.py --repeat 30
```

Replays 5 attack scenarios × 30 repeats = **150 alerts**. Expected summary:

```
sent=150 failed=0

=== GET /api/v1/events (total=5) ===
  'Abnormal web request detected'          alert_count=30 risk_score=50 risk_level=medium
  'Suspicious process execution detected'  alert_count=30 risk_score=70 risk_level=medium
  'SSH login failure detected'             alert_count=30 risk_score=50 risk_level=medium
  'Malicious IOC match detected'           alert_count=30 risk_score=90 risk_level=high
  'File integrity change detected'         alert_count=30 risk_score=70 risk_level=medium
```

Why these scores: severity base + frequency band (30 alerts → +20). The scenario IPs are documentation-reserved ranges, so no public-source bonus applies.

## 3. Dashboard (auto-refreshes every 15 s)

| Metric | Expected |
|---|---|
| Active Incidents | 3 |
| Today's Alerts | 150 |
| Today's Events | 5 |
| Critical / High / Medium incidents | 1 / 2 / 0 |
| Risk distribution | high 1 · medium 4 · critical 0 · low 0 |

The 3 incidents were **auto-created** the first time each event's score reached ≥ 70.

## 4. Events

- The Events page lists 5 rows, each with 30 evidence alerts.
- Set **Risk level = high** → exactly 1 row remains (Malicious IOC, score 90).
- Open any event: fingerprint (64-hex), the explainable factor table (e.g. `severity +30, frequency +20, public_source +0`), and the full alert evidence list.

## 5. Incident triage

1. Open the Incident Queue → 3 cases, all `open`.
2. Open one case and click **Start Investigation** → status becomes `in progress`.
3. Click **Resolve** → `resolved`, timestamp + disposition recorded.
4. Click **Close** → `closed`; the action panel now states no further transitions are allowed.
5. Back in the queue, the case shows `closed`; the filter `status=closed` isolates it.

## 6. Reset

```powershell
# stop the backend first, then:
Remove-Item demo.db
Remove-Item Env:DATABASE_URL
```

## Notes

- The incident **risk snapshot** reflects the score at the first threshold crossing (e.g. the IOC case shows 70 — one critical alert — even though the event later reaches 90). This is intentional: case records are immutable history, live risk lives on the event.
- The simulator defaults to `--timestamps now` (current UTC); use `--timestamps file` for deterministic replay.
