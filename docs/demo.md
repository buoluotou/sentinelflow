# SentinelFlow Demo Guide

A 15-minute end-to-end walkthrough: from an empty database to a fully triaged incident — alert storm, risk scoring, AI analysis chain, human approval, and the incident AI investigation view — using only the simulator and the web console.

> The default `AI_PROVIDER=mock` makes every AI step instant and offline-safe (deterministic output). To demo a real model, set `AI_PROVIDER=ollama` + `AI_MODEL=qwen3:4b` in `.env` and allow tens of seconds per generation.

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

## 6. AI analysis chain (Event Detail)

Open one high-risk event (e.g. *Malicious IOC match detected*, score 90). Three panels sit below the risk factor table, in analysis order:

1. **AI Alert Explanation** — click **Analyze with AI** → the panel fills with attack type, summary, why-risky factors, confidence and provider/model (mock: instant; qwen3:4b: ~30–60 s with a disabled "Analyzing…" state). Click again → a second history row is appended (the first is never overwritten); the page load itself only ever GETs.
2. **AI Risk Summary** — click **Generate Risk Summary** → analyst priority, key findings and frozen risk-driver vocabulary render. Note what is **absent**: no risk score anywhere — `EventRisk.score` (90) stays the single official number.
3. **Response Recommendation** — click **Generate Response Recommendation** → up to 5 suggestions with action labels (e.g. *Block source IP*, *Escalate to incident*), targets and rationales. There is no Approve/Execute button here — decisions live in the Approval Queue.

## 7. Approval Queue

1. Open the **Approval Queue** page → the recommendation generated above appears as pending ("pending" is derived — the database stores only approved/rejected).
2. Enter a reviewer name and click **Approve** → `201`, the item leaves the queue. Refresh: it stays gone (decision persisted).
3. Trying to decide twice returns `409` and re-syncs from the server — one decision per recommendation, ever.
4. Key boundary: approving recorded a human decision. Nothing was blocked, isolated or executed — the event, its risk and its incidents are untouched.

## 8. Incident AI Investigation (Incident Detail)

1. Open one of the auto-created incidents → the **AI Investigation** panel loads via a single `GET /incidents/{id}/ai-context`.
2. It shows the incident snapshot (status/severity + the frozen **risk score snapshot**) and the event's complete AI histories — explanation, risk summary and recommendation, newest first — with the **Approved** chip (reviewer + timestamp) auditing the Step 7 decision.
3. The panel renders **zero buttons**: no approve, reject or execute affordance of any kind — it observes, reviews and audits only.
4. An incident with no AI history shows the legal empty state "No AI analysis available yet." — not an error.

## 9. Reset

```powershell
# stop the backend first, then:
Remove-Item demo.db
Remove-Item Env:DATABASE_URL
```

## Notes

- The incident **risk snapshot** reflects the score at the first threshold crossing (e.g. the IOC case shows 70 — one critical alert — even though the event later reaches 90). This is intentional: case records are immutable history, live risk lives on the event — and no AI result ever writes it back.
- The simulator defaults to `--timestamps now` (current UTC); use `--timestamps file` for deterministic replay.
- AI panels are explicit-trigger only: refreshing any page emits GETs, never an automatic model call. Failures (provider down → 503, protocol violation → 502) surface the backend message verbatim and never persist a row.
- Approve ≠ Execute is the v1.1.0 safety boundary end-to-end: AI advises, humans decide, execution stays out of scope until Phase 3 (v2.0).
