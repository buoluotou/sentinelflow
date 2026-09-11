# SentinelFlow Demo Guide

An end-to-end walkthrough that takes about 15 minutes. It starts from an empty database, replays an alert storm, scores risk, runs the AI analysis chain, records a human approval, dispatches one controlled execution, and shows the incident AI investigation view. Everything here uses the simulator and the web console.

The default `AI_PROVIDER=mock` makes every AI step instant, offline and deterministic. To use a real model, set `AI_PROVIDER=ollama` + `AI_MODEL=qwen3:4b` in `.env` and allow tens of seconds per generation.

The default `EXECUTION_ADAPTER=mock` makes execution a zero-outbound DryRun, so the approve → execute → audit chain runs without any external call.

## 0. Prerequisites

Backend on port 8000 and frontend on port 5173. The fastest route is the
**[Docker Quickstart](QUICKSTART.md)** (`scripts/quickstart.ps1` / `.sh`), which
provisions **PostgreSQL** and runs this whole demo, including the step 8
execution, end to end.

Steps 1–7 (alert → incident → AI → approval) run on either PostgreSQL or SQLite.
**Step 8 (response execution) requires PostgreSQL**: the durable dispatch attempt
is committed on an independent connection, which SQLite's single write lock
cannot satisfy, so on SQLite that step returns HTTP 500 before dispatching
anything and makes no external call. See
[Troubleshooting](TROUBLESHOOTING.md#3-sqlite-execution-returns-500-database-is-locked).
For a PostgreSQL-free trial of steps 1–7:

```powershell
# Windows PowerShell: SQLite, chain through approval (step 8 returns HTTP 500)
cd backend
$env:DATABASE_URL="sqlite:///demo.db"
python -m alembic upgrade head
python -m uvicorn app.main:app --port 8000
```

## 1. Empty state

Open `http://localhost:5173/`. The Dashboard shows all-zero metrics: every counter `0`, risk distribution all zeros.

## 2. Generate the alert storm

```powershell
python simulator/runner/run.py --repeat 30
```

Replays 5 attack scenarios × 30 repeats = **150 alerts**. Expected summary:

```
sent=150 failed=0

=== GET /api/v1/events (total=5, showing 5) ===
  'Abnormal web request detected'          alert_count=30 risk_score=50 risk_level=medium
  'Suspicious process execution detected'  alert_count=30 risk_score=70 risk_level=medium
  'SSH login failure detected'             alert_count=30 risk_score=50 risk_level=medium
  'Malicious IOC match detected'           alert_count=30 risk_score=90 risk_level=high
  'File integrity change detected'         alert_count=30 risk_score=70 risk_level=medium
```

Why these scores: severity base plus frequency band (30 alerts → +20). The scenario IPs are documentation-reserved ranges, so no public-source bonus applies.

## 3. Dashboard (auto-refreshes every 15 s)

| Metric | Expected |
|---|---|
| Active Incidents | 3 |
| Today's Alerts | 150 |
| Today's Events | 5 |
| Critical / High / Medium incidents | 1 / 2 / 0 |
| Risk distribution | high 1 · medium 4 · critical 0 · low 0 |

The 3 incidents were created automatically the first time each event's score reached ≥ 70.

## 4. Events

- The Events page lists 5 rows, each with 30 evidence alerts.
- Set **Risk level = high** → exactly 1 row remains (Malicious IOC, score 90).
- Open any event: fingerprint (64-hex), the risk factor table (for example `severity +30, frequency +20, public_source +0`), and the full alert evidence list.

## 5. Incident triage

1. Open the Incident Queue → 3 cases, all `open`.
2. Open one case and click **Start Investigation** → status becomes `in progress`.
3. Click **Resolve** → `resolved`, timestamp + disposition recorded.
4. Click **Close** → `closed`; the action panel now states no further transitions are allowed.
5. Back in the queue, the case shows `closed`; the filter `status=closed` isolates it.

## 6. AI analysis chain (Event Detail)

Open one high-risk event (for example *Malicious IOC match detected*, score 90). Three panels sit below the risk factor table, in analysis order:

1. **AI Alert Explanation** — click **Analyze with AI** → the panel fills with attack type, summary, why-risky factors, confidence and provider/model (mock: instant; qwen3:4b: ~30–60 s with a disabled "Analyzing…" state). Click again → a second history row is appended and the first one stays as it was. Loading the page only reads existing history; it does not call the model.
2. **AI Risk Summary** — click **Generate Risk Summary** → analyst priority, key findings and risk drivers render. No risk score appears here: `EventRisk.score` (90) stays the single official number.
3. **Response Recommendation** — click **Generate Response Recommendation** → up to 5 suggestions with action labels (for example *Block source IP*, *Escalate to incident*), targets and rationales. There is no Approve or Execute button here; decisions live in the Approval Queue.

## 7. Approval Queue

1. Open the **Approval Queue** page → the recommendation generated above appears as pending ("pending" is derived — the database stores only approved/rejected).
2. Enter a reviewer name and click **Approve** → `201`, the item leaves the queue. Refresh: it stays gone, because the decision was persisted.
3. Trying to decide twice returns `409` and re-syncs from the server. Only one decision per recommendation is accepted.
4. Approving recorded a human decision. Nothing was blocked, isolated or executed — the event, its risk and its incidents are untouched.

## 8. Response execution

1. Open **Incidents**, pick the case whose event carries the recommendation you approved in step 7, and scroll to its **AI Investigation** panel. The approved recommendation appears there with an **Execute** control, because the approval is already recorded. There is no separate Execute Console page.
2. Click **Execute** → the dialog asks for **Operator**, **Execution Token** and an optional **Comment** → click **Confirm Execute**. The action comes from the recommendation; there is no action picker. The recorded operator identity comes from the Bearer token (RBAC), not from the Operator field, which is display-only. Only `executor` / `admin` roles may dispatch; without a token the request is `401`.
3. The MockExecutor processes the request as a zero-outbound DryRun: `201` with `status=succeeded`, `detail` showing `{"dry_run": true}`. No real external call is made.
4. Open the **Execution Audit** page — the append-only `execution_log` shows the row you just created: execution id, adapter name (`mock`), action, target, operator, status (`succeeded`), and the redacted detail. Secrets never appear.
5. With `EXECUTION_ADAPTER=mock`, the approve → execute → audit chain is recorded end to end with no external side effect. Switching `EXECUTION_ADAPTER` to `shuffle` / `wazuh` / `thehive` in `.env` (plus credentials) activates a real adapter — the chain stays identical, only the outbound target changes.
6. **Execution Observability** — open the **Execution Observability** page: the metrics cards show the run you just executed (total / succeeded / failed / guard-rejected / in-flight, success rate), and the adapter card shows `Observed: healthy` for the mock adapter. The page has **zero buttons** and emits only the two read-only GETs (`/executions/metrics` + `/executions/health`). "Observed" is derived from the recorded audit rows; there is no live health probe. Empty denominators render as N/A, never 0%.

## 9. Incident AI Investigation (Incident Detail)

1. Open one of the auto-created incidents → the **AI Investigation** panel loads via a single `GET /incidents/{id}/ai-context`.
2. It shows the incident snapshot (status/severity + the risk score captured when the incident was created) and the event's complete AI histories — explanation, risk summary and recommendation, newest first — with the **Approved** chip (reviewer + timestamp) for the decision you made in step 7.
3. Apart from the guarded **Execute** control described in step 8, the panel is read-only (one `GET`, zero writes) and offers no approve/reject affordance — decisions belong to the Approval Queue. The Execute control POSTs `/api/v1/executions`, and every request is still gated server-side by RBAC + Guard + policy.
4. An incident with no AI history shows the empty state "No AI analysis available yet." — not an error.

## 10. Reset

```powershell
# stop the backend first, then:
Remove-Item demo.db
Remove-Item Env:DATABASE_URL
```

## Notes

- The incident **risk snapshot** holds the score from the first threshold crossing (the IOC case shows 70 — one critical alert — even though the event later reaches 90). Incident records are history; live risk lives on the event, and no AI result writes it back.
- The simulator defaults to `--timestamps now` (current UTC); use `--timestamps file` for a deterministic replay.
- AI panels run only when you click. Refreshing any page emits GETs and never triggers a model call. Failures (provider down → 503, malformed output → 502) surface the backend message verbatim and persist no row.
- Approving and executing are separate steps: the AI advises, a human decides, and dispatch is a separate chain governed by RBAC, the Guard and the execution policy, with read-only metrics and observed adapter health on top. The MockExecutor runs that chain without external side effects; real adapters (Shuffle / Wazuh / TheHive) need their `.env` sections filled in plus credentials.
