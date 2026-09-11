# External Integration Safety Matrix (RC2 §11)

**One capability per row — never one PASS for everything.** Statuses are from
the RC2 finalization round (2026-09-10/11, isolated Kali lab). Code-level
certification comes from the frozen M4 evidence line; lab status comes from
this round's real runtime only.

Status vocabulary: `PASS` · `PARTIAL` · `BLOCKED` · `UNVERIFIED` ·
`NOT IN SCOPE` · `RESOURCE BLOCKED`.

---

## 1. TheHive (case management) — 4.1.24-1

| Capability | Status | Evidence / detail |
|---|---|---|
| CONNECTIVITY | **PASS** | Isolated Docker lab, `127.0.0.1:9000`, image digest `sha256:c8b6c7ea...c6811` verified against the M2-R reference; Cassandra 3.11 + Lucene (no ES). `/api/status` 200. |
| AUTH | **PASS** | Bearer API keys. Purpose org `sf-lab` + `org-admin` writer key + **independent read-only key** (GET 200 / POST 403). Key rotation invalidates the old key (401 observed). |
| WRITE | **PASS** | Real `POST /api/case` through the durable dispatch chain: `derived_state=succeeded`, `case_id=~8408` (caseId 7), severity 3, tags `[sentinelflow, sentinelflow:execution:<uuid>, sentinelflow:approval:<uuid>]`. |
| RESOURCE REFERENCE | **PASS** | Response `_id`/`id` string `~8408` is the reference; `caseId` (int) audit-only; persisted as the frozen reconcile key `detail.case_id`. |
| READ | **PASS** | `GET /api/case/{_id}` via the trusted reader: `resource_id=~8408`, `correlation_tag_present=True`, `external_created_at` = case `createdAt`; also independently observable with a separate read-only key. |
| CORRELATION | **PASS** | `sentinelflow:execution:<uuid>` + `sentinelflow:approval:<uuid>` tags persisted by TheHive and echoed back; reader verified the tag matches THIS execution. |
| OUTCOME PROOF | **BLOCKED BY GATE 5** | OutputCase carries no authoritative instance/tenant; reader observes `observed_instance=observed_tenant=None`; platform refuses to fabricate → `UnrecognizedExternalState`, **zero outcome facts**. Correct fail-closed result. |
| RETRY BEHAVIOUR | **PASS** | Zero automatic retry / polling / callbacks (frozen); one POST, one GET — observed in the lab (attempt, dispatch, terminal, single read). |
| IDEMPOTENCY | **PARTIAL** | No certified duplicate contract for case creation → 409 and any non-string-id 2xx are fail-closed (`failed`). Not exercised against the live lab in this round (no deliberate duplicate POST). |
| LAB | **PASS** | Real runtime, throwaway data, loopback only. Runtime findings recorded: platform `admin` profile lacks `manageCase` (403); the system `admin` org lacks the freetag taxonomy (404 on tagged create); a purpose-created org + org-admin profile resolves both. |
| PRODUCTION | **NOT CERTIFIED** | TheHive 4 is EOL/archived — lab-only compatibility target. See `THEHIVE-SUPPORTED-VERSION-FEASIBILITY.md`. |

## 2. Shuffle (workflow orchestration) — no lab

| Capability | Status | Evidence / detail |
|---|---|---|
| CONNECTIVITY | **NOT VALIDATED (RESOURCE BLOCKED)** | The official open-source compose needs shuffle-frontend + shuffle-backend + shuffle-orborus + **OpenSearch** (plus Redis in most deployments) — measured host headroom during this round (≈0.8–1.8 GB available with the SentinelFlow/TheHive labs running, 6.2 GB total) cannot host that stack alongside the already-running labs. A meaningful trigger test additionally requires provisioning a workflow + API key in the UI. |
| AUTH | **SOURCE-CERTIFIED** | Bearer API key, header-only (3.2.2 secret boundary); not exercised against a live instance. |
| WRITE | **NOT VALIDATED** | Adapter contract frozen (trigger only; `succeeded` == trigger confirmed, never workflow completion). Unit/integration-certified against stubs. |
| RESOURCE REFERENCE | **SOURCE-CERTIFIED** | Trigger response carries the workflow execution id (`external_execution_id`); live shape unverified. |
| READ | **NOT IN SCOPE** | No Shuffle reader exists; the production read registry stays EMPTY (fail-closed 404). |
| CORRELATION | **SOURCE-CERTIFIED** | `sentinelflow_execution_id` in every trigger body; live echo unverified. |
| OUTCOME PROOF | **BLOCKED (VOCABULARY EMPTY)** | No shared external-state word is certified for Shuffle; `FINISHED` etc. never map to effect success. Outcome stays UNKNOWN without version-specific evidence. |
| RETRY BEHAVIOUR | **PASS (frozen)** | Zero automatic retry / polling (E5). |
| IDEMPOTENCY | **SOURCE-CERTIFIED** | External duplicate signals (409 / "already triggered") map to `succeeded` as an idempotency hit (frozen §5 rule 3); not lab-exercised. |
| LAB | **RESOURCE BLOCKED** | Minimum recommended for a real Shuffle lab: ≥4 GB free RAM (OpenSearch ≥1 GB heap + backend/workers), plus workflow + API-key provisioning. |
| PRODUCTION | **NOT CERTIFIED** | LAB / EXPERIMENTAL, config-gated, never auto-deployed. |

## 3. Wazuh (endpoint response) — no lab

| Capability | Status | Evidence / detail |
|---|---|---|
| CONNECTIVITY | **NOT VALIDATED (RESOURCE BLOCKED)** | Manager API (`:55000`) + a registered throwaway agent is the minimal path; the official single-node stack (manager + indexer + dashboard) needs ≥4 GB. Image acquisition (`wazuh/wazuh-manager:4.10.2`) was started twice in this round — interrupted by the host reboot, not completed within the resource window. |
| AUTH | **SOURCE-CERTIFIED** | Basic user/password → Authorization header via the secret boundary; not lab-exercised. |
| WRITE | **NOT VALIDATED** | Active-response command contract frozen (`quarantine-host` / `disable-account` / `block-source-ip`); requires manager + agent + a custom benign command to test for real. |
| RESOURCE REFERENCE | **SOURCE-CERTIFIED** | `command_id` semantics recorded from the frozen contract; live shape unverified. |
| READ | **NOT IN SCOPE** | No Wazuh reader exists; read registry stays EMPTY (fail-closed). |
| CORRELATION | **SOURCE-CERTIFIED** | Command id correlation; live command-effect correlation would be the real-lab acceptance. |
| OUTCOME PROOF | **BLOCKED (VOCABULARY EMPTY, G1-C FROZEN)** | All inbound outcome words stay EMPTY; `completed`/`agent_status`/`success` mappings must NOT be restored without exact-version official + source + real command-effect evidence. |
| RETRY BEHAVIOUR | **PASS (frozen)** | Zero automatic retry (E5). |
| IDEMPOTENCY | **SOURCE-CERTIFIED** | 409 ⇒ idempotency hit (`succeeded`); not lab-exercised. |
| LAB | **RESOURCE BLOCKED** | Minimum recommended: ≥2 GB free for manager + agent (tuned heaps) plus custom active-response provisioning; sequenced AFTER TheHive per §8.1 — not reached in the available window. |
| PRODUCTION | **NOT CERTIFIED** | LAB / EXPERIMENTAL, config-gated. |

---

## 4. Reading this matrix

- No single PASS covers an adapter: connectivity, auth, write, read,
  correlation and outcome proof are separate facts and fail separately.
- `RESOURCE BLOCKED` is an honest verdict, not a failure of the adapter —
  the code-level certification stands where marked, and the missing runtime
  evidence is never substituted with mocks or stubs.
- Gate 5 (VERIFIED EXTERNAL OUTCOME) is blocked for TheHive today and is an
  open, version-independent design question; the `UNKNOWN`/zero-fact
  behaviour is the correct fail-closed state.
