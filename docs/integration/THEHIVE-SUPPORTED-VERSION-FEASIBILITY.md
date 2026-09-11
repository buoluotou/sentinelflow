# TheHive — Supported-Version (5.x) Feasibility Study (RC2 §8.5)

**Status: RESEARCH ONLY — no adapter rewrite, no migration performed.**
This document exists because the §8 real lab confirmed that TheHive 4.1.24-1
cannot satisfy Gate 5 (VERIFIED EXTERNAL OUTCOME) and because TheHive 3/4 are
officially **end of life**. It records what a move to the supported line
(TheHive 5.x) would require — and, importantly, what it would NOT fix.

## 1. Verified upstream facts (sources)

| Fact | Source |
|---|---|
| TheHive v3/v4 are **end of life**; `thehive4py` v1.x is unmaintained | Official `TheHive-Project/TheHive4py` README (2024+) |
| `thehive4py` v2.x is a **complete rewrite for TheHive 5**, not API-compatible with v1.x | same README |
| TheHive 5 auth: username/password **or API key** (`TheHiveApi(url=..., apikey=...)`) | thehive4py 2.x documentation |
| Alert creation de-duplicates on `(type, source, sourceRef)` — a certified idempotency key exists for ALERTS | thehive4py 2.x docs |
| TheHive 5 UI is React-based; profiles keep the admin / org-admin / analyst / read-only model | vendor material |
| TheHive 5 is the commercial supported line (StrangeBee); entitlement/licensing is a deployment-owner matter | vendor material — verify at procurement time |

**Not verified in this round:** exact 5.x version matrix, licence terms, API
DTOs against a running instance (no licensed 5.x instance was available; the
RC2 authorization forbids connecting to production systems).

## 2. What changing 4.1.24-1 → 5.x would touch (adapter-local)

| Area | TheHive 4.1.24-1 (frozen contract) | TheHive 5.x (to verify at spike time) | Impact |
|---|---|---|---|
| Create endpoint | `POST /api/case` (v0) | `POST /api/v1/case` | path constant |
| Read endpoint | `GET /api/case/{id}` (EntityIdOrName, `~` prefix) | `GET /api/v1/case/{id}` | path constant + id shape |
| Auth | `Authorization: Bearer <apikey>` | same header family (apikey auth documented) | none at the transport layer |
| Organisation context | from the principal's membership (observed in lab) | bound to the API key's organisation; platform-admin selectors to verify | verify per exact version |
| Create body | `title`, `description`, `severity:int(1-4)`, `tags:Set[String]` | same field names documented in client samples; additional fields exist (`tlp`, `pap`, `template`) | field-map review |
| Create response | `OutputCase{_id == id (string), caseId:int, ...}` | `_id` string + `caseId` int still present in client models | response parser review |
| Error envelope | `{"type": "...", "message": "..."}` | same shape observed in client error handling | none expected |
| Duplicate contract | none certified for cases (409 ⇒ fail-closed) | alerts have a certified key; **cases to verify** | keep fail-closed until certified |
| Severity scale | 1-4 (3 == High) | 1-4 documented | unchanged |
| Version gate | `THEHIVE_EXPECTED_VERSION == "4.1.24-1"` (reader) | new certified constant needed | config + tests |

The change is **adapter-local and moderate** (paths, DTO review, new version
constant, tests) — it is NOT a re-architecture. Per RC2 §8.5, no rewrite was
attempted: a rewrite without a licensed instance and runtime evidence would
repeat exactly the mistake the frozen process forbids.

## 3. What TheHive 5.x would NOT fix — Gate 5 (the decisive point)

Gate 5 asks the SYSTEM to prove, from authoritative facts, that the
**write-target namespace and the read-observed namespace are the same
authoritative identity domain** (instance/tenant). The 4.1.24-1 lab proved
the real failure mode: `observed_instance = observed_tenant = None` — the
OutputCase carries no such identity, and SentinelFlow refuses to fabricate one
(0 outcome facts, `UnrecognizedExternalState`).

Migrating to 5.x **does not automatically close this gap**: it must be shown,
per exact version, that (a) the create response or an authoritative
post-create read carries an instance/organisation identifier that the
platform can bind at dispatch time, and (b) that identifier is the SAME fact
observed by the trusted reader. Until that evidence exists, the verdict stays:

```
THEHIVE WRITE = PASS (adapter-local migration achievable)
THEHIVE VERIFIED EXTERNAL OUTCOME = BLOCKED BY GATE 5 (unchanged by the version bump)
```

## 4. Recommendation

1. **Do not rewrite the adapter now.** Keep the frozen 4.1.24-1 contract as
   the lab-certified compatibility target (isolated lab only; TheHive 4 is
   EOL and must never be recommended for production).
2. Schedule a time-boxed **TheHive 5.x spike** ONLY when a licensed instance
   (isolated, throwaway data) is available, with these acceptance questions:
   - exact version + image/source evidence;
   - create + read round trip with an execution-correlation tag;
   - an authoritative instance/tenant identifier present in BOTH the write
     binding and the read observation (Gate 5);
   - duplicate-creation behaviour (certify or keep fail-closed).
3. Treat any 5.x outcome as a **new evidence line** — it never retroactively
   upgrades this round's verdicts, and never becomes "production certified"
   without the same standard applied to the whole chain.

## 5. Bottom line

```
THEHIVE 4.1.24-1 = EOL / lab-only (this round: WRITE+READ PASS, Gate 5 blocked)
THEHIVE 5.x MIGRATION = FEASIBLE (adapter-local) / NOT ATTEMPTED (no licensed instance)
GATE 5 = OPEN DESIGN QUESTION, version-independent
```
