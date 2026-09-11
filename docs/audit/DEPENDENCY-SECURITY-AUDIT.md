# Dependency Security Audit (RC2 §15)

**Executed 2026-09-11** against the exact repository locks. Tools: `pip-audit
2.10.1` (backend), `npm audit` (frontend). No package was upgraded — nothing
required it, and blind upgrades are out of policy.

## Results

| Scope | Input | Result |
|---|---|---|
| Backend runtime | `backend/requirements/base.lock` (exact pins) | **No known vulnerabilities found** (`rc=0`) |
| Backend dev/test | `backend/requirements/dev.lock` | **No known vulnerabilities found** |
| Frontend | `frontend/package-lock.json` (lockfileVersion 3) | **0 vulnerabilities** — `{info:0, low:0, moderate:0, high:0, critical:0}` |

Raw evidence: `rc2-evidence/09-dependency-audit.txt`.

## Before / after / reason

- **Before:** no changes were made in this round prior to the audit.
- **After:** identical lockfiles — `base.lock`, `dev.lock`, `package-lock.json`
  all unchanged (hashes recorded in `rc2-evidence/lockfile-sha256.txt`).
- **Reason:** zero advisories found at every severity; no compatibility-driven
  bumps were needed.

## Policy (RC2-R §4 — COMPUTED GATES, not reports)

1. **pip-audit is a REAL gate** (`.github/workflows/ci.yml`, `security` job):
   `pip-audit -r backend/requirements/base.lock` runs with NO `|| true` — any
   unallowlisted advisory FAILS the job. The lock is currently advisory-free.
   If an exception ever becomes necessary it must be an **explicit CVE
   allowlist entry** carrying (a) the CVE id, (b) the reason, and (c) an
   expiry/review date, recorded in this document; a blanket exit-code swallow
   is forbidden.
2. **npm audit policy: HIGH + CRITICAL block, MEDIUM/LOW report.** The CI job
   reads `npm audit --json` and exits 1 when `high > 0 || critical > 0`; the
   severity counts are printed and tracked here. Current state stays
   **0 blocking advisories** at every severity.
3. **Secret gate (RC2-R §4.3)**: `scripts/ci/secret-scan.sh` FAILS on any
   unallowlisted high-confidence hit (private-key header, `ghp_`/
   `github_pat_`, AWS `AKIA`, Slack `xox*`, OpenAI-style `sk-`, long Bearer
   credentials) and on a tracked `.env`. The only allowlist entry is the
   exact AWS documentation example value `AKIAIOSFODNN7EXAMPLE` (a redaction
   sentinel) — there is NO whole-directory exclusion, so a real key committed
   under `backend/tests` would still be caught. Validated RED/GREEN locally
   (synthetic `ghp_` fixture + staged `.env` → exit 1; cleanup → exit 0).
4. Any upgrade must be a deliberate, reviewed change with a full re-test
   (backend suite + frontend suite + the PostgreSQL external suite), never a
   silent range bump.
5. The dependency wording rule stands: `base.lock` is **exact version pins**,
   not pip `--hash` verification; lockfile artifact SHA-256 is recorded
   separately (`rc2-evidence/lockfile-sha256.txt`).
6. External labs (TheHive/Shuffle/Wazuh) are NOT dependency inputs of this
   repository — nothing here pulls them in.
