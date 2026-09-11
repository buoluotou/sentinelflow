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

## Policy going forward

1. CI (`.github/workflows/ci.yml`, `security` job) reruns `pip-audit` on the
   base lock and `npm audit` on every push/PR. `npm audit` fails the job on
   **critical** only; `pip-audit` is report-first today — triage below decides
   when it should be flipped to fail-closed.
2. Any upgrade must be a deliberate, reviewed change with a full re-test
   (backend suite + frontend suite + the PostgreSQL external suite), never a
   silent range bump.
3. The `[Unreleased]` dependency wording rule stands: `base.lock` is **exact
   version pins**, not pip `--hash` verification; lockfile artifact SHA-256 is
   recorded separately (see `docs/operations/BACKUP-RESTORE.md` §1 for the
   same distinction in backup context, and `CHANGELOG.md`).
4. External labs (TheHive/Shuffle/Wazuh) are NOT dependency inputs of this
   repository — nothing here pulls them in.
