# GitHub Branch Protection Plan — main (RC2 §26)

**Status: PLAN ONLY. Nothing in this document was applied.** The RC2 authorization
explicitly forbids remote GitHub mutation in this round. Apply these settings by
hand (or with a reviewed Terraform/GitHub App change) after the final review.

## 1. Goal

Make `main` a reviewable, CI-gated, forward-only branch:

- no direct pushes to `main`;
- every change lands through a pull request;
- the CI workflow (`.github/workflows/ci.yml`) must pass before merge;
- force-pushes and branch deletion are blocked;
- conversations must be resolved before merge;
- releases are tagged only from reviewed `main` commits.

## 2. Recommended protection for `main`

| Setting | Value | Why |
|---|---|---|
| Require a pull request before merging | **ON**, ≥ 1 approval | every change reviewed |
| Dismiss stale approvals on new commits | ON | re-review after edits |
| Require review from Code Owners | ON (if a CODEOWNERS file is added) | ownership on security-sensitive paths |
| Require status checks to pass | ON — `Backend — exact dev lock + default pytest suite`, `Frontend — npm ci + typecheck + tests + production build`, `Quality — whitespace, shell syntax, compose config`, `Migration — fresh PostgreSQL 16, upgrade head, current == heads`, `PostgreSQL external durable suite`, `Security — pip-audit + npm audit + secret scan` | the CI jobs in this repository |
| Require branches to be up to date before merging | ON | avoids untested merge combinations |
| Require conversation resolution | ON | reviewers can block on open threads |
| Require signed commits | OPTIONAL (recommended if the org uses signing) | provenance |
| Require linear history | ON (recommended — the RC2 commit strategy is deliberately forward-only) | auditable history |
| Allow force pushes | **OFF** | never rewrite shared history |
| Allow deletions | **OFF** | `main` is permanent |
| Lock branch | OFF (admins may still need emergency merges via PR) | keep the escape hatch auditable |
| Restrict who can push | maintainers only, via PR | least privilege |

## 3. Recommended rulesets for tags (`v*`)

| Setting | Value |
|---|---|
| Restrict creation of tags matching `v*` | maintainers only |
| Restrict updating/deleting matching tags | **ON — nobody** (tags are immutable release facts) |
| Require the tag commit to be on `main` and CI-green | operational rule, not enforceable directly — keep it in the release checklist |

## 4. Required checks — exact job names

The check names must match the `name:` values in `.github/workflows/ci.yml`
exactly; GitHub maps required checks by name:

```
Backend — exact dev lock + default pytest suite
Frontend — npm ci + typecheck + tests + production build
Quality — whitespace, shell syntax, compose config
Migration — fresh PostgreSQL 16, upgrade head, current == heads
Docker — build backend + frontend images
PostgreSQL external durable suite
Security — pip-audit + npm audit + secret scan
```

> The `Docker` job is optional as a *required* check (it is slow); recommended
> at least on release branches. The `Security` job must not be allowed to
> silently skip: `pip-audit` is currently report-first, `npm audit` fails on
> **critical** only, and the secret scan fails on tracked `.env` / real
> credential patterns.

## 5. Release discipline (tagging)

1. Merge every change to `main` through a PR with green checks.
2. Move `[Unreleased]` in `CHANGELOG.md` into the new version section in a PR.
3. Tag the merged commit: `git tag -a vX.Y.Z -m "..."` — annotated tag.
4. Push the tag deliberately (`git push origin vX.Y.Z`); never move/delete it.
5. Create the GitHub Release from the tag with the changelog entry as notes.
6. Production deployments build from the tag, never from a moving branch.

## 6. What this round did NOT do

- No branch protection was enabled/changed on GitHub.
- No tag or release was created (RC2 §24/§25: **DO NOT CREATE TAG / RELEASE**).
- No remote history was rewritten; all RC2 commits are local forward commits
  pending the final review.
