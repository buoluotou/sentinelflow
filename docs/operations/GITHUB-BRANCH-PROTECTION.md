# GitHub branch protection for `main`

**Status: plan only. None of these settings are applied.** Remote GitHub
mutation is not authorized yet, so apply them by hand (or with a reviewed
Terraform/GitHub App change) once the change is approved.

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
| Require a pull request before merging | ON, ≥ 1 approval | every change reviewed |
| Dismiss stale approvals on new commits | ON | re-review after edits |
| Require review from Code Owners | ON (if a CODEOWNERS file is added) | ownership on security-sensitive paths |
| Require status checks to pass | ON — the checks listed in section 4 | nothing merges while CI is red |
| Require branches to be up to date before merging | ON | avoids untested merge combinations |
| Require conversation resolution | ON | reviewers can block on open threads |
| Require signed commits | Optional (recommended if the org uses signing) | provenance |
| Require linear history | ON (recommended; commits are forward-only) | auditable history |
| Allow force pushes | OFF | never rewrite shared history |
| Allow deletions | OFF | `main` is permanent |
| Lock branch | OFF (admins may still need an emergency merge through a PR) | keep the escape hatch auditable |
| Restrict who can push | maintainers only, through a PR | least privilege |

## 3. Recommended rulesets for tags (`v*`)

| Setting | Value |
|---|---|
| Restrict creation of tags matching `v*` | maintainers only |
| Restrict updating/deleting matching tags | ON — nobody (tags are immutable release facts) |
| Require the tag commit to be on `main` and CI-green | operational rule, not enforceable directly — keep it in the release checklist |

## 4. Required checks on `main`

GitHub maps a required check to a job by the job's `name:` value, so these
strings must match `.github/workflows/ci.yml` character for character. These
are the jobs the workflow defines today:

```
Backend — exact dev lock + default pytest suite
Frontend — npm ci + typecheck + tests + production build
Quality — whitespace, shell syntax, compose config
Migration — fresh PostgreSQL 16, upgrade head, current == heads
Docker — build backend + frontend images
PostgreSQL external durable suite
Security — pip-audit + npm audit + secret scan
Docker Compose demo stack — ordered boot + real end-to-end smoke (PostgreSQL)
Browser E2E — PostgreSQL + Playwright
```

The list grows with the workflow. Whenever a job is added to
`.github/workflows/ci.yml`, add its `name:` value here in the same change;
a job that is not listed does not gate merges, so a new check can go red while
`main` still merges. The `Docker` job is optional as a required check (it is
slow) and is worth requiring at least on release branches.

The `Security` job must not be allowed to skip silently: `pip-audit` runs against
`base.lock` as a real gate, `npm audit` fails on HIGH and CRITICAL findings
(MEDIUM and LOW are reported only), and the secret scan fails on a tracked `.env`
or on an unallowlisted credential pattern.

## 5. Release discipline (tagging)

1. Merge every change to `main` through a PR with green checks.
2. Move `[Unreleased]` in `CHANGELOG.md` into the new version section in a PR.
3. Tag the merged commit: `git tag -a vX.Y.Z -m "..."` — annotated tag.
4. Push the tag (`git push origin vX.Y.Z`); never move or delete it.
5. Create the GitHub Release from the tag with the changelog entry as notes.
6. Production deployments build from the tag, never from a moving branch.

## 6. What is not applied

- No branch protection was enabled or changed on GitHub.
- No tag or release was created.
- No remote history was rewritten; the commits so far are local, forward-only
  and still waiting on review.
