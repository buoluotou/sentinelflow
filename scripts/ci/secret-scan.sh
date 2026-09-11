#!/usr/bin/env bash
# RC2-R §4.3 — high-confidence secret gate (real FAIL, precise allowlist).
#
# Previous behaviour printed SECRET_PATTERN_HITS_FOUND and stayed green — not
# acceptable. This gate exits 1 on ANY unallowlisted high-confidence hit.
#
# Design rules:
#   * high-confidence credential SHAPES only (a private-key header, a GitHub
#     token, an AWS key id, a Slack token, an OpenAI-style key, a long Bearer
#     credential) — low-signal words like the "wrong-token" test fixtures must
#     NOT trip the gate, so the scan stays honest instead of noisy;
#   * the allowlist is EXACT documented synthetic values (the AWS
#     documentation example key id used by the redaction tests), never a
#     whole-directory exclusion — a real private key committed under
#     backend/tests would still be caught;
#   * a tracked `.env` fails the gate outright.
#
# Usage:
#   bash scripts/ci/secret-scan.sh            # scan tracked files (CI checkout)
#   bash scripts/ci/secret-scan.sh --index    # scan the INDEX (local RED/GREEN
#                                             # validation before committing)
set -u

GREP_ARGS=()
if [ "${1:-}" = "--index" ]; then
  GREP_ARGS=(--cached)
fi

PATTERNS='(-----BEGIN (RSA|OPENSSH|EC|PGP) PRIVATE KEY-----|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{32,}|Bearer[[:space:]]+[A-Za-z0-9+/=_.-]{40,})'

# EXACT synthetic fixture values (documented, not directory-wide):
#   AKIAIOSFODNN7EXAMPLE — the official AWS documentation example key id,
#   used as a redaction/no-leak sentinel across the test suite.
ALLOWLIST='AKIAIOSFODNN7EXAMPLE'

echo "### 1) tracked .env inventory (must be empty)"
tracked_env="$(git ls-files | grep -E '(^|/)\.env$' || true)"
if [ -n "$tracked_env" ]; then
  echo "TRACKED_ENV_FOUND:"
  echo "$tracked_env"
  echo "SECRET_GATE=FAIL"
  exit 1
fi
echo "tracked .env: absent"

echo "### 2) high-confidence credential scan"
hits="$(git grep -nIE "${GREP_ARGS[@]}" -e "$PATTERNS" -- . ':(exclude)frontend/node_modules' 2>/dev/null | grep -vE "$ALLOWLIST" || true)"
if [ -n "$hits" ]; then
  echo "SECRET_PATTERN_HITS_FOUND (unallowlisted):"
  echo "$hits" | head -20
  echo "SECRET_GATE=FAIL"
  exit 1
fi

echo "SECRET_GATE=PASS (0 unallowlisted high-confidence hits)"
exit 0
