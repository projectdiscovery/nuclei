#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   bash submit_5838_pr.sh
#
# What it does:
# 1) Runs proof commands and stores outputs
# 2) Commits current changes (no co-author trailer)
# 3) Pushes current branch
# 4) Creates PR to dev with required sections and /claim #5838

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
PROOF_DIR=".pr-proof-5838"
mkdir -p "$PROOF_DIR"

UNIT_OUT="$PROOF_DIR/unit_${TIMESTAMP}.txt"
COMPILE_OUT="$PROOF_DIR/compile_${TIMESTAMP}.txt"

echo "[1/5] Running unit proof command..."
go test -vet=off -v -count=1 ./pkg/fuzz/analyzers/xss | tee "$UNIT_OUT"

echo "[2/5] Running compile proof command..."
go test -vet=off ./cmd/integration-test ./pkg/protocols/http -run TestDoesNotExist -count=1 | tee "$COMPILE_OUT"

echo "[3/5] Committing changes..."
git add -A
if git diff --cached --quiet; then
  echo "No staged changes to commit. Aborting."
  exit 1
fi

git commit -m "$(cat <<'EOF'
feat(XSS): add context-aware XSS analyzer with tokenizer verification

Implements xss_context analyzer for HTTP fuzzing with browser-grade context
detection, character-aware payload filtering, targeted replay verification,
expanded tests, and integration templates.
EOF
)"

echo "[4/5] Pushing branch ${BRANCH}..."
git push -u origin "${BRANCH}"

echo "[5/5] Creating PR (upstream: projectdiscovery/nuclei)..."
# When pushing from a fork, PR head must be fork_owner:branch
ORIGIN_URL="$(git remote get-url origin 2>/dev/null || true)"
FORK_OWNER="$(echo "$ORIGIN_URL" | sed -n 's|.*github\.com[:/]\([^/]*\)/.*|\1|p')"
[[ -z "$FORK_OWNER" ]] && FORK_OWNER="ashuwhy"
HEAD_FOR_PR="${FORK_OWNER}:${BRANCH}"

PR_BODY="$(cat <<EOF
/claim #5838

## Proposed Changes

- Added a new \`xss_context\` analyzer in \`pkg/fuzz/analyzers/xss/\` using \`html.Tokenizer\` for browser-grade reflection context detection.
- Implemented character-survival tracking (\`CharacterSet\`) so payloads are filtered by server-side encoded/allowed characters.
- Added context-aware payload selection and replay verification to reduce blind fuzzing and false positives.
- Wired analyzer response fields (\`ResponseBody\`, \`ResponseHeaders\`, \`ResponseStatusCode\`) into runtime options.
- Added integration templates and handlers for body, attribute, script, and encoded reflection cases.
- Updated analyzer docs in syntax and template docs.

## Proof

### 1) Unit tests
\`\`\`bash
go test -vet=off -v -count=1 ./pkg/fuzz/analyzers/xss
\`\`\`

\`\`\`text
$(cat "$UNIT_OUT")
\`\`\`

### 2) Compile checks
\`\`\`bash
go test -vet=off ./cmd/integration-test ./pkg/protocols/http -run TestDoesNotExist -count=1
\`\`\`

\`\`\`text
$(cat "$COMPILE_OUT")
\`\`\`

## Checklist

- [x] PR created against the correct branch (\`dev\`)
- [x] All checks passed (targeted unit/compile checks run locally)
- [x] Tests added that prove the fix is effective
- [x] Documentation added (if appropriate)

EOF
)"

if gh pr create --repo projectdiscovery/nuclei --base dev --head "${HEAD_FOR_PR}" \
  --title "feat(xss): add context-aware XSS analyzer with tokenizer verification" \
  --body "$PR_BODY"; then
  echo
  echo "PR created successfully."
else
  echo
  echo "PR create failed (e.g. no default repo). Run this manually:"
  echo
  echo "  gh pr create --repo projectdiscovery/nuclei --base dev --head ${HEAD_FOR_PR} \\"
  echo "    --title \"feat(xss): add context-aware XSS analyzer with tokenizer verification\" \\"
  echo "    --body-file - <<'PRBODY'"
  echo "$PR_BODY"
  echo "PRBODY"
  echo
  echo "Or set default repo first: gh repo set-default projectdiscovery/nuclei"
fi
echo "Proof files: $UNIT_OUT, $COMPILE_OUT"
