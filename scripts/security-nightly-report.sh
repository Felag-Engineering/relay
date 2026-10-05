#!/usr/bin/env bash
# scripts/security-nightly-report.sh
#
# Reads the captured govulncheck / cargo-audit / gitleaks outputs and exit codes, then
# creates or updates exactly one persistent tracking GitHub issue labelled
# "security-scan".  Always exits 0 so the scan job never fails on findings.
#
# Expects the following files in the working directory (written by the CI steps):
#   vuln-relay.rc   — exit code of `make vuln-relay`
#   vuln-relay.txt  — stdout+stderr of `make vuln-relay`
#   vuln-daemon.rc  — exit code of `make vuln-daemon`
#   vuln-daemon.txt — stdout+stderr of `make vuln-daemon`
#   secrets-history.rc  — exit code of `make secrets-scan-history`
#   secrets-history.txt — its output (gitleaks --redact: rule, file, commit; never a secret)
#
# Requires: gh CLI authenticated via GH_TOKEN env var.

set -euo pipefail

LABEL="security-scan"
TODAY="$(date -u +%Y-%m-%d)"

relay_rc="$(cat vuln-relay.rc 2>/dev/null || echo 1)"
daemon_rc="$(cat vuln-daemon.rc 2>/dev/null || echo 1)"
relay_out="$(cat vuln-relay.txt 2>/dev/null || echo '(no output)')"
daemon_out="$(cat vuln-daemon.txt 2>/dev/null || echo '(no output)')"
secrets_rc="$(cat secrets-history.rc 2>/dev/null || echo 1)"
secrets_out="$(cat secrets-history.txt 2>/dev/null || echo '(no output)')"

# Find the number of any open issue with the security-scan label.
open_issue="$(gh issue list --label "$LABEL" --state open --json number --jq '.[0].number // empty' 2>/dev/null || true)"

if [[ "$relay_rc" -eq 0 && "$daemon_rc" -eq 0 && "$secrets_rc" -eq 0 ]]; then
  # All scans clean.
  if [[ -n "$open_issue" ]]; then
    gh issue comment "$open_issue" \
      --body "**Security scan ${TODAY}: all clear.** Closing — no vulnerabilities found in Relay (govulncheck) or relay-daemon (cargo audit), and no secrets in the git history (gitleaks)."
    gh issue close "$open_issue"
    echo "Closed issue #${open_issue} (all scans clean)."
  else
    echo "All scans clean; no open tracking issue to close."
  fi
  exit 0
fi

# Build the findings body.
body="## Security scan findings — ${TODAY}

Automated nightly scan detected findings.  Address these before the next release.

### Relay — govulncheck

\`\`\`
${relay_out}
\`\`\`

Exit code: ${relay_rc}

### Daemon — cargo audit

\`\`\`
${daemon_out}
\`\`\`

Exit code: ${daemon_rc}

### Git history — gitleaks

A finding here is a credential in a commit every clone carries: rotate it first, then
decide whether the history needs rewriting.

\`\`\`
${secrets_out}
\`\`\`

Exit code: ${secrets_rc}

---
*Updated by the nightly [Security workflow](../../actions/workflows/security-nightly.yml).*"

if [[ -n "$open_issue" ]]; then
  # Update the existing issue body in place and add a dated comment.
  gh issue edit "$open_issue" --body "$body"
  gh issue comment "$open_issue" \
    --body "**Security scan ${TODAY}:** findings still present (relay rc=${relay_rc}, daemon rc=${daemon_rc}, secrets rc=${secrets_rc}).  See updated issue body."
  echo "Updated issue #${open_issue} with latest findings."
else
  # Ensure the label exists (idempotent).
  gh label create "$LABEL" --color "e4e669" --description "Nightly vulnerability scan findings" --force 2>/dev/null || true
  new_issue="$(gh issue create \
    --title "Security scan findings — ${TODAY}" \
    --label "$LABEL" \
    --body "$body")"
  echo "Created tracking issue: ${new_issue}"
fi

exit 0
