#!/usr/bin/env bash
# Comment hygiene for shipped code: no issue or PR numbers in comments. The commit message
# and the PR carry a change's history; a `#NNN` in a comment goes stale the day it lands
# and cannot be read without the tracker open. AGENTS.md "Code comments" is the policy.
#
# Checked: tracked non-test Go under relay/ (generated *.pb.go excluded), and tracked Rust
# under daemon/ outside tests/, benches/ and fuzz/, up to a file's first #[cfg(test)] or #![cfg(test)].
# Exempt: `Deprecated:` lines. Test files may cite the issue they regress.
#
# Exit 1 with file:line for each finding; exit 0 when clean.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

files() {
  git ls-files -- 'relay/*.go' | grep -v -e '_test\.go$' -e '\.pb\.go$' || true
  git ls-files -- 'daemon/*.rs' | grep -v -e '/tests/' -e '/benches/' -e '^daemon/fuzz/' || true
}

findings=$(files | while IFS= read -r f; do
  awk -v f="$f" '
    /^#!?\[cfg\(test\)\]/ && f ~ /\.rs$/ { exit }
    {
      line = $0
      i = index(line, "//")
      if (i == 0) next
      c = substr(line, i)
      if (c ~ /Deprecated:/) next
      if (c ~ /(^|[^A-Za-z0-9])#[0-9]/) printf "%s:%d: %s\n", f, NR, $0
    }
  ' "$f"
done)

if [ -n "$findings" ]; then
  printf '%s\n' "$findings"
  n=$(printf '%s\n' "$findings" | wc -l | tr -d ' ')
  echo "comment-hygiene: $n comment line(s) cite an issue or PR number." >&2
  echo "comment-hygiene: say why the code is so, citing an ADR or spec claim where one holds the reason (AGENTS.md, \"Code comments\")." >&2
  exit 1
fi
echo "comment-hygiene: ok"
