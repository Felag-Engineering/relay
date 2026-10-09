#!/usr/bin/env bash
# Proves every disallowed-methods entry in a read-only crate's clippy.toml fires
# (AGENTS.md invariants 1 and 2, #889).
#
# A typo'd path in clippy.toml is silently inert, so each read-only crate holds a
# ban_probe.rs, compiled only under its `ban-probe` feature, with one banned call
# per entry on a line ending in `// PROBE`. This lints the whole workspace with
# every crate's feature on and requires clippy's `disallowed_methods` diagnostics to
# land on EXACTLY those lines:
#   - a probe line with no diagnostic is an entry that does not fire;
#   - a diagnostic anywhere else is a banned call outside the probe.
# `-W` overrides the workspace `deny` for this one run, so the probe compiles and
# the rest of the graph is unaffected; the normal `make lint-daemon` builds without
# the feature and is the negative control. Any clippy config warning ("does not refer
# to a reachable function") also fails: it means a path did not resolve. With
# --message-format=json those warnings are compiler-message records on STDOUT, so
# that is where they are looked for (stderr is checked too).
#
# The whole workspace is linted at once, not `-p <crate>`: clippy resolves a path
# against the features the workspace unifies (tokio's `fs`, `process`), which a
# single-crate build does not have. An entry naming a crate that a read-only crate
# does not depend on (libc in relay-log, relay-proto and relay-exec; tokio in relay-log,
# relay-proto and relay-policy) is probed in a crate that has it: libc in relay-policy
# and relay-ops, tokio in relay-exec and relay-ops.
set -euo pipefail
cd "$(dirname "$0")/../daemon"

command -v jq >/dev/null || { echo "clippy-ban-probe: jq is required" >&2; exit 1; }

PROBE_CRATES=(relay-policy relay-log relay-proto relay-exec relay-ops)

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

features=$(printf '%s/ban-probe,' "${PROBE_CRATES[@]}")
features=${features%,}

if ! cargo clippy --workspace --lib --features "$features" --message-format=json \
  -- -W clippy::disallowed_methods >"$tmp/out.json" 2>"$tmp/err.txt"; then
  echo "clippy-ban-probe: FAIL: clippy exited non-zero" >&2
  jq -r 'select(.reason == "compiler-message") | .message.rendered' "$tmp/out.json" >&2 || true
  cat "$tmp/err.txt" >&2
  exit 1
fi

fail=0
jq -r 'select(.reason == "compiler-message") | .message
       | select((.message | test("does not refer to"))
                or any(.spans[]?; .file_name | endswith("clippy.toml")))
       | .rendered' "$tmp/out.json" >"$tmp/config-warnings.txt"
if [ -s "$tmp/config-warnings.txt" ]; then
  cat "$tmp/config-warnings.txt" >&2
  echo "clippy-ban-probe: FAIL: clippy reported a configuration warning (a clippy.toml path does not resolve)" >&2
  fail=1
fi
if grep -E 'clippy\.toml|does not refer to' "$tmp/err.txt" >&2; then
  echo "clippy-ban-probe: FAIL: clippy reported a configuration warning on stderr" >&2
  fail=1
fi

# The JSON path is crates/<c>/src/../ban_probe.rs; normalise it.
jq -r 'select(.reason == "compiler-message") | .message
       | select(.code.code == "clippy::disallowed_methods")
       | .spans[] | select(.is_primary) | "\(.file_name):\(.line_start)"' "$tmp/out.json" |
  while IFS=: read -r file line; do
    echo "$(realpath -m --relative-to="$PWD" "$file"):$line"
  done | sort -u >"$tmp/got.txt"

: >"$tmp/want.txt"
for c in "${PROBE_CRATES[@]}"; do
  probe="crates/$c/ban_probe.rs"
  n=$(grep -c '// PROBE$' "$probe" || true)
  if [ "$n" -eq 0 ]; then
    echo "clippy-ban-probe: FAIL $c: $probe has no // PROBE lines" >&2
    fail=1
  fi
  grep -n '// PROBE$' "$probe" | cut -d: -f1 | sed "s|^|$probe:|" >>"$tmp/want.txt" || true
done
sort -u -o "$tmp/want.txt" "$tmp/want.txt"

missing=$(comm -13 "$tmp/got.txt" "$tmp/want.txt")
extra=$(comm -23 "$tmp/got.txt" "$tmp/want.txt")
if [ -n "$missing" ]; then
  echo "clippy-ban-probe: FAIL: probe lines clippy did NOT flag (the ban entry does not fire):" >&2
  echo "$missing" >&2
  fail=1
fi
if [ -n "$extra" ]; then
  echo "clippy-ban-probe: FAIL: disallowed_methods hits outside the probe lines:" >&2
  echo "$extra" >&2
  fail=1
fi
if [ -z "$missing$extra" ] && [ "$fail" -eq 0 ]; then
  for c in "${PROBE_CRATES[@]}"; do
    echo "clippy-ban-probe: ok $c ($(grep -c "^crates/$c/" "$tmp/want.txt") entries fire)"
  done
fi
exit "$fail"
