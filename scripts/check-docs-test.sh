#!/usr/bin/env bash
# Proves scripts/check-docs.sh's "every cited test exists" check (check 2) covers what its header
# claims: a Go Test/Benchmark/Fuzz name anywhere in a spec, and — in a "What proves each claim"
# row — a Rust test fn or a cargo-fuzz target. A cited name that does not exist fails; so does a
# Rust fn that exists but is not a test, and a test that exists only in build output under
# target/. Snake_case names outside proof rows (MCP tool names, refusal codes in prose) and
# single-word tokens inside them are not read as Rust citations.
#
# Runs the REAL check-docs.sh inside a throwaway fixture repo with its own docs/, relay/ and
# daemon/ trees, so it proves the shipped script against sources whose contents it controls.
# Hermetic: bash, grep, awk, find; no Go, no Rust, no network, no writes outside its own
# `mktemp -d`. The fixture spec is legacy (Status aspirational), which check 2 covers like every
# other spec and the migrated-shape checks (3a-3h) skip, so no other check can fire here.
#
# NOT `set -e`: every case must run and be reported, not stop at the first failure
# (security-surface-test.sh:13).
set -uo pipefail

# --- Safety preamble, the same idiom as security-surface-test.sh: the trap's `rm -rf` only
# ever targets an absolute $WORKDIR from mktemp, and $FIX is only ever derived from it.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
WORKDIR="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORKDIR:-}" in /*) rm -rf "$WORKDIR" ;; esac' EXIT
case "$WORKDIR" in
  /*) ;;
  *) echo "FAIL: mktemp returned a non-absolute path: '$WORKDIR'" >&2; exit 1 ;;
esac
FIX="$WORKDIR/repo"

fail=0

# --- Fixture repo: the real script, and sources whose test names the cases control.
mkdir -p "$FIX/scripts" "$FIX/docs/adr" "$FIX/docs/specs" "$FIX/relay/internal/thing" \
         "$FIX/daemon/src" "$FIX/daemon/tests" "$FIX/daemon/fuzz" "$FIX/daemon/target/debug/build"
cp "$REPO_ROOT/scripts/check-docs.sh" "$FIX/scripts/check-docs.sh"
chmod +x "$FIX/scripts/check-docs.sh"
echo "# ADR-0001: fixture" > "$FIX/docs/adr/0001-fixture.md"

cat > "$FIX/relay/internal/thing/thing_test.go" <<'GO'
package thing

import "testing"

func TestGoThing(t *testing.T) {}

func BenchmarkGoThing(b *testing.B) {}

func FuzzGoThing(f *testing.F) {}
GO

# Every test-declaration shape the daemon uses: #[test]; #[tokio::test] with arguments on an
# async fn; and attributes and a doc comment between the test attribute and the fn. Plus a
# helper fn that is NOT a test, which a proof row must not be able to cite.
cat > "$FIX/daemon/src/dispatch.rs" <<'RS'
pub fn helper_that_is_not_a_test() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_rust_test() {
        helper_that_is_not_a_test();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn async_rust_test() {}

    #[test]
    #[cfg(unix)]
    /// A doc comment between the attribute and the fn.
    fn rust_test_behind_attributes() {}
}
RS
cat > "$FIX/daemon/tests/e2e.rs" <<'RS'
#[test]
fn integration_rust_test() {}
RS
# Build output under target/ is not source: a test here must not satisfy a citation.
cat > "$FIX/daemon/target/debug/build/generated.rs" <<'RS'
#[test]
fn test_only_in_build_output() {}
RS
cat > "$FIX/daemon/fuzz/Cargo.toml" <<'TOML'
[package]
name = "fixture-fuzz"

[dependencies]
libfuzzer-sys = "0.4"

[[bin]]
name = "fuzz_decode_thing"
path = "fuzz_targets/fuzz_decode_thing.rs"
TOML

SPEC="$FIX/docs/specs/thing.md"

# write_spec [extra proof row ...] — a legacy spec whose proof table cites every name above
# that exists, then any extra rows the case adds. snake_case names that are NOT Rust citations
# sit outside the proof table (prose, the Performance table) and as single words inside it.
write_spec() {
  {
    cat <<'MD'
# Thing

**Status:** aspirational — a self-test fixture.

## Behaviour

An AI-agent calls `describe_node` and `run_operation`; a refusal reads `no_nodes_matched`.

## Seams and proof

### What proves each claim

| Claim | Proven by | Seam |
|---|---|---|
| Go | `TestGoThing`, `BenchmarkGoThing` | capability |
| Rust | `plain_rust_test`, `async_rust_test`, `rust_test_behind_attributes` | daemon |
| Rust, qualified | `dispatch::tests::plain_rust_test`, `integration_rust_test` | daemon |
| Fuzz | `fuzz_decode_thing`; Go `FuzzGoThing` | daemon, relay |
| Words | `admin`, `viewer`, `state:` | API |
MD
    for row in "$@"; do printf '%s\n' "$row"; done
    cat <<'MD'

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Scale | `list_nodes` stays correct | *(none)* |

## Out of scope

Nothing.
MD
  } > "$SPEC"
}

# --- Capture harness. Globals only: `local out=$(cmd)` sets $? from `local`, not the command
# run inside it (security-surface-test.sh:106-108).
OUT=""
RC=0
run_check() {
  OUT="$("$FIX/scripts/check-docs.sh" 2>&1)"
  RC=$?
}

assert_rc() {
  local name=$1 want=$2
  if [ "$RC" -ne "$want" ]; then
    echo "FAIL: $name: rc=$RC want=$want; output: [$OUT]" >&2
    fail=$((fail + 1))
  fi
}

assert_contains() {
  local name=$1 needle=$2
  case "$OUT" in
    *"$needle"*) ;;
    *) echo "FAIL: $name: output=[$OUT] does not contain [$needle]" >&2; fail=$((fail + 1)) ;;
  esac
}

assert_not_contains() {
  local name=$1 needle=$2
  case "$OUT" in
    *"$needle"*) echo "FAIL: $name: output=[$OUT] unexpectedly contains [$needle]" >&2; fail=$((fail + 1)) ;;
    *) ;;
  esac
}

# --- Cases ---

# 1: every cited name exists -> exit 0. Proves each test-declaration shape resolves, a path
# qualifier is dropped, a cargo-fuzz target resolves by its [[bin]] name, and no snake_case name
# outside the proof table (prose, Performance) or single word inside it is read as a citation.
write_spec
run_check
assert_rc "case1-all-exist" 0
assert_not_contains "case1-all-exist" "describe_node"
assert_not_contains "case1-all-exist" "list_nodes"

# 2: a proof row cites a Rust test that does not exist -> exit 1, named.
write_spec '| Gone | `rust_test_that_was_renamed` | daemon |'
run_check
assert_rc "case2-missing-rust-test" 1
assert_contains "case2-missing-rust-test" "cites rust_test_that_was_renamed"

# 3: a proof row cites a Rust fn that exists but is not a test -> exit 1. A helper is not evidence.
write_spec '| Helper | `helper_that_is_not_a_test` | daemon |'
run_check
assert_rc "case3-non-test-fn" 1
assert_contains "case3-non-test-fn" "cites helper_that_is_not_a_test"

# 4: a proof row cites a test that exists only in build output under target/ -> exit 1.
write_spec '| Built | `test_only_in_build_output` | daemon |'
run_check
assert_rc "case4-target-only" 1
assert_contains "case4-target-only" "cites test_only_in_build_output"

# 5: a proof row cites a cargo-fuzz target that does not exist -> exit 1.
write_spec '| Fuzz | `fuzz_decode_other_thing` | daemon |'
run_check
assert_rc "case5-missing-fuzz-target" 1
assert_contains "case5-missing-fuzz-target" "cites fuzz_decode_other_thing"

# 6: a path-qualified citation whose fn does not exist -> exit 1, named by its fn.
write_spec '| Qualified | `policy::tests::rust_test_that_was_renamed` | daemon |'
run_check
assert_rc "case6-missing-qualified" 1
assert_contains "case6-missing-qualified" "cites rust_test_that_was_renamed"

# 7: a Go fuzz target that does not exist -> exit 1, named.
write_spec '| Fuzz | `FuzzGoOtherThing` | relay |'
run_check
assert_rc "case7-missing-go-fuzz" 1
assert_contains "case7-missing-go-fuzz" "cites FuzzGoOtherThing"

# 8: the pre-existing Go Test check still fires -> exit 1, named.
write_spec '| Go | `TestGoOtherThing` | relay |'
run_check
assert_rc "case8-missing-go-test" 1
assert_contains "case8-missing-go-test" "cites TestGoOtherThing"

# 9: every missing name is reported in one run, not just the first.
write_spec '| Gone | `rust_test_that_was_renamed`, `fuzz_decode_other_thing`, `FuzzGoOtherThing` | daemon |'
run_check
assert_rc "case9-all-reported" 1
assert_contains "case9-all-reported" "cites rust_test_that_was_renamed"
assert_contains "case9-all-reported" "cites fuzz_decode_other_thing"
assert_contains "case9-all-reported" "cites FuzzGoOtherThing"

if [ "$fail" -ne 0 ]; then
  echo "FAIL: $fail assertion(s) failed" >&2
  exit 1
fi

echo "PASS: check-docs.sh fails a spec citing a Go Test/Benchmark/Fuzz name that does not exist, and a proof row citing a Rust test or cargo-fuzz target that does not exist, a Rust fn that is not a test, or a test only under target/; it reads every test-declaration shape the daemon uses, and never mistakes a snake_case name outside proof rows for a Rust citation."
