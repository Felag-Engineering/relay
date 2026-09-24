#!/usr/bin/env bash
# Proves scripts/proto-tools-check.sh sees what its header claims: a plugin at the wrong
# version, an absent plugin, and resolution that follows `make proto` (GOPATH/bin first, then
# the ambient PATH) rather than whatever happens to be first on the caller's own PATH — and
# that it refuses, loudly, rather than passing vacuously when the proto-tools recipe it parses
# has been reshaped out from under it (#710).
#
# Runs against a throwaway fixture repo built from the REAL check script and the REAL
# Makefile, so it proves the SHIPPED pairing, not a synthetic one. Hermetic: bash only, no Go
# toolchain, no network, no writes outside its own `mktemp -d`. A stub `go` stands in for the
# real one — the docs job this runs in has no `Set up Go` step, which is exactly why the stub
# is load-bearing rather than a convenience.
#
# PINS ARE NEVER WRITTEN HERE. They are derived from the fixture Makefile by `derive_pin`, an
# expression independent of the check's own awk parser, so a bug in that parser cannot be
# mirrored into this test's oracle. A second literal copy of a version number is the exact bug
# class #710 exists to kill, and that includes this file.
#
# NOT `set -e`: every case must run and be reported, not stop at the first failure
# (security-surface-test.sh:13).
set -uo pipefail

# --- Safety preamble, the same idiom as security-surface-test.sh:15-34: this file's only
# destructive operation is the trap's `rm -rf "$WORKDIR"`. With -e off, a failed mktemp would
# otherwise leave WORKDIR empty-and-set — `rm -rf ""` is just a harmless "cannot remove ''"
# error, not a cwd deletion, but the trap's own guard refuses to `rm -rf` anything but an
# absolute path regardless. The trap is installed the instant mktemp succeeds, and $FIX is
# only ever derived from $WORKDIR below — never from an argument or the environment — so
# nothing here can point the cleanup at this checkout.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
WORKDIR="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORKDIR:-}" in /*) rm -rf "$WORKDIR" ;; esac' EXIT
case "$WORKDIR" in
  /*) ;;
  *) echo "FAIL: mktemp returned a non-absolute path: '$WORKDIR'" >&2; exit 1 ;;
esac
FIX="$WORKDIR/repo"

fail=0

# --- Fixture: the real check script and the real Makefile. A synthetic Makefile for cases
# 1-5 would prove the harness works while proving nothing about the shipped recipe; only
# cases 6 and 7, which exist to test a RESHAPED recipe, get purpose-built minimal ones.
mkdir -p "$FIX/scripts"
cp "$REPO_ROOT/scripts/proto-tools-check.sh" "$FIX/scripts/proto-tools-check.sh"
cp "$REPO_ROOT/Makefile" "$FIX/Makefile"
chmod +x "$FIX/scripts/proto-tools-check.sh"
SCRIPT="$FIX/scripts/proto-tools-check.sh"

# --- Stub `go`. Answers `env GOPATH` with the per-case root (via $STUB_GOPATH, set by each
# case before invoking the check) and `env GOBIN` with an empty line; exits 1 on anything
# else. This is what makes the suite need no real Go toolchain and immune to the host's real
# $GOPATH/bin in both directions — the check never sees the real one.
mkdir -p "$WORKDIR/stub"
cat > "$WORKDIR/stub/go" <<'STUB'
#!/usr/bin/env bash
case "${1:-} ${2:-}" in
  "env GOPATH") printf '%s\n' "${STUB_GOPATH:?STUB_GOPATH not set}" ;;
  "env GOBIN") printf '\n' ;;
  *) exit 1 ;;
esac
STUB
chmod +x "$WORKDIR/stub/go"

# --- Stub tool generator. Only the --version SHAPE is a literal, captured from the real
# binaries on 2026-09-24 (the codex-review-test.sh "recorded real capture" idiom); the
# VERSION is always a caller-supplied argument, so a pin bump needs no edit here.
write_stub() {
  local path=$1 bin=$2 ver=$3 line
  case "$bin" in
    protoc-gen-go)      line="protoc-gen-go v$ver" ;;
    protoc-gen-go-grpc) line="protoc-gen-go-grpc $ver" ;;
    buf)                line="$ver" ;;
    *) echo "FAIL: write_stub: unknown bin '$bin'" >&2; exit 1 ;;
  esac
  cat > "$path" <<STUB
#!/usr/bin/env bash
# Stub $bin --version, shape recorded from the real binary 2026-09-24 (#710).
case "\${1:-}" in
  --version) echo "$line" ;;
  *) exit 1 ;;
esac
STUB
  chmod +x "$path"
}

# --- Pins, derived from the FIXTURE Makefile by an expression INDEPENDENT of the check's own
# awk parser (a test that reuses the parser mirrors its bugs into the oracle). The `@` anchored
# immediately after the module path is what keeps the protoc-gen-go pattern from matching the
# protoc-gen-go-grpc line; escaping the dots keeps `.` from matching anything else.
derive_pin() {
  local esc
  esc=${1//./\\.}
  sed -n "s|^[[:space:]]*go install ${esc}@\([^[:space:]]*\)[[:space:]]*\$|\1|p" \
    "$FIX/Makefile" | head -n 1
}
PIN_GO=$(derive_pin 'google.golang.org/protobuf/cmd/protoc-gen-go')
PIN_GRPC=$(derive_pin 'google.golang.org/grpc/cmd/protoc-gen-go-grpc')
PIN_BUF=$(derive_pin 'github.com/bufbuild/buf/cmd/buf')

# --- Oracle guard, before case 1 runs. A silently-empty derived pin would make the stubs
# below echo an empty version and every case that follows would prove nothing.
n_derived=0
for v in "$PIN_GO" "$PIN_GRPC" "$PIN_BUF"; do
  [ -n "$v" ] && n_derived=$((n_derived + 1))
done
if [ "$n_derived" -ne 3 ]; then
  echo "FAIL: derived $n_derived of 3 pins from the fixture Makefile — the oracle would be vacuous" >&2
  exit 1
fi
# Case 2's deliberately-wrong version is a literal, not a pin — guard it so a future pin bump
# that happened to land on the same string can't turn case 2 vacuous without anyone noticing.
if [ "$PIN_GO" = "v1.36.10" ]; then
  echo "FAIL: case 2's wrong version equals the pin" >&2
  exit 1
fi
N_GO=${PIN_GO#v}
N_GRPC=${PIN_GRPC#v}
N_BUF=${PIN_BUF#v}

# --- Capture harness. Globals only: `local out=$(cmd)` sets $? from `local`, not the
# command run inside it — a documented pitfall (security-surface-test.sh:106-108) that would
# make every rc assertion below pass regardless of what the check actually did.
OUT=""
RC=0
ERRFILE="$WORKDIR/stderr"

# run_check <STUB_GOPATH value> <full PATH value>
run_check() {
  OUT="$(env STUB_GOPATH="$1" PATH="$2" "$SCRIPT" 2>"$ERRFILE")"
  RC=$?
}

assert_rc() {
  local name=$1 want=$2
  if [ "$RC" -ne "$want" ]; then
    echo "FAIL: $name: rc=$RC want=$want (stdout=[$OUT] stderr=[$(cat "$ERRFILE")])" >&2
    fail=$((fail + 1))
  fi
}

assert_stdout_empty() {
  local name=$1
  if [ -n "$OUT" ]; then
    echo "FAIL: $name: stdout not empty: [$OUT]" >&2
    fail=$((fail + 1))
  fi
}

assert_stderr_empty() {
  local name=$1 err
  err=$(cat "$ERRFILE")
  if [ -n "$err" ]; then
    echo "FAIL: $name: stderr not empty: [$err]" >&2
    fail=$((fail + 1))
  fi
}

assert_contains() {
  local name=$1 needle=$2 err
  err=$(cat "$ERRFILE")
  case "$err" in
    *"$needle"*) ;;
    *) echo "FAIL: $name: stderr=[$err] does not contain [$needle]" >&2; fail=$((fail + 1)) ;;
  esac
}

assert_not_contains() {
  local name=$1 needle=$2 err
  err=$(cat "$ERRFILE")
  case "$err" in
    *"$needle"*) echo "FAIL: $name: stderr=[$err] unexpectedly contains [$needle]" >&2; fail=$((fail + 1)) ;;
    *) ;;
  esac
}

# Each case runs the fixture script with PATH SET (not prepended) to a value built entirely
# from $WORKDIR, so the real ~/go/bin is unreachable from the test in either direction.
BASE_PATH="$WORKDIR/stub:/usr/bin:/bin"

# --- Cases ---

# 1: all three stubs at the derived pins -> exit 0, no output. Also proves the check's own
# parse finds all three real `go install` lines in the shipped recipe (the fixture Makefile
# has not been touched yet).
GOPATH1="$WORKDIR/case1/gopath"
mkdir -p "$GOPATH1/bin"
write_stub "$GOPATH1/bin/protoc-gen-go" protoc-gen-go "$N_GO"
write_stub "$GOPATH1/bin/protoc-gen-go-grpc" protoc-gen-go-grpc "$N_GRPC"
write_stub "$GOPATH1/bin/buf" buf "$N_BUF"
run_check "$GOPATH1" "$BASE_PATH"
assert_rc "case1-all-pinned" 0
assert_stdout_empty "case1-all-pinned"
assert_stderr_empty "case1-all-pinned"

# 2: protoc-gen-go reports the issue's exact wrong version -> exit 1; message names the
# installed version, the DERIVED pin, the resolved path, and the fix.
GOPATH2="$WORKDIR/case2/gopath"
mkdir -p "$GOPATH2/bin"
write_stub "$GOPATH2/bin/protoc-gen-go" protoc-gen-go "1.36.10"
write_stub "$GOPATH2/bin/protoc-gen-go-grpc" protoc-gen-go-grpc "$N_GRPC"
write_stub "$GOPATH2/bin/buf" buf "$N_BUF"
run_check "$GOPATH2" "$BASE_PATH"
assert_rc "case2-wrong-version" 1
assert_contains "case2-wrong-version" "1.36.10"
assert_contains "case2-wrong-version" "$PIN_GO"
assert_contains "case2-wrong-version" "$GOPATH2/bin/protoc-gen-go"
assert_contains "case2-wrong-version" "make proto-tools"

# 3: protoc-gen-go absent, the other two at the pins -> exit 1, "not installed". Proves
# constraint 3: absent is never "the right version".
GOPATH3="$WORKDIR/case3/gopath"
mkdir -p "$GOPATH3/bin"
write_stub "$GOPATH3/bin/protoc-gen-go-grpc" protoc-gen-go-grpc "$N_GRPC"
write_stub "$GOPATH3/bin/buf" buf "$N_BUF"
run_check "$GOPATH3" "$BASE_PATH"
assert_rc "case3-plugin-absent" 1
assert_contains "case3-plugin-absent" "not installed"

# 4: all three at wrong versions -> exit 1 and all three named in one run (no early exit).
# Also the case that proves the buf assertion fires at all.
WRONG4="0.0.1"
GOPATH4="$WORKDIR/case4/gopath"
mkdir -p "$GOPATH4/bin"
write_stub "$GOPATH4/bin/protoc-gen-go" protoc-gen-go "$WRONG4"
write_stub "$GOPATH4/bin/protoc-gen-go-grpc" protoc-gen-go-grpc "$WRONG4"
write_stub "$GOPATH4/bin/buf" buf "$WRONG4"
run_check "$GOPATH4" "$BASE_PATH"
assert_rc "case4-all-wrong" 1
assert_contains "case4-all-wrong" "protoc-gen-go is v$WRONG4"
assert_contains "case4-all-wrong" "protoc-gen-go-grpc is v$WRONG4"
assert_contains "case4-all-wrong" "buf is v$WRONG4"

# 5a: correct stub in $GOPATH/bin, a WRONG stub earlier on the ambient PATH -> must PASS.
GOPATH5A="$WORKDIR/case5a/gopath"
AMBIENT5A="$WORKDIR/case5a/ambient"
mkdir -p "$GOPATH5A/bin" "$AMBIENT5A"
write_stub "$GOPATH5A/bin/protoc-gen-go" protoc-gen-go "$N_GO"
write_stub "$GOPATH5A/bin/protoc-gen-go-grpc" protoc-gen-go-grpc "$N_GRPC"
write_stub "$GOPATH5A/bin/buf" buf "$N_BUF"
write_stub "$AMBIENT5A/protoc-gen-go" protoc-gen-go "$WRONG4"
run_check "$GOPATH5A" "$WORKDIR/stub:$AMBIENT5A:/usr/bin:/bin"
assert_rc "case5a-gopath-wins" 0
assert_stderr_empty "case5a-gopath-wins"

# 5b: correct stub on the ambient PATH, a WRONG stub in $GOPATH/bin -> must FAIL. This is the
# case that makes the check not theatre: it only fails if the check looked where `make proto`
# looks, not merely wherever happened to be first on the caller's own PATH.
GOPATH5B="$WORKDIR/case5b/gopath"
AMBIENT5B="$WORKDIR/case5b/ambient"
mkdir -p "$GOPATH5B/bin" "$AMBIENT5B"
write_stub "$GOPATH5B/bin/protoc-gen-go" protoc-gen-go "$WRONG4"
write_stub "$GOPATH5B/bin/protoc-gen-go-grpc" protoc-gen-go-grpc "$N_GRPC"
write_stub "$GOPATH5B/bin/buf" buf "$N_BUF"
write_stub "$AMBIENT5B/protoc-gen-go" protoc-gen-go "$N_GO"
run_check "$GOPATH5B" "$WORKDIR/stub:$AMBIENT5B:/usr/bin:/bin"
assert_rc "case5b-gopath-first" 1
assert_contains "case5b-gopath-first" "protoc-gen-go is v$WRONG4"
assert_contains "case5b-gopath-first" "$GOPATH5B/bin/protoc-gen-go"

# 6: a reshaped `proto-tools` recipe with NO `go install` lines -> exit 1 with the "parsed
# no ..." message, and no version verdict printed. Total vacuity. The recipe's only content is
# a comment, which the parser skips rather than reports as unparseable — this must fail as
# "found nothing", not as "found a line it couldn't read" (that is case 7).
printf 'proto-tools:\n\t# nothing pinned here anymore\n' > "$FIX/Makefile"
GOPATH6="$WORKDIR/case6/gopath"
run_check "$GOPATH6" "$BASE_PATH"
assert_rc "case6-no-pins" 1
assert_contains "case6-no-pins" "parsed no"
assert_not_contains "case6-no-pins" "the pin is"

# 7: a reshaped recipe with ONE valid `go install` line and one tab-indented line the check
# cannot parse -> exit 1, the offending line quoted, and no version verdict printed. Partial
# vacuity — the reshape that would otherwise silently narrow what the check vouches for.
printf 'proto-tools:\n\tgo install google.golang.org/protobuf/cmd/protoc-gen-go@%s\n\t@echo installing proto tools\n' \
  "$PIN_GO" > "$FIX/Makefile"
GOPATH7="$WORKDIR/case7/gopath"
run_check "$GOPATH7" "$BASE_PATH"
assert_rc "case7-partial-vacuity" 1
assert_contains "case7-partial-vacuity" "@echo installing proto tools"
assert_not_contains "case7-partial-vacuity" "the pin is"

# 8: the three real pin lines, each carrying trailing whitespace -> exit 0, silent. Proves the
# `sub(/[ \t]+$/, "", stripped)` strip in the recipe-parsing awk: without it, a good pin line
# with trailing whitespace is misreported as unparseable even though CI's own tool-cache-key
# grep still matches it.
printf 'proto-tools:\n\tgo install google.golang.org/protobuf/cmd/protoc-gen-go@%s   \n\tgo install google.golang.org/grpc/cmd/protoc-gen-go-grpc@%s   \n\tgo install github.com/bufbuild/buf/cmd/buf@%s   \n' \
  "$PIN_GO" "$PIN_GRPC" "$PIN_BUF" > "$FIX/Makefile"
GOPATH8="$WORKDIR/case8/gopath"
mkdir -p "$GOPATH8/bin"
write_stub "$GOPATH8/bin/protoc-gen-go" protoc-gen-go "$N_GO"
write_stub "$GOPATH8/bin/protoc-gen-go-grpc" protoc-gen-go-grpc "$N_GRPC"
write_stub "$GOPATH8/bin/buf" buf "$N_BUF"
run_check "$GOPATH8" "$BASE_PATH"
assert_rc "case8-trailing-whitespace" 0
assert_stdout_empty "case8-trailing-whitespace"
assert_stderr_empty "case8-trailing-whitespace"

if [ "$fail" -ne 0 ]; then
  echo "FAIL: $fail case(s) failed" >&2
  exit 1
fi

echo "PASS: proto-tools-check.sh fires on a wrong version and on an absent plugin, resolves the same binary 'make proto' would invoke (GOPATH/bin first), refuses rather than passing when the proto-tools recipe parses to zero pins or to a line it cannot read, and still passes a good pin line that merely carries trailing whitespace (#710)."
