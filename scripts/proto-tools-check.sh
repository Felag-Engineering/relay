#!/usr/bin/env bash
# Assert the proto codegen toolchain (protoc-gen-go, protoc-gen-go-grpc, buf) is at the
# versions the Makefile's `proto-tools` recipe pins, BEFORE any codegen runs.
#
# Why this exists (#710): `make proto-tools` installs into the shared $(go env GOPATH)/bin.
# Parallel dev-loop runners in separate worktrees share that directory, so one runner's
# `make proto-tools` at a different pin makes a SIBLING runner's proto-drift gate report
# drift in relay/internal/relay/v1/*.pb.go whose entire content is the generator stamp
# (`protoc-gen-go v1.36.12` -> `v1.36.10`) — a confusing failure that touches no file under
# proto/ and has cost a full `make verify` four times in one week (#672, #617, #607, #638).
# This turns that spurious diff into a named instruction before codegen ever runs.
#
# ONE COPY OF THE PINS: they live only as the `go install <module>@<version>` lines in the
# Makefile's `proto-tools` recipe. This script PARSES those lines rather than restating them
# — a second copy of a version number is the exact bug class #710 exists to kill. The Makefile
# comment above `proto-tools` names the other two consumers of that same line shape (ci.yml's
# tool-cache key, and this script), so a reshape of the recipe is a three-way coordinated edit.
#
# buf is asserted too, not just the two codegen plugins — a deliberate behaviour change (see
# the PR that introduced this script for the full argument). buf's own version is not recorded
# anywhere in the generated code (protoc-gen-go and protoc-gen-go-grpc stamp their versions;
# buf does not), so a wrong buf produces byte-identical output and no drift diff at all —
# nothing else in this repo can catch it. A buf installed from apt/brew/nix at a version other
# than the pin now fails here, with the fix (`make proto-tools`) named in the message.
#
# Resolution mirrors `make proto` exactly (Makefile: `PATH="$(go env GOPATH)/bin:$PATH" buf
# generate`): GOPATH/bin first, then the ambient PATH. This inspects the same binary that
# codegen is about to invoke, not merely "a" binary with the right name — a shadowing tool
# earlier on the ambient PATH would otherwise let a wrong version through unnoticed.
#
# Security notes, for the reviewer: the parsed module@version strings are used only for
# string comparison and message text — never executed, never passed to `go install`. This
# script installs nothing and fetches nothing; self-healing (auto-running `make proto-tools`)
# was rejected on purpose — a network side effect inside a verify gate, and two parallel
# runners fighting over one shared bin. The only binaries it executes are the ones `make proto`
# was about to execute anyway, and only with `--version`. No new trust is introduced, and
# every new exit path here is a FAILURE, never a pass.
#
# NOT `set -e`: every tool must be reported in one run, like security-surface-test.sh:13.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

# --- a. Resolve the toolchain paths, exactly as `make proto` does.
gopath=$(go env GOPATH 2>/dev/null)
if [ -z "$gopath" ]; then
  echo "proto-tools-check: cannot run 'go env GOPATH' — is the Go toolchain on PATH?" >&2
  exit 1
fi
# GOBIN may legitimately be empty; `go install` falls back to $(go env GOPATH)/bin then.
gobin=$(go env GOBIN 2>/dev/null)
export PATH="$gopath/bin:$PATH"

# --- b. Parse the `proto-tools` recipe with one pass that classifies EVERY line, emitting
# `PIN <module@version>` or `UNPARSED <line>`. The `/^\t/` pattern test is load-bearing and
# deliberately kept separate from the field test below it: awk's default field splitter
# strips the leading tab before $1 is ever built, so testing $1=="go" alone would not prove
# the line was indented at all.
pins=()
unparsed=()
while IFS= read -r rec; do
  case "$rec" in
    "PIN "*) pins+=("${rec#PIN }") ;;
    "UNPARSED "*) unparsed+=("${rec#UNPARSED }") ;;
  esac
done < <(awk '
  /^proto-tools:/ { on = 1; next }
  on && /^\t/ {
    stripped = $0
    sub(/^\t[ \t]*/, "", stripped)
    sub(/[ \t]+$/, "", stripped)
    if (stripped == "" || stripped ~ /^#/) next
    n = split(stripped, f, /[ \t]+/)
    if (n == 3 && f[1] == "go" && f[2] == "install" && f[3] ~ /@/ && f[3] !~ /[ \t]/) {
      print "PIN " f[3]
    } else {
      print "UNPARSED " stripped
    }
    next
  }
  on && /^[ \t]*$/ { next }
  on { exit }
' Makefile)

# --- c. Non-vacuity guard, TOTAL over the proto-tools recipe body — not merely anti-zero. A
# recipe reshape that leaves two of three lines parseable would pass an anti-zero guard while
# vouching for less than the reader believes; naming the unparsed line and refusing is the only
# answer that cannot go quiet. This totality stops at the recipe body: a pin moved into a
# prerequisite target, or deleted outright, is out of scope for this awk and is caught instead
# by the three-way-edit rule in the Makefile comment above the proto-tools pins. Both paths
# exit before any version is compared, so a parse problem can never be reported as a version
# verdict.
if [ "${#unparsed[@]}" -gt 0 ]; then
  for line in "${unparsed[@]}"; do
    echo "proto-tools-check: proto-tools recipe line the check cannot parse: $line" >&2
  done
  echo "proto-tools-check: the check can only vouch for the 'go install <module>@<version>' lines it parsed — update scripts/proto-tools-check.sh with the recipe" >&2
  exit 1
fi
if [ "${#pins[@]}" -eq 0 ]; then
  echo "proto-tools-check: parsed no 'go install <module>@<version>' lines from the proto-tools recipe — the check can vouch for nothing" >&2
  exit 1
fi

# --- d. For each pin, accumulate failures — no early exit, so a runner several plugins
# behind hears about all of them in one run.
fail=0
for spec in "${pins[@]}"; do
  version=${spec##*@}
  module=${spec%@*}
  bin=${module##*/}

  path=$(command -v "$bin" 2>/dev/null)
  case "$path" in
    /*) ;;
    *)
      # Not found, empty, or a bare word (a shell builtin/function `command -v` can return
      # for) are all "not installed" — never "the right version" (constraint 3), and the
      # message below promises a path, so it must never print something that isn't one.
      echo "proto-tools-check: $bin is not installed (looked in $gopath/bin, then PATH)" >&2
      fail=1
      continue
      ;;
  esac

  out=$("$path" --version 2>&1 </dev/null)
  rc=$?
  if [ "$rc" -ne 0 ] || [ -z "$out" ]; then
    echo "proto-tools-check: $bin ($path) could not report a version: $out" >&2
    fail=1
    continue
  fi

  # The three shipped --version shapes differ ("protoc-gen-go v<N>", "protoc-gen-go-grpc <N>",
  # "<N>"). All three reduce the same way: first line, last whitespace-separated field, strip
  # one leading 'v'. The pin gets the identical normalisation.
  installed=$(printf '%s\n' "$out" | head -n1 | awk '{print $NF}')
  installed=${installed#v}
  pin=${version#v}

  if [ "$installed" != "$pin" ]; then
    echo "proto-tools-check: $bin is v$installed, the pin is $version" >&2
    echo "proto-tools-check:   $path" >&2
    if [ "$bin" = "buf" ]; then
      echo "proto-tools-check:   buf's version is not recorded in the generated code, so a" >&2
      echo "proto-tools-check:   mismatch here shows up as no drift at all — it changes what 'buf lint' and" >&2
      echo "proto-tools-check:   'buf breaking' accept. 'make proto-tools' installs the pinned buf into" >&2
      echo "proto-tools-check:   $gopath/bin, which the proto targets resolve first." >&2
    fi
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "proto-tools-check: run 'make proto-tools' and try again." >&2
  if [ -n "$gobin" ] && [ "$gobin" != "$gopath/bin" ]; then
    echo "proto-tools-check:   note: your GOBIN is $gobin, so 'go install' writes there — the proto targets resolve $gopath/bin first." >&2
  fi
  exit 1
fi

# Silent on success, like proto-check: a gate that chatters when it passes trains people to
# skim it.
exit 0
