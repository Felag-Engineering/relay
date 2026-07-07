#!/usr/bin/env bash
# Mechanically proves the #112 dev-harness dispatch/control surface
# (relay/cmd/relay/devharness.go) is genuinely absent from the normal
# (untagged, shippable) relay binary, and genuinely present in the
# `devharness`-tagged one. This is a dev backdoor on an RCE control plane —
# its exclusion from production is asserted here, not by review.
#
# NOTE (plan-review BLOCKING-2): main.harnessSink is NOT checked. It is an
# unexported struct with a single interface implementation, so it gets
# devirtualized/inlined and never appears in `nm` in EITHER build — asserting
# on it would be vacuous and give false confidence. Instead:
#   (a) main.serveDevHarnessSocket — kept alive as a distinct symbol by
#       //go:noinline specifically so this check has something load-bearing
#       to grep for.
#   (b) the RELAY_DEVHARNESS_SOCKET string literal — referenced only inside
#       the gated file, so unlike a symbol it cannot be inlined away; an
#       independent second signal.
#
# Both the negative (untagged binary lacks them) and positive (tagged binary
# has them) checks run, so a rename/removal of the symbol or string can't
# silently make the negative check vacuous.
#
# Exits non-zero on any mismatch.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

SYMBOL="main.serveDevHarnessSocket"
STRING_LITERAL="RELAY_DEVHARNESS_SOCKET"

echo "Building the normal (untagged) relay binary..."
(cd "${REPO_ROOT}/relay" && go build -o "${WORKDIR}/relay" ./cmd/relay)

echo "Building the devharness-tagged relay binary..."
(cd "${REPO_ROOT}/relay" && go build -tags devharness -o "${WORKDIR}/relay-devharness" ./cmd/relay)

fail=0

# NOTE: nm/strings output is captured into a variable rather than piped
# straight into `grep -q` — under `set -o pipefail`, a `grep -q` that matches
# early closes its stdin, sending SIGPIPE to the writer (nm/strings), which
# then exits non-zero and makes the whole pipeline look like it failed even
# though the match was found. Capturing first avoids that false failure.
untagged_nm="$(go tool nm "${WORKDIR}/relay" 2>/dev/null || true)"
untagged_strings="$(strings "${WORKDIR}/relay")"
tagged_nm="$(go tool nm "${WORKDIR}/relay-devharness" 2>/dev/null || true)"
tagged_strings="$(strings "${WORKDIR}/relay-devharness")"

echo "Asserting the untagged binary does NOT contain symbol ${SYMBOL}..."
if grep -q "${SYMBOL}" <<<"${untagged_nm}"; then
    echo "FAIL: untagged relay binary contains ${SYMBOL} — the devharness surface leaked into production" >&2
    fail=1
fi

echo "Asserting the untagged binary does NOT contain string \"${STRING_LITERAL}\"..."
if grep -q "${STRING_LITERAL}" <<<"${untagged_strings}"; then
    echo "FAIL: untagged relay binary contains the string \"${STRING_LITERAL}\" — the devharness surface leaked into production" >&2
    fail=1
fi

echo "Asserting the devharness binary DOES contain symbol ${SYMBOL}..."
if ! grep -q "${SYMBOL}" <<<"${tagged_nm}"; then
    echo "FAIL: devharness relay binary is missing ${SYMBOL} — the negative check above would be vacuous" >&2
    fail=1
fi

echo "Asserting the devharness binary DOES contain string \"${STRING_LITERAL}\"..."
if ! grep -q "${STRING_LITERAL}" <<<"${tagged_strings}"; then
    echo "FAIL: devharness relay binary is missing the string \"${STRING_LITERAL}\" — the negative check above would be vacuous" >&2
    fail=1
fi

if [[ "${fail}" -ne 0 ]]; then
    exit 1
fi

echo "PASS: devharness surface is absent from the untagged binary and present in the tagged one."
