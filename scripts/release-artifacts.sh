#!/usr/bin/env bash
# Stage, verify, name, and checksum the release artifacts for a v* tag
# (issue #250, closes #44; ADR-0007 static musl daemon, ADR-0014 IaC-pulled upgrades).
#
# This script does NOT build and does NOT publish. It takes the two binaries
# `make build-release` produced, refuses to let them through if anything about
# them is wrong, and lays them out in dist/ under the published naming
# convention with a SHA256SUMS beside them. The workflow
# (.github/workflows/release.yml) builds, then calls this, then — only if this
# exits 0 — runs `gh release create` over dist/.
#
# THE SPLIT MATTERS: every guard below is a plain shell assertion over local
# files, so the whole verification path is runnable (and is run) on a developer
# machine without GitHub Actions, a tag push, or a real Release. What cannot be
# rehearsed locally is the publish step itself. See docs/operations/release-artifacts.md.
#
# Usage:
#   scripts/release-artifacts.sh v0.0.9     # explicit argv
#   TAG=v0.0.9 scripts/release-artifacts.sh # how the Makefile passes it
#   scripts/release-artifacts.sh            # falls back to $GITHUB_REF_NAME
#
# The tag arrives as an argv element or an environment value, never as text
# interpolated into a shell command — see the Makefile's `export TAG`. A tag
# name may legally contain `;`, `&`, backticks and `$(...)`, so it is treated
# as untrusted data everywhere below.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

DIST="dist"
DAEMON_BIN="daemon/target/x86_64-unknown-linux-musl/release/relay-daemon"
RELAY_BIN="relay/bin/relay"

# Rust's own name for the daemon's build target and Go's own name for the
# Relay's. They are deliberately NOT unified into one invented platform token:
# each string is the exact identifier its toolchain was invoked with, so an
# operator can check the claim rather than trust it. See
# docs/operations/release-artifacts.md ("Naming and pinning").
DAEMON_PLATFORM="x86_64-unknown-linux-musl"
RELAY_PLATFORM="linux-amd64"

die() { echo "release-artifacts: $*" >&2; exit 1; }

tag="${1:-${TAG:-${GITHUB_REF_NAME:-}}}"
[ -n "$tag" ] || die "no tag given (pass one as \$1, or set TAG / GITHUB_REF_NAME)"

# --- guard 1: the tag is a release tag -------------------------------------
# `on.push.tags: v*` matches `vnext` and `v0.0.9.1` too. The version token is
# embedded in every artifact name and pinned by config management, so it has to
# be semver, not merely v-prefixed.
#
# This is a shape check, not a semver validator: it still admits oddities like
# `v01.0.0` and `v0.0.9-.`. That is fine — guard 3 rejects anything the stamp
# does not reproduce exactly, and the stamp comes from Cargo.toml, which cargo
# already requires to be real semver. What this guard is for is failing early
# and legibly on a tag that was never meant to be a release.
#
# It is NOT a sanitizer, and nothing downstream may rely on it as one. Safety
# comes from the tag never being shell text: it reaches this script as an argv
# element or an environment value (the Makefile's `export TAG`), and every use
# below is a quoted expansion, so it is never word-split, re-parsed, or
# substituted no matter what it contains.
if ! [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
  die "tag '$tag' is not a release tag (want v<major>.<minor>.<patch>[-prerelease])"
fi

# The version token in artifact names carries NO leading 'v': it is exactly
# what the binaries print for --version, so `relay-daemon --version` output can
# be compared to a pinned version string with no stripping on either side. The
# 'v' belongs to the git tag and to the release, not to the artifact.
version="${tag#v}"

# --- guard 2: both binaries exist ------------------------------------------
[ -f "$DAEMON_BIN" ] || die "missing $DAEMON_BIN — run 'make build-release' first"
[ -f "$RELAY_BIN" ]  || die "missing $RELAY_BIN — run 'make build-release' first"

# --- guard 3: the stamped version IS the tag -------------------------------
# The load-bearing assertion (issue #250, comments 1 and 2). Both binaries
# print "<name> <version> (commit <sha>, built <date>)"; field 2 is the stamp.
#
# Asserting EQUALITY WITH THE TAG, rather than merely "does not contain -dev",
# is deliberate and catches strictly more:
#   * unstamped / untagged / dirty build   -> "0.0.9-dev+g<sha>"  != "0.0.9"
#   * tags fetched shallowly, tag invisible-> "0.0.9-dev+g<sha>"  != "0.0.9"
#   * Cargo.toml bumped ahead of the tag   -> "0.0.10-dev+g<sha>" != "0.0.9"
#   * several v* tags on one commit: build-version.sh stamps whichever one
#     matches Cargo.toml, so a run triggered by v0.0.10 on a commit also
#     tagged v0.0.9 (Cargo.toml = 0.0.9) stamps a clean "0.0.9" with no -dev
#     anywhere — an artifact reporting the wrong release, invisible to a
#     -dev check, caught here.
# Every one of those publishes a binary that lies about which release it is,
# under a release name that says otherwise. Fail the release; never publish.
stamped_version() {
  local bin="$1" out
  out="$("$bin" --version)" || die "$bin --version failed"
  awk '{print $2}' <<<"$out"
}

daemon_version="$(stamped_version "$DAEMON_BIN")"
relay_version="$(stamped_version "$RELAY_BIN")"

[ "$daemon_version" = "$version" ] || die \
  "relay-daemon reports version '$daemon_version', tag $tag requires '$version'.
  A stamped version that disagrees with its tag means the published artifact would
  lie about which release it is. Refusing to publish. Check that daemon/Cargo.toml's
  [package] version is exactly '$version', that the checkout has the tag
  (fetch-depth: 0), and that the tree is clean. See docs/operations/version-stamping.md."
[ "$relay_version" = "$version" ] || die \
  "relay reports version '$relay_version', tag $tag requires '$version'. Refusing to publish."

# --- guard 4: the daemon really is static ----------------------------------
# ADR-0007's whole point: one binary that runs on any Node in a heterogeneous
# fleet, with no libc dependency to match. A musl build that silently picked up
# a dynamic dependency would only fail on the customer's oldest machines, long
# after publication.
#
# readelf, not ldd, is the real check: it is a static read of the ELF, it does
# not execute the binary, and it distinguishes the two shapes ldd conflates. A
# static-PIE (what this build produces) still HAS a .dynamic section for
# self-relocation, so "has a dynamic section" proves nothing; what must be
# absent is any interpreter (PT_INTERP) and any shared-library dependency
# (DT_NEEDED). ldd is asserted too, because it is what the issue's acceptance
# criterion names and what an operator will reach for — it prints "statically
# linked" for a static-PIE and "not a dynamic executable" for a classic
# non-PIE static binary, so both phrasings are accepted.
assert_static() {
  local bin="$1" name="$2"

  # Both readelf predicates below are ABSENCE tests, so a readelf that does not
  # run makes both of them false and the guard silently passes — the check the
  # docs call the real one would be inert, leaving only the weaker ldd
  # fallback. Presence (`command -v`) is not enough to rule that out: a stub, a
  # busybox applet, or a readelf that chokes on this file all exist and all
  # still fail. So capture the output and assert the STATUS, on this exact
  # binary, before trusting anything readelf does not say. A verification step
  # that cannot run must fail, not abstain.
  command -v readelf >/dev/null 2>&1 \
    || die "readelf not found — cannot verify that $name is statically linked (install binutils)"

  local phdrs dyn
  phdrs="$(readelf -l "$bin")" \
    || die "readelf -l failed on $name — cannot verify static linkage"
  if grep -q 'INTERP' <<<"$phdrs"; then
    die "$name is not static: it has a PT_INTERP program header (needs a dynamic loader)"
  fi

  # `readelf -d`'s status is deliberately not asserted: a binary with no
  # dynamic section at all is a legitimate static shape ("There is no dynamic
  # section in this file."), and whether that is an error is binutils-version
  # dependent. The -l call above already proved readelf runs on this file,
  # which is what closes the abstain-silently hole.
  dyn="$(readelf -d "$bin" 2>/dev/null || true)"
  if grep -q 'NEEDED' <<<"$dyn"; then
    die "$name is not static: it has DT_NEEDED shared-library dependencies:
$(grep 'NEEDED' <<<"$dyn")"
  fi
  # ldd exits non-zero on a static binary on some systems, hence `|| true`.
  local ldd_out
  ldd_out="$(ldd "$bin" 2>&1 || true)"
  if ! grep -Eq 'statically linked|not a dynamic executable' <<<"$ldd_out"; then
    die "$name: ldd does not report a static binary: $ldd_out"
  fi
}

assert_static "$DAEMON_BIN" "relay-daemon"
# The Relay is built CGO_ENABLED=0 for the same libc-independence reason, so it
# gets the same assertion — a toolchain change that quietly re-enabled cgo
# would otherwise ship a binary pinned to the runner's glibc.
assert_static "$RELAY_BIN" "relay"

# --- stage under the published names ---------------------------------------
daemon_asset="relay-daemon-${version}-${DAEMON_PLATFORM}"
relay_asset="relay-${version}-${RELAY_PLATFORM}"

rm -rf "$DIST"
mkdir -p "$DIST"
install -m 0755 "$DAEMON_BIN" "$DIST/$daemon_asset"
install -m 0755 "$RELAY_BIN"  "$DIST/$relay_asset"

# SHA256SUMS lists the assets by their PUBLISHED names and nothing else, so an
# operator who downloads assets next to it can run `sha256sum --check` in that
# directory with no rewriting. Generated from inside dist/ so the paths are
# bare filenames rather than "dist/..." .
( cd "$DIST" && sha256sum "$daemon_asset" "$relay_asset" > SHA256SUMS )

# --- guard 5: the checksum file actually verifies ---------------------------
# Cheap, but it is the exact command the documented install path runs, so a
# format or path mistake surfaces here instead of on a fleet.
( cd "$DIST" && sha256sum --check --strict SHA256SUMS ) \
  || die "SHA256SUMS does not verify against the staged artifacts"

# --- prerelease decision ---------------------------------------------------
# Pre-1.0 publishes as a pre-release (issue #250): 0.y.z makes no compatibility
# promise. Any tag carrying a semver prerelease suffix (v0.1.0-beta) is one too.
prerelease=false
if [[ "$version" == 0.* || "$version" == *-* ]]; then
  prerelease=true
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    echo "version=$version"
    echo "prerelease=$prerelease"
  } >> "$GITHUB_OUTPUT"
fi

echo
echo "release-artifacts: $tag verified — version $version, prerelease=$prerelease"
( cd "$DIST" && ls -l && echo && cat SHA256SUMS )
