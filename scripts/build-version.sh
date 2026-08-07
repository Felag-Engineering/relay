#!/usr/bin/env bash
# Derive the build stamp for BOTH binaries (issue #249, ADR-0014).
#
# Prints one line: "<version> <commit> <build-date>" — three whitespace-free
# fields, consumed by the Makefile ($(word 1..3,...)) and stamped into the
# relay (-ldflags -X) and the relay-daemon (RELAY_BUILD_* -> build.rs).
#
# THE SCHEME (see daemon/src/version.rs for the full rationale)
#
#   base            = daemon/Cargo.toml's [package] version — the SEMANTIC
#                     version of both binaries, i.e. the release this working
#                     tree is developing toward. May itself be a prerelease
#                     (e.g. "0.1.0-beta").
#   core            = base with any prerelease suffix dropped ("X.Y.Z").
#   clean + HEAD is exactly tag v<base>  ->  "<base>"
#   anything else                        ->  "<core>-0.dev[+g<sha>[.dirty]]"
#
# Git supplies IDENTITY, never ordering. `-0.dev` is a semver prerelease whose
# FIRST identifier is numeric, and semver orders every numeric identifier below
# every alphanumeric one — so a dev build sorts strictly BELOW the release it
# precedes even when that release is itself a prerelease:
#     0.0.9-0.dev < 0.0.9      and      0.1.0-0.dev < 0.1.0-beta < 0.1.0
# That is the truthful ordering, and the fail-closed direction for the Relay's
# min-daemon-version gate. The earlier `<base>-dev` marker (issue #249) got
# this WRONG for prerelease targets: `0.1.0-beta-dev` sorts ABOVE `0.1.0-beta`
# (a single identifier, lexically greater), inverting the gate fail-open —
# fixed by issue #261, and why the target's prerelease suffix is dropped for
# dev builds instead of appended to. Any further identifiers must stay AFTER
# `0.dev`, so the leading numeric identifier keeps deciding the order.
# Deriving from the LAST tag instead (`git describe` -> 0.0.9-14-gabc) would
# be backwards: that is a prerelease of 0.0.9 and would report a build made
# *after* the 0.0.9 release as older than it.
#
# Dirtiness is deliberately expressed by the `-0.dev` prerelease, not only by
# the `.dirty` build-metadata suffix: semver comparison IGNORES build metadata,
# so `<base>+dirty` would be invisible to the gate.
#
# No tags, no git, or no bash-visible repo at all: the untagged/unknown path is
# taken and still yields valid semver ("<core>-0.dev"). This script never fails
# the build.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# The [package] version only: dependency tables also contain `version = ` keys,
# so the scan is bounded to the [package] section and stops at the next table.
base="$(awk -F'"' '
  /^\[package\]/      { in_pkg = 1; next }
  /^\[/               { in_pkg = 0 }
  in_pkg && /^version[[:space:]]*=/ { print $2; exit }
' daemon/Cargo.toml)"

if [ -z "$base" ]; then
  echo "build-version.sh: could not read [package] version from daemon/Cargo.toml" >&2
  exit 1
fi

commit="unknown"
dirty=""
in_git=0
if git rev-parse --git-dir >/dev/null 2>&1; then
  in_git=1
  commit="$(git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
  # Tracked modifications only (staged or not), matching `git describe --dirty`:
  # untracked scratch files must not mark an otherwise-clean build as dirty.
  if ! git diff --quiet HEAD -- 2>/dev/null; then
    dirty=".dirty"
  fi
fi

# The numeric core: any prerelease suffix on the target is DROPPED for dev
# builds ("0.1.0-beta" -> "0.1.0"), so the dev marker is always the first —
# and numerically-least — prerelease identifier. See the scheme note above.
core="${base%%-*}"

version="${core}-0.dev"
# `git tag --points-at`, not `git describe --exact-match`: describe returns ONE
# tag and picks it by its own ordering, so an unrelated tag also sitting on HEAD
# (say `nightly`) could hide the real `v<base>` tag and silently demote a
# release build to a dev build. --points-at lists every tag on HEAD, annotated
# and lightweight, so the match is on presence rather than on describe's choice.
if [ "$in_git" -eq 1 ] && [ -z "$dirty" ] &&
   git tag --points-at HEAD 2>/dev/null | grep -qx "v${base}"; then
  # An exact, clean release build: report exactly the release version, with no
  # prerelease and no metadata.
  version="$base"
elif [ "$commit" != "unknown" ]; then
  # Non-release build: carry the commit (and dirtiness) as semver BUILD
  # METADATA — fleet-visible via the registry, comparison-neutral by design.
  version="${version}+g${commit}${dirty}"
fi

# Date, not timestamp: the stamp is a cargo `rustc-env` input, so a wall-clock
# timestamp would force a daemon recompile on every single build. UTC date
# keeps that to at most once a day. SOURCE_DATE_EPOCH is honoured for
# reproducible-build pipelines.
if [ -n "${SOURCE_DATE_EPOCH:-}" ]; then
  build_date="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y-%m-%d 2>/dev/null || date -u +%Y-%m-%d)"
else
  build_date="$(date -u +%Y-%m-%d)"
fi

echo "${version} ${commit} ${build_date}"
