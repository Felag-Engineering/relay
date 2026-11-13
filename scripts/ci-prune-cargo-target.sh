#!/usr/bin/env bash
# Trims daemon/target before CI saves it as a cache: removes the relay-daemon
# crate's own artifacts (its lib, bin and integration-test binaries), those of every
# workspace member under daemon/crates/, and any incremental state, and keeps the
# compiled third-party dependencies — the part worth caching.
#
# The daemon crates are first-party and change on nearly every commit (and the bin's
# build stamp is a build-script input), so their artifacts are dead weight in a cache; without this, each
# weekly refresh restores the previous week's copies and saves them again, and the
# entry grows without bound.
set -euo pipefail
cd "$(dirname "$0")/../daemon"
[ -d target ] || exit 0

# Cargo 1.100 (the pinned CI toolchain) keeps each unit's artifacts, dep-info and
# fingerprint under <profile>/build/<package>/<hash>/, so a first-party package's
# whole build/<package>/ directory is its artifacts: lib, bin, test binaries and
# build-script output. The cache key carries the rustc version, so a cache never
# mixes this layout with the older deps/ and .fingerprint/ one.
packages=(relay-daemon)
for d in crates/*/; do
  [ -d "$d" ] && packages+=("$(basename "$d")")
done

find target -type d -name incremental -prune -exec rm -rf {} +
shopt -s nullglob
for p in "${packages[@]}"; do
  # target/<profile>/build/<p> and target/<triple>/<profile>/build/<p>
  for dir in target/*/build/"$p" target/*/*/build/"$p"; do
    rm -rf "$dir"
  done
done
# Uplifted copies of the binary and the first-party libs (target/<profile>/relay-daemon,
# librelay_*.rlib and their .d, and the musl equivalents).
find target -maxdepth 3 -type f \( -name relay-daemon -o -name relay-daemon.d -o -name 'librelay_*' \) -delete
du -sh target
