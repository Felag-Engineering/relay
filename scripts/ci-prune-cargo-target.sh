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

names=(relay_daemon librelay_daemon)
for t in tests/*.rs; do
  [ -e "$t" ] && names+=("$(basename "$t" .rs)")
done
# The workspace members (crates/<name>/): their rlibs and build-script outputs.
crates=()
for d in crates/*/; do
  [ -d "$d" ] || continue
  n=$(basename "$d")
  crates+=("$n")
  names+=("${n//-/_}" "lib${n//-/_}")
done

find target -type d -name incremental -prune -exec rm -rf {} +
for n in "${names[@]}"; do
  find target -path '*/deps/*' -name "${n}-*" -exec rm -rf {} +
done
for n in "${crates[@]}"; do
  find target -maxdepth 4 \( -path '*/.fingerprint/*' -o -path '*/build/*' \) -type d -name "${n}-*" -prune -exec rm -rf {} +
done
# depth 4 reaches target/<triple>/<profile>/{.fingerprint,build}/ as well as target/<profile>/…
find target -maxdepth 4 \( -path '*/.fingerprint/*' -o -path '*/build/*' \) -type d -name 'relay-daemon-*' -prune -exec rm -rf {} +
# Uplifted copies of the binary (target/<profile>/relay-daemon and the musl equivalent).
find target -maxdepth 3 -type f \( -name relay-daemon -o -name relay-daemon.d \) -delete
du -sh target
