#!/usr/bin/env bash
# Builds the relay-daemon .deb and .rpm, which carry the shipped read catalog, and optionally
# the Relay's own .deb and .rpm, from binaries the release already built and guarded (DI-24,
# DI-29, RC-23).
#
#   scripts/build-packages.sh <version> <x86_64|aarch64> <relay-daemon-binary> <outdir>
#                             [--relay <relay-binary>]
#
# Packaging builds nothing: the binary is placed byte for byte, and nothing here compiles,
# strips or rewrites it (ADR-0033). SOURCE_DATE_EPOCH must be set (the release sets it to the
# commit time); every manifest's mtime is rendered from it, so two builds of one commit are
# byte-identical, which the release checks by building twice.
#
# The manifests under daemon/packaging/nfpm/ and relay/packaging/nfpm/ are templates: this
# script substitutes their @NAME@ placeholders and nothing else, then runs the nfpm pinned
# under tools/nfpm.
set -euo pipefail

usage() {
  echo "usage: $0 <version> <x86_64|aarch64> <relay-daemon-binary> <outdir> [--relay <relay-binary>]" >&2
  exit 2
}

if [ "$#" -lt 4 ]; then usage; fi
version="$1" arch="$2" bin="$3" out="$4"
shift 4
relay_bin=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --relay) [ "$#" -ge 2 ] || usage; relay_bin="$2"; shift 2 ;;
    *) usage ;;
  esac
done

case "$arch" in
  x86_64) goarch=amd64 ;;
  aarch64) goarch=arm64 ;;
  *) echo "build-packages: unknown architecture '$arch'" >&2; exit 2 ;;
esac
# A version is a semver-shaped release stamp; it is substituted into YAML, so nothing else.
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?(\+[0-9A-Za-z.]+)?$ ]]; then
  echo "build-packages: '$version' is not a release version" >&2
  exit 2
fi
if ! [[ "${SOURCE_DATE_EPOCH:-}" =~ ^[0-9]+$ ]]; then
  echo "build-packages: SOURCE_DATE_EPOCH must be set to an integer (the commit time)" >&2
  exit 2
fi
[ -f "$bin" ] || { echo "build-packages: no binary at '$bin'" >&2; exit 2; }
if [ -n "$relay_bin" ]; then
  [ -f "$relay_bin" ] || { echo "build-packages: no Relay binary at '$relay_bin'" >&2; exit 2; }
  relay_bin="$(cd "$(dirname "$relay_bin")" && pwd -P)/$(basename "$relay_bin")"
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
bin="$(cd "$(dirname "$bin")" && pwd -P)/$(basename "$bin")"
mkdir -p "$out"
out="$(cd "$out" && pwd -P)"
mtime="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%Y-%m-%dT%H:%M:%SZ)"

# The module proxy sometimes drops a stream mid-download, so nfpm's modules are fetched with a
# few retries before the build. Each module is still checked against go.sum, and one that never
# downloads fails the build below.
for attempt in 1 2 3; do
  GOWORK=off go -C "$root/tools/nfpm" mod download && break
  [ "$attempt" = 3 ] || { echo "build-packages: module download failed, retrying" >&2; sleep $((attempt * 10)); }
done
nfpm="$(GOWORK=off go -C "$root/tools/nfpm" tool -n nfpm)"
[ -x "$nfpm" ] || { echo "build-packages: cannot build the pinned nfpm" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# render TEMPLATE: the manifest with its placeholders substituted. A placeholder left over
# means the template and this script disagree, which is a failure, not a default.
render() {
  local tpl="$1" dst esc_bin esc_relay_bin esc_root
  dst="$work/$(basename "$1")"
  esc_bin="$(printf '%s' "$bin" | sed 's/[\\|&]/\\&/g')"
  esc_relay_bin="$(printf '%s' "$relay_bin" | sed 's/[\\|&]/\\&/g')"
  esc_root="$(printf '%s' "$root" | sed 's/[\\|&]/\\&/g')"
  sed -e "s|@VERSION@|${version}|g" \
      -e "s|@ARCH@|${goarch}|g" \
      -e "s|@MTIME@|${mtime}|g" \
      -e "s|@DAEMON_BIN@|${esc_bin}|g" \
      -e "s|@RELAY_BIN@|${esc_relay_bin}|g" \
      -e "s|@SRC@|${esc_root}|g" \
      "$tpl" > "$dst"
  if grep -v '^[[:space:]]*#' "$dst" | grep '@[A-Z_]*@' >&2; then
    echo "build-packages: unrendered placeholder in $tpl" >&2
    exit 1
  fi
  printf '%s\n' "$dst"
}

# nfpm reads no other environment for these manifests: version and arch are rendered above.
pkg() {
  local manifest="$1" packager="$2"
  (cd "$work" && SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" "$nfpm" package \
     --config "$manifest" --packager "$packager" --target "$out/") >&2
}

daemon_manifest="$(render "$root/daemon/packaging/nfpm/relay-daemon.yaml")"
pkg "$daemon_manifest" deb
pkg "$daemon_manifest" rpm
if [ -n "$relay_bin" ]; then
  relay_manifest="$(render "$root/relay/packaging/nfpm/relay.yaml")"
  pkg "$relay_manifest" deb
  pkg "$relay_manifest" rpm
fi
ls -1 "$out"
