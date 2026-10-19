#!/usr/bin/env bash
# Builds the relay-daemon and relay-read .deb and .rpm packages from an already-built release
# daemon binary. The one package build path: the Makefile, the release workflow and the tests
# all call it. It compiles, strips and rewrites nothing (DI-24).
#
#   package-daemon.sh --nfpm PATH --bin PATH --version V --arch amd64|arm64 --out DIR
#
# SOURCE_DATE_EPOCH (the commit time) must be set. It is rendered into each manifest's mtime,
# because nfpm does not expand the variable there and falls back to the wall clock when it is
# unset. Every refusal names its reason.
set -euo pipefail

die() { echo "::error::package-daemon: $*" >&2; exit 1; }

nfpm="" bin="" version="" arch="" out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --nfpm) [ "$#" -ge 2 ] || die "--nfpm needs a value"; nfpm="$2"; shift 2 ;;
    --bin) [ "$#" -ge 2 ] || die "--bin needs a value"; bin="$2"; shift 2 ;;
    --version) [ "$#" -ge 2 ] || die "--version needs a value"; version="$2"; shift 2 ;;
    --arch) [ "$#" -ge 2 ] || die "--arch needs a value"; arch="$2"; shift 2 ;;
    --out) [ "$#" -ge 2 ] || die "--out needs a value"; out="$2"; shift 2 ;;
    *) die "unknown argument '$1' (usage: $0 --nfpm PATH --bin PATH --version V --arch amd64|arm64 --out DIR)" ;;
  esac
done

[ -n "$nfpm" ] && [ -n "$bin" ] && [ -n "$version" ] && [ -n "$arch" ] && [ -n "$out" ] \
  || die "usage: $0 --nfpm PATH --bin PATH --version V --arch amd64|arm64 --out DIR"
[ -n "${SOURCE_DATE_EPOCH:-}" ] || die "SOURCE_DATE_EPOCH is unset; package mtimes must come from the commit time"
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH '$SOURCE_DATE_EPOCH' is not a number of seconds"
case "$arch" in
  amd64 | arm64) ;;
  *) die "unsupported arch '$arch' (want amd64 or arm64)" ;;
esac
[ -x "$nfpm" ] || die "nfpm '$nfpm' is not an executable file"
[ -f "$bin" ] && [ ! -L "$bin" ] || die "--bin '$bin' is not a regular file"
if [ -e "$out" ]; then
  [ -d "$out" ] || die "--out '$out' exists and is not a directory"
  [ -z "$(ls -A "$out")" ] || die "--out '$out' is not empty; stale packages must not ride along"
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin="$(cd "$(dirname "$bin")" && pwd)/$(basename "$bin")"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

work="$(mktemp -d)" || die "mktemp -d failed"
case "$work" in /*) ;; *) die "mktemp returned a non-absolute path" ;; esac
trap 'rm -rf "$work"' EXIT

mtime="$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)" || die "cannot render SOURCE_DATE_EPOCH '$SOURCE_DATE_EPOCH'"

# render <name>: copy the manifest and replace its one mtime token.
render() {
  local src="$repo_root/daemon/packaging/nfpm/$1.yaml" dst="$work/$1.yaml" n
  [ -f "$src" ] || die "no manifest $src"
  n="$(grep -c '@SOURCE_DATE_EPOCH@' "$src" || true)"
  [ "$n" = 1 ] || die "$1.yaml has $n mtime tokens, want exactly 1"
  sed "s|@SOURCE_DATE_EPOCH@|$mtime|" "$src" >"$dst"
  ! grep -q '@SOURCE_DATE_EPOCH@' "$dst" || die "$1.yaml still has the mtime token after rendering"
}
render relay-daemon
render relay-read

cd "$repo_root"
export RELAY_PKG_VERSION="$version" RELAY_PKG_ARCH="$arch" RELAY_DAEMON_BIN="$bin" SOURCE_DATE_EPOCH
for name in relay-daemon relay-read; do
  for fmt in deb rpm; do
    "$nfpm" pkg -f "$work/$name.yaml" -p "$fmt" -t "$out/" >/dev/null || die "nfpm failed building $name .$fmt"
  done
done
ls -1 "$out"
