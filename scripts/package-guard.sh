#!/usr/bin/env bash
# The release workflow's package guards (DI-24, DI-32). Reads package bytes only; builds nothing.
#
#   package-guard.sh same <package> <path-in-package> <file>
#       The member at <path-in-package> is byte-equal to <file>. Used for the payload binary
#       against the release binary, and the packaged unit and environment example against the
#       standalone copies the release attaches.
#   package-guard.sh listed <sums-file> <file>...
#       Each file's basename has a line in <sums-file> carrying its own SHA-256.
#   package-guard.sh no-config <package>
#       The package declares no file the package manager would preserve as configuration
#       (no dpkg conffiles, no rpm %config): the live Policy and environment file are placed by
#       maintainer scripts, never package-owned (ADR-0033), and the catalog's Templates are
#       package-owned plain files (DI-29).
#
# A .deb is read with dpkg-deb, a .rpm with rpm2cpio and cpio. Exit 0 pass, 1 refused, 2 usage
# or a missing tool.
set -euo pipefail

die() { echo "package-guard: $*" >&2; exit 2; }
refuse() { echo "package-guard: REFUSED: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

# member PACKAGE PATH: writes the member's bytes to stdout; fails if it is absent.
member() {
  local pkg="$1" path="$2"
  case "$pkg" in
    *.deb)
      need dpkg-deb
      dpkg-deb --fsys-tarfile "$pkg" | tar -xOf - ".${path}"
      ;;
    *.rpm)
      need rpm2cpio; need cpio
      local tmp
      tmp="$(mktemp -d)"
      (cd "$tmp" && rpm2cpio "$pkg" | cpio -id --quiet --no-absolute-filenames ".${path}") \
        || { rm -rf "$tmp"; return 1; }
      if [ ! -f "$tmp${path}" ] || [ -L "$tmp${path}" ]; then rm -rf "$tmp"; return 1; fi
      cat "$tmp${path}"
      rm -rf "$tmp"
      ;;
    *) die "not a .deb or .rpm: $pkg" ;;
  esac
}

cmd="${1:-}"
case "$cmd" in
  same)
    [ "$#" -eq 4 ] || die "usage: same <package> <path-in-package> <file>"
    pkg="$(realpath "$2")" path="$3" file="$4"
    [ -f "$pkg" ] || die "no package at $pkg"
    [ -f "$file" ] || die "no file at $file"
    [[ "$path" == /* ]] || die "path-in-package must be absolute: $path"
    got="$(mktemp)"
    trap 'rm -f "$got"' EXIT
    member "$pkg" "$path" > "$got" 2>/dev/null || refuse "$(basename "$pkg") has no $path"
    cmp -s "$got" "$file" || refuse "$(basename "$pkg"): $path differs from $file"
    echo "package-guard: $(basename "$pkg"): $path is byte-equal to $(basename "$file")"
    ;;
  listed)
    [ "$#" -ge 3 ] || die "usage: listed <sums-file> <file>..."
    sums="$2"; shift 2
    [ -f "$sums" ] || die "no sums file at $sums"
    fail=0
    for f in "$@"; do
      [ -f "$f" ] || die "no file at $f"
      n="$(basename "$f")"
      want="$(sha256sum "$f" | awk '{print $1}')"
      if awk -v h="$want" -v n="$n" '$1 == h && ($2 == n || $2 == "*" n) {found=1} END {exit !found}' "$sums"; then
        echo "package-guard: $n is listed in $(basename "$sums")"
      else
        echo "package-guard: REFUSED: $n is not listed in $(basename "$sums") with its SHA-256" >&2
        fail=1
      fi
    done
    exit "$fail"
    ;;
  no-config)
    [ "$#" -eq 2 ] || die "usage: no-config <package>"
    pkg="$2"
    [ -f "$pkg" ] || die "no package at $pkg"
    case "$pkg" in
      *.deb)
        need dpkg-deb
        if dpkg-deb --ctrl-tarfile "$pkg" | tar -t | grep -qx './conffiles'; then
          refuse "$(basename "$pkg") declares conffiles"
        fi
        ;;
      *.rpm)
        need rpm
        conf="$(rpm -qcp "$pkg" 2>/dev/null)" || die "rpm cannot read $pkg"
        if [ -n "$conf" ] && [ "$conf" != "(contains no files)" ]; then
          refuse "$(basename "$pkg") declares %config files: $conf"
        fi
        ;;
      *) die "not a .deb or .rpm: $pkg" ;;
    esac
    echo "package-guard: $(basename "$pkg") declares no configuration files"
    ;;
  *) die "usage: $0 same|listed|no-config ..." ;;
esac
