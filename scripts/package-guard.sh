#!/usr/bin/env bash
# The release workflow's package guards (DI-24, DI-32, RC-23). Reads package bytes only; builds
# nothing.
#
#   package-guard.sh same <package> <path-in-package> <file>
#       The member at <path-in-package> is byte-equal to <file>. Used for the payload binary
#       against the release binary, and the packaged unit, environment example and example
#       configuration against the standalone copies the release attaches.
#   package-guard.sh listed <sums-file> <file>...
#       Each file's basename has a line in <sums-file> carrying its own SHA-256.
#   package-guard.sh no-config <package>
#       The package declares no file the package manager would preserve as configuration
#       (no dpkg conffiles, no rpm %config): the live Policy and environment file are placed by
#       maintainer scripts, never package-owned (ADR-0033), and the catalog's Templates are
#       package-owned plain files (DI-29).
#   package-guard.sh content <package> <relay-daemon|relay-read|relay> <version> <x86_64|aarch64>
#       The package's whole content, read with the distribution's own tools and never with
#       nfpm, equals what the repository says it must be:
#         - its identity is the expected one, computed from <version> and <arch> and never
#           read from the package: on .deb the whole control file equals
#           <expected>/<name>.deb.control with only Version, Architecture and
#           Installed-Size filled in (Package, epoch-free Version, amd64|arm64 or all); on .rpm
#           NAME, EPOCHNUM (0), VERSION-RELEASE and ARCH (x86_64|aarch64 or noarch) are exact;
#         - its payload listing (path, type, mode, owner; and on rpm, file capabilities) equals
#           <expected>/<name>.<deb|rpm>.files, and no entry is setuid, setgid or
#           sticky or carries a file capability;
#         - its maintainer scripts are byte-equal to <scripts>/*.sh (on .deb the
#           control archive holds exactly the expected members; on .rpm the output of
#           `rpm -qp --scripts --triggers --filetriggers` equals the source scripts, each under
#           the one header line rpm itself prints, and declares no trigger);
#         - its relationships and control fields equal
#           <expected>/<name>.<deb|rpm>.relations, with the EXPECTED
#           version-release and rpm architecture tag written as placeholders;
#         - every file it carries from the repository (default Policy, LICENSE, the privilege
#           posture document, the units, the example configuration and environment example, the
#           Relay's sysusers entry, configuration template and guide, the catalog) is
#           byte-equal to its source.
#       <expected> and <scripts> are daemon/packaging/{expected,scripts} for relay-daemon and
#       relay-read, and relay/packaging/{expected,scripts} for relay.
#       This is the check that does not trust the packager: both release passes run the same
#       pinned nfpm, so their comparison proves determinism, not that nfpm put the right bytes
#       in.
#
# A .deb is read with dpkg-deb, a .rpm with rpm, rpm2cpio and cpio. Exit 0 pass, 1 refused, 2
# usage or a missing tool.
set -euo pipefail

die() { echo "package-guard: $*" >&2; exit 2; }
refuse() { echo "package-guard: REFUSED: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# EXPECTED and SCRIPTS name the reviewed baseline and the maintainer scripts of the package
# under check; content() sets them from the package name.
EXPECTED=""
SCRIPTS=""
SCRIPTS_SRC=""

# files_view PACKAGE: one line per payload entry, "<mode-string> <owner> <path>" (rpm adds
# "caps=<capabilities>"). Symlinks and hard links keep their "-> target" / "link to" suffix, so
# any such entry differs from an expected regular file.
files_view() {
  case "$1" in
    *.deb) dpkg-deb -c "$1" | awk '{ p = $6; for (i = 7; i <= NF; i++) p = p " " $i; print $1, $2, p }' ;;
    *.rpm) rpm -qp --qf '[%{FILEMODES:perms} %{FILEUSERNAME}:%{FILEGROUPNAME} caps=%{FILECAPS} %{FILENAMES}\n]' "$1" ;;
  esac
}

# identity NAME VERSION ARCH: sets the identity the package must carry, derived from the
# release version and architecture the caller expects and never read from the package:
#   DEB_VERSION  <base>[~<pre>][+<meta>]-1   (no epoch)     RPM_VR  the same, pre's '-' as '_'
#   DEB_ARCH     amd64 | arm64, or all for the catalog       RPM_ARCH  x86_64 | aarch64 | noarch
#   RPM_ISA      the rpm architecture tag in Provides (x86-64 | aarch-64), empty for noarch
# These are the transformations nfpm applies to a semver version; a package whose identity
# differs, whatever produced it, is refused.
identity() {
  local name="$1" v="$2" arch="$3" base pre="" meta=""
  [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?(\+[0-9A-Za-z.]+)?$ ]] \
    || die "'$v' is not a release version"
  base="${v%%[-+]*}"
  if [[ "$v" == *-* ]]; then pre="${v#*-}"; pre="${pre%%+*}"; fi
  if [[ "$v" == *+* ]]; then meta="${v#*+}"; fi
  DEB_VERSION="$base${pre:+~$pre}${meta:++$meta}-1"
  RPM_VR="$base${pre:+~${pre//-/_}}${meta:++$meta}-1"
  case "$arch" in
    x86_64) DEB_ARCH=amd64; RPM_ARCH=x86_64; RPM_ISA=x86-64 ;;
    aarch64) DEB_ARCH=arm64; RPM_ARCH=aarch64; RPM_ISA=aarch-64 ;;
    *) die "unknown architecture '$arch'" ;;
  esac
  if [ "$name" = relay-read ]; then DEB_ARCH=all; RPM_ARCH=noarch; RPM_ISA=""; fi
}

# relations_view PACKAGE: every relationship the package declares, with the EXPECTED
# version-release written as @VR@ and the expected rpm architecture tag as @ISA@, so a package
# carrying any other version or architecture in a relationship differs from the baseline. On
# .deb also the set of control field names.
relations_view() {
  local pkg="$1" vr
  case "$pkg" in
    *.deb)
      vr="$DEB_VERSION"
      echo "Fields: $(dpkg-deb -f "$pkg" | awk -F: '/^[A-Za-z][A-Za-z0-9-]*:/ {print $1}' | sort | paste -sd ' ' -)"
      for f in Depends Pre-Depends Provides Replaces Conflicts Breaks Recommends Suggests Enhances; do
        echo "$f: $(dpkg-deb -f "$pkg" "$f")"
      done | sed "s|${vr//./\\.}|@VR@|g"
      ;;
    *.rpm)
      vr="$RPM_VR"
      local isa='s/^//'
      if [ -n "$RPM_ISA" ]; then isa="s/(${RPM_ISA})/(@ISA@)/g"; fi
      for q in provides requires conflicts obsoletes recommends suggests supplements enhances; do
        rpm -qp "--$q" "$pkg" | sed "s/^/$q: /"
      done | sed -e "s|${vr//./\\.}|@VR@|g" -e "$isa"
      ;;
  esac
}

# control_expected NAME PKG: the reviewed .deb control file with only Version, Architecture
# (both from identity) and Installed-Size (read from the package, and required to be a number)
# filled in.
control_expected() {
  local size
  size="$(dpkg-deb -f "$2" Installed-Size)"
  [[ "$size" =~ ^[0-9]+$ ]] || refuse "$PKG_NAME: Installed-Size '$size' is not a number"
  sed -e "s|@VERSION@|$DEB_VERSION|" -e "s|@ARCH@|$DEB_ARCH|" -e "s|@INSTALLED_SIZE@|$size|" \
    "$EXPECTED/$1.deb.control"
}

# rpm_scripts_expected NAME: what `rpm -qp --scripts --triggers --filetriggers` prints for
# the source scripts. rpm prints one header line before each scriptlet, naming its phase and
# interpreter, and one newline after it (its --scripts query format ends each body with "\n");
# those two are the only normalisation. The scriptlet bytes themselves must be the source's.
rpm_scripts_expected() {
  [ "$1" = relay-read ] && return 0
  local label src
  for pair in preinstall:preinst postinstall:postinst preuninstall:prerm postuninstall:postrm; do
    label="${pair%%:*}"; src="${pair##*:}"
    printf '%s scriptlet (using /bin/sh):\n' "$label"
    cat "$SCRIPTS/$src.sh"
    echo
  done
}

# compare_view WHAT EXPECTED-FILE ACTUAL-FILE: refuse with a diff unless equal.
compare_view() {
  if ! diff -u "$2" "$3" >&2; then
    refuse "$PKG_NAME: $1 differs from $(basename "$2")"
  fi
}

content() {
  local pkg="$1" name="$2" fmt
  case "$pkg" in *.deb) fmt=deb; need dpkg-deb ;; *.rpm) fmt=rpm; need rpm; need rpm2cpio; need cpio ;;
    *) die "not a .deb or .rpm: $pkg" ;; esac
  case "$name" in
    relay-daemon | relay-read) EXPECTED="$ROOT/daemon/packaging/expected"; SCRIPTS="$ROOT/daemon/packaging/scripts"; SCRIPTS_SRC=daemon/packaging/scripts ;;
    relay) EXPECTED="$ROOT/relay/packaging/expected"; SCRIPTS="$ROOT/relay/packaging/scripts"; SCRIPTS_SRC=relay/packaging/scripts ;;
    *) die "unknown package name: $name" ;;
  esac
  [ -f "$pkg" ] || die "no package at $pkg"
  PKG_NAME="$(basename "$pkg")"
  identity "$name" "$3" "$4"
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT

  # Identity: name, epoch, version and architecture are the expected ones, never values taken
  # from the package itself.
  if [ "$fmt" = deb ]; then
    dpkg-deb -f "$pkg" > "$work/control"
    control_expected "$name" "$pkg" > "$work/control.want"
    compare_view "control file" "$work/control.want" "$work/control"
  else
    rpm -qp --qf '%{NAME} %{EPOCHNUM} %{VERSION}-%{RELEASE} %{ARCH}\n' "$pkg" > "$work/ident" 2>/dev/null
    printf '%s 0 %s %s\n' "$name" "$RPM_VR" "$RPM_ARCH" > "$work/ident.want"
    compare_view "name, epoch, version and architecture" "$work/ident.want" "$work/ident"
  fi

  # Payload listing, and no privilege bits or capabilities anywhere.
  files_view "$pkg" > "$work/files"
  compare_view "payload listing" "$EXPECTED/$name.$fmt.files" "$work/files"
  if awk '{print $1}' "$work/files" | grep -q '[sStT]'; then
    refuse "$PKG_NAME: an entry is setuid, setgid or sticky"
  fi
  if [ "$fmt" = rpm ] && grep -Ev ' caps=(\(none\))? ' "$work/files" | grep -q .; then
    refuse "$PKG_NAME: an entry carries a file capability"
  fi

  # Maintainer scripts.
  if [ "$fmt" = deb ]; then
    dpkg-deb --ctrl-tarfile "$pkg" | tar -t | sort > "$work/ctrl"
    { echo ./control; echo ./md5sums
      if [ "$name" != relay-read ]; then printf './%s\n' postinst postrm preinst prerm; fi
    } | sort > "$work/ctrl.want"
    compare_view "control archive members" "$work/ctrl.want" "$work/ctrl"
    if [ "$name" != relay-read ]; then
      mkdir "$work/c"
      dpkg-deb --ctrl-tarfile "$pkg" | tar -xf - -C "$work/c"
      for s in preinst postinst prerm postrm; do
        cmp -s "$work/c/$s" "$SCRIPTS/$s.sh" || refuse "$PKG_NAME: $s differs from $SCRIPTS_SRC/$s.sh"
      done
    fi
  else
    rpm -qp --scripts --triggers --filetriggers "$pkg" > "$work/scripts" 2>/dev/null
    rpm_scripts_expected "$name" > "$work/scripts.want"
    compare_view "scriptlets and triggers" "$work/scripts.want" "$work/scripts"
  fi

  # Relationships and control fields.
  relations_view "$pkg" > "$work/relations"
  compare_view "relationships" "$EXPECTED/$name.$fmt.relations" "$work/relations"

  # Files carried from the repository, byte for byte.
  local pairs
  if [ "$name" = relay-daemon ]; then
    pairs="/usr/share/relay-daemon/policy.default.toml:daemon/policy.default.toml
/usr/share/doc/relay-daemon/LICENSE:LICENSE
/usr/share/doc/relay-daemon/daemon-privilege-posture.md:docs/operations/daemon-privilege-posture.md
/usr/lib/systemd/system/relay-daemon.service:daemon/packaging/relay-daemon.service
/usr/share/relay-daemon/relay-daemon.env.example:daemon/packaging/relay-daemon.env.example"
  elif [ "$name" = relay ]; then
    pairs="/usr/lib/systemd/system/relay.service:relay/packaging/relay.service
/usr/lib/sysusers.d/relay.conf:relay/packaging/relay.sysusers.conf
/usr/share/relay/relay.toml.in:relay/packaging/relay.toml.in
/usr/share/relay/relay.toml.example:relay/packaging/relay.toml.example
/usr/share/relay/configuration-guide.txt:relay/packaging/configuration-guide.txt
/usr/share/doc/relay/configuration-guide.txt:relay/packaging/configuration-guide.txt
/usr/share/doc/relay/LICENSE:LICENSE"
  else
    pairs="/etc/relay-daemon/templates.d/relay-read/catalog.toml:daemon/packaging/templates.d/relay-read/catalog.toml"
  fi
  while IFS=: read -r path src; do
    member "$pkg" "$path" > "$work/m" 2>/dev/null || refuse "$PKG_NAME has no $path"
    cmp -s "$work/m" "$ROOT/$src" || refuse "$PKG_NAME: $path differs from $src"
  done <<<"$pairs"
  echo "package-guard: $PKG_NAME: payload, scripts, relationships and repository files are as expected"
}

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
  content)
    [ "$#" -eq 5 ] || die "usage: content <package> <relay-daemon|relay-read|relay> <version> <x86_64|aarch64>"
    content "$(realpath "$2")" "$3" "$4" "$5"
    ;;
  *) die "usage: $0 same|listed|no-config|content ..." ;;
esac
