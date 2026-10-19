#!/usr/bin/env bash
# Inspects and guards the relay-daemon and relay-read packages. Every refusal names its reason
# and exits non-zero.
#
#   package-guard.sh list <pkg>
#       Canonical listing, one line per entry in archive order:
#       "<type> <mode> <uid> <gid> <mtime> <path>", with the mtime in UTC. type is f, d, l or o.
#   package-guard.sh conffiles <pkg>
#       Prints the paths the package marks as configuration files. A package has none.
#   package-guard.sh payload <pkg> <path> <expected-file>
#       <path> must be exactly one regular-file entry whose bytes equal <expected-file>.
#   package-guard.sh maintscripts <pkg> <scripts-dir>
#       The maintainer scripts embedded in a relay-daemon package are the committed ones; a
#       relay-read package has none.
#   package-guard.sh scripts <dir>
#       Static rules for the maintainer scripts in <dir> (the committed ones).
#   package-guard.sh release <dist> <version> <scripts-dir> <catalog-file>
#       The release workflow's guard over the assembled dist directory.
#
# Packages and the committed scripts are inputs to a root-at-install path, so nothing here
# trusts a file name: contents are extracted and compared.
set -euo pipefail

die() { echo "::error::package-guard: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required"; }

pkg_kind() {
  [ -f "$1" ] || die "no such package: $1"
  case "$1" in
    *.deb) echo deb ;;
    *.rpm) echo rpm ;;
    *) die "$1 is neither a .deb nor an .rpm" ;;
  esac
}

# list_tsv <pkg>: type mode uid gid mtime path
list_pkg() {
  local pkg="$1" kind
  kind="$(pkg_kind "$pkg")"
  export TZ=UTC LC_ALL=C
  if [ "$kind" = deb ]; then
    need dpkg-deb
    dpkg-deb --fsys-tarfile "$pkg" | tar -tv --numeric-owner --full-time | awk '
      function bit(c, v) { return (c != "-" && c != "S" && c != "T") ? v : 0 }
      {
        p = $1; t = substr(p, 1, 1)
        type = (t == "-") ? "f" : (t == "d") ? "d" : (t == "l") ? "l" : "o"
        u = bit(substr(p,2,1),4) + bit(substr(p,3,1),2) + bit(substr(p,4,1),1)
        g = bit(substr(p,5,1),4) + bit(substr(p,6,1),2) + bit(substr(p,7,1),1)
        o = bit(substr(p,8,1),4) + bit(substr(p,9,1),2) + bit(substr(p,10,1),1)
        sp = (substr(p,4,1) ~ /[sS]/ ? 4 : 0) + (substr(p,7,1) ~ /[sS]/ ? 2 : 0) + (substr(p,10,1) ~ /[tT]/ ? 1 : 0)
        split($2, own, "/")
        path = $6
        for (i = 7; i <= NF; i++) { if ($i == "->" || $i == "link") break; path = path " " $i }
        sub(/^\./, "", path); if (length(path) > 1) sub(/\/$/, "", path)
        printf "%s %d%d%d%d %s %s %sT%sZ %s\n", type, sp, u, g, o, own[1], own[2], $4, $5, path
      }'
  else
    need rpm
    rpm -qp --dump "$pkg" | while read -r path _size mtime _digest mode owner group _rest; do
      # rpm prints the full st_mode in octal: the file-type bits, then the permission bits.
      case $((8#$mode & 8#170000)) in
        $((8#100000))) type=f ;;
        $((8#040000))) type=d ;;
        $((8#120000))) type=l ;;
        *) type=o ;;
      esac
      mode="$(printf '%04o' $((8#$mode & 07777)))"
      [ "$owner" != root ] || owner=0
      [ "$group" != root ] || group=0
      printf '%s %s %s %s %s %s\n' "$type" "$mode" "$owner" "$group" "$(date -u -d "@$mtime" +%Y-%m-%dT%H:%M:%SZ)" "$path"
    done
  fi
}

cmd_list() {
  [ "$#" -eq 1 ] || die "usage: list <pkg>"
  list_pkg "$1"
}

cmd_conffiles() {
  [ "$#" -eq 1 ] || die "usage: conffiles <pkg>"
  local kind; kind="$(pkg_kind "$1")"
  if [ "$kind" = deb ]; then
    need dpkg-deb
    if dpkg-deb --ctrl-tarfile "$1" | tar -tf - | grep -qx '\./conffiles'; then
      dpkg-deb --ctrl-tarfile "$1" | tar -xOf - ./conffiles
    fi
  else
    need rpm
    rpm -qpc "$1" | grep -v '^(contains no files)$' || true
  fi
}

# extract <pkg> <path>: the bytes of one payload member on stdout.
extract() {
  local kind; kind="$(pkg_kind "$1")"
  if [ "$kind" = deb ]; then
    dpkg-deb --fsys-tarfile "$1" | tar -xOf - "./${2#/}"
  else
    need rpm2cpio; need cpio
    rpm2cpio "$1" | cpio -i --quiet --to-stdout "./${2#/}"
  fi
}

cmd_payload() {
  [ "$#" -eq 3 ] || die "usage: payload <pkg> <path> <expected-file>"
  local pkg="$1" path="$2" want="$3" lines n
  [ -f "$want" ] || die "no such expected file: $want"
  lines="$(list_pkg "$pkg" | awk -v p="$path" '$6 == p')"
  n="$(printf '%s' "$lines" | grep -c . || true)"
  [ "$n" = 1 ] || die "$pkg has $n entries for $path, want exactly 1"
  [ "${lines%% *}" = f ] || die "$pkg: $path is not a regular file (entry: $lines)"
  extract "$pkg" "$path" | cmp -s - "$want" || die "$pkg: $path differs from $want"
}

cmd_maintscripts() {
  [ "$#" -eq 2 ] || die "usage: maintscripts <pkg> <scripts-dir>"
  local pkg="$1" dir="$2" kind name pair
  kind="$(pkg_kind "$pkg")"
  if [ "$kind" = deb ]; then
    need dpkg-deb
    name="$(dpkg-deb -f "$pkg" Package)"
  else
    need rpm
    name="$(rpm -qp --qf '%{NAME}' "$pkg")"
  fi
  case "$name" in
    relay-read)
      if [ "$kind" = deb ]; then
        for s in preinst postinst prerm postrm; do
          ! dpkg-deb --ctrl-tarfile "$pkg" | tar -tf - | grep -qx "\./$s" || die "$pkg embeds a $s script; relay-read has none"
        done
      else
        for tag in PREIN POSTIN PREUN POSTUN; do
          [ "$(rpm -qp --qf "%{$tag}" "$pkg")" = "(none)" ] || die "$pkg embeds a $tag script; relay-read has none"
        done
      fi
      return 0
      ;;
    relay-daemon) ;;
    *) die "$pkg is package '$name', want relay-daemon or relay-read" ;;
  esac
  if [ "$kind" = deb ]; then
    for pair in preinst:preinst postinst:postinst prerm:prerm postrm:postrm; do
      dpkg-deb --ctrl-tarfile "$pkg" | tar -xOf - "./${pair%%:*}" | cmp -s - "$dir/deb-${pair##*:}.sh" \
        || die "$pkg: embedded ${pair%%:*} differs from the committed deb-${pair##*:}.sh"
    done
  else
    for pair in PREIN:pre POSTIN:post PREUN:preun POSTUN:postun; do
      rpm -qp --qf "%{${pair%%:*}}" "$pkg" | cmp -s - "$dir/rpm-${pair##*:}.sh" \
        || die "$pkg: embedded ${pair%%:*} differs from the committed rpm-${pair##*:}.sh"
    done
    for tag in PREINPROG POSTINPROG PREUNPROG POSTUNPROG; do
      [ "$(rpm -qp --qf "%{$tag}" "$pkg")" = "/bin/sh" ] || die "$pkg: $tag is not /bin/sh"
    done
  fi
}

# --- scripts: the static maintainer-script rules ---------------------------------------------
# Every command rule matches command position only: line start, or after ; & | ( { ! or one of
# then/do/else/if/elif/while/until. A case label such as `install)` is not a command.
CMD='(^|[;&|({]|(^|[[:space:]])(then|do|else|if|elif|while|until)|[[:space:]]!)[[:space:]]*'

# code_lines <file>: the file without whole-line comments.
code_lines() { grep -Ev '^[[:space:]]*#' "$1" || true; }

# shared_block <file> <name>: the lines from BEGIN to END, inclusive.
shared_block() {
  awk -v n="$2" '
    $0 ~ "^[[:space:]]*# BEGIN shared: " n "$" { on = 1 }
    on { print }
    on && /^[[:space:]]*# END shared$/ { on = 0 }
  ' "$1"
}

check_script() {
  local f="$1" code hits
  [ "$(head -n 1 "$f")" = '#!/bin/sh' ] || die "$f: first line is not #!/bin/sh"
  grep -qx 'set -eu' "$f" || die "$f: missing set -eu"
  code="$(code_lines "$f")"

  hits="$(printf '%s\n' "$code" | grep -En "${CMD}systemctl([[:space:]]|\$)" || true)"
  if [ -n "$hits" ]; then
    printf '%s\n' "$hits" | grep -Eq "${CMD}/[^[:space:]]*systemctl" && die "$f: systemctl is called by an absolute path"
    while IFS= read -r line; do
      verb="$(printf '%s\n' "$line" | sed -E 's/.*systemctl[[:space:]]+(-[^[:space:]]+[[:space:]]+)*([^[:space:];&|)]+).*/\2/')"
      case "$verb" in
        daemon-reload | preset | stop | disable) ;;
        *) die "$f: systemctl $verb is not allowed (only daemon-reload, preset, stop, disable): $line" ;;
      esac
    done <<<"$hits"
  fi
  printf '%s\n' "$code" | grep -Eq '(^|[[:space:]])--now([[:space:]]|$)' && die "$f: --now is not allowed"
  printf '%s\n' "$code" | grep -Eq "${CMD}/[^[:space:]]*systemctl" && die "$f: systemctl is called by an absolute path"

  printf '%s\n' "$code" | grep -Eq "${CMD}(rm|rmdir)[[:space:]][^;&|]*[\$]" && die "$f: an rm or rmdir argument contains a variable expansion"
  printf '%s\n' "$code" | grep -Eq "${CMD}(chmod|chown|install)([[:space:]]|\$)" && die "$f: chmod, chown and install are not allowed"

  hits="$(printf '%s\n' "$code" | sed -e 's/\${1:-}//g' -e 's/\${2:-}//g' | grep -E '\$[0-9@*#]|\$\{[0-9@*#]' || true)"
  [ -z "$hits" ] || die "$f: positional parameters may only be read as \${1:-} or \${2:-}: $hits"

  hits="$(printf '%s\n' "$code" | grep -oE '(^|[^[:alnum:]_.$/-])/[A-Za-z][A-Za-z0-9._/-]*' | sed -E 's/^[^/]*//' || true)"
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    case "$p" in
      /etc/relay-daemon* | /var/lib/relay-daemon* | /usr/share/relay-daemon* | /run/systemd/system*) ;;
      *) die "$f: absolute path $p is outside the allowed prefixes" ;;
    esac
  done <<<"$hits"
}

cmd_scripts() {
  [ "$#" -eq 1 ] || die "usage: scripts <dir>"
  local dir="$1" f n deb rpm a b
  [ -d "$dir" ] || die "no such directory: $dir"
  for f in deb-preinst deb-postinst deb-prerm deb-postrm rpm-pre rpm-post rpm-preun rpm-postun; do
    [ -f "$dir/$f.sh" ] || die "missing $dir/$f.sh"
    check_script "$dir/$f.sh"
  done
  for pair in observe:deb-preinst:rpm-pre first-install:deb-postinst:rpm-post created-flags:deb-postrm:rpm-postun; do
    n="${pair%%:*}"; deb="${pair#*:}"; rpm="${deb#*:}"; deb="${deb%%:*}"
    a="$(shared_block "$dir/$deb.sh" "$n")"
    b="$(shared_block "$dir/$rpm.sh" "$n")"
    [ -n "$a" ] || die "$deb.sh has no shared block '$n'"
    [ -n "$b" ] || die "$rpm.sh has no shared block '$n'"
    [ "$a" = "$b" ] || die "shared block '$n' differs between $deb.sh and $rpm.sh"
  done
}

# --- release ----------------------------------------------------------------------------------
only_one() { # <dir> <glob>: print the single match, or die
  local dir="$1" pat="$2" m
  m="$(cd "$dir" && compgen -G "$pat" || true)"
  [ -n "$m" ] || die "no file matching $pat in $dir"
  [ "$(printf '%s\n' "$m" | wc -l)" = 1 ] || die "more than one file matches $pat in $dir: $(printf '%s ' $m)"
  printf '%s/%s\n' "$dir" "$m"
}

cmd_release() {
  [ "$#" -eq 4 ] || die "usage: release <dist> <version> <scripts-dir> <catalog-file>"
  local dist="$1" version="$2" scripts="$3" catalog="$4"
  local rpm_arch deb_arch deb rpm bin f pair line
  [ -d "$dist" ] || die "no such directory: $dist"
  [ -f "$dist/SHA256SUMS" ] || die "$dist/SHA256SUMS is missing"
  [ -f "$dist/relay-daemon.service" ] || die "$dist/relay-daemon.service is missing"
  [ -f "$dist/relay-daemon.env.example" ] || die "$dist/relay-daemon.env.example is missing"
  local -a pkgs=()
  for pair in x86_64:amd64 aarch64:arm64; do
    rpm_arch="${pair%%:*}"; deb_arch="${pair##*:}"
    deb="$(only_one "$dist" "relay-daemon_*_${deb_arch}.deb")"
    rpm="$(only_one "$dist" "relay-daemon-*.${rpm_arch}.rpm")"
    bin="$dist/relay-daemon-${version}-${rpm_arch}-unknown-linux-musl"
    [ -f "$bin" ] || die "no release binary $bin"
    for f in "$deb" "$rpm"; do
      cmd_payload "$f" /usr/bin/relay-daemon "$bin"
      cmd_maintscripts "$f" "$scripts"
      cmd_payload "$f" /usr/lib/systemd/system/relay-daemon.service "$dist/relay-daemon.service"
      cmd_payload "$f" /usr/share/relay-daemon/relay-daemon.env.example "$dist/relay-daemon.env.example"
      pkgs+=("$f")
    done
  done
  deb="$(only_one "$dist" "relay-read_*_all.deb")"
  rpm="$(only_one "$dist" "relay-read-*.noarch.rpm")"
  for f in "$deb" "$rpm"; do
    cmd_payload "$f" /etc/relay-daemon/templates.d/relay-read/catalog.toml "$catalog"
    cmd_maintscripts "$f" "$scripts"
    pkgs+=("$f")
  done
  [ "$(cd "$dist" && ls -1 -- *.deb | wc -l)" = 3 ] || die "$dist holds a .deb other than the three expected"
  [ "$(cd "$dist" && ls -1 -- *.rpm | wc -l)" = 3 ] || die "$dist holds an .rpm other than the three expected"
  for f in "${pkgs[@]}"; do
    [ -z "$(cmd_conffiles "$f")" ] || die "$f marks configuration files; the packages have none"
  done

  local sums; sums="$(mktemp)" || die "mktemp failed"
  # shellcheck disable=SC2064
  trap "rm -f '$sums'" RETURN
  for f in "${pkgs[@]}" "$dist/relay-daemon.service" "$dist/relay-daemon.env.example"; do
    f="$(basename "$f")"
    line="$(awk -v f="$f" 'length($1) == 64 && $1 ~ /^[0-9a-f]+$/ && $2 == f' "$dist/SHA256SUMS")"
    [ -n "$line" ] && [ "$(printf '%s\n' "$line" | wc -l)" = 1 ] || die "$dist/SHA256SUMS has not exactly one line for $f"
    printf '%s\n' "$line" >>"$sums"
  done
  (cd "$dist" && sha256sum --check --strict --quiet "$sums") || die "sha256sum --check failed for the packages, unit or example"
  echo "package-guard: packages, unit and example verified for $version"
}

[ "$#" -ge 1 ] || die "usage: $0 list|conffiles|payload|maintscripts|scripts|release ..."
sub="$1"; shift
case "$sub" in
  list) cmd_list "$@" ;;
  conffiles) cmd_conffiles "$@" ;;
  payload) cmd_payload "$@" ;;
  maintscripts) cmd_maintscripts "$@" ;;
  scripts) cmd_scripts "$@" ;;
  release) cmd_release "$@" ;;
  *) die "unknown subcommand '$sub'" ;;
esac
