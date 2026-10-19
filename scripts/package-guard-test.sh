#!/usr/bin/env bash
# Proves scripts/package-daemon.sh and scripts/package-guard.sh: the packages are reproducible,
# hold exactly the declared contents and modes, wrap the release binary and the reviewed
# maintainer scripts untouched, and the release guard refuses what its header says it refuses.
# Hermetic: no network, nothing written outside its own `mktemp -d`. Needs NFPM (the pinned
# binary, from `make test-packages`), dpkg-deb, rpm, rpm2cpio, cpio and tar.
#
# Every refusal case asserts the REASON as well as the exit status, so a fixture that breaks for
# an unrelated reason cannot pass as a proof.
#
# NOT `set -e`: every case must run and be reported, not stop at the first failure.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
BUILD="$REPO_ROOT/scripts/package-daemon.sh"
GUARD="$REPO_ROOT/scripts/package-guard.sh"
SCRIPTS="$REPO_ROOT/daemon/packaging/nfpm/scripts"
CATALOG="$REPO_ROOT/daemon/packaging/templates.d/relay-read/catalog.toml"
: "${NFPM:?NFPM must name the pinned nfpm binary}"

WORKDIR="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORKDIR:-}" in /*) rm -rf "$WORKDIR" ;; esac' EXIT
case "$WORKDIR" in
  /*) ;;
  *) echo "FAIL: mktemp returned a non-absolute path: '$WORKDIR'" >&2; exit 1 ;;
esac

fail=0
n=0
cur_fail=""
EPOCH=1700000000
VER="0.0.9-0.dev+g0123456789ab"
head -c 4096 /dev/urandom >"$WORKDIR/bin-amd64"
head -c 4096 /dev/urandom >"$WORKDIR/bin-arm64"

# fresh prints a new, absent path. It runs in command substitutions, so it keeps no counter.
fresh() { echo "$WORKDIR/d.$RANDOM$RANDOM$RANDOM"; }

# build <outdir> <arch> <epoch> <version> [env assignments...]
build() {
  local out="$1" arch="$2" epoch="$3" ver="$4"; shift 4
  env SOURCE_DATE_EPOCH="$epoch" "$@" bash "$BUILD" --nfpm "$NFPM" --bin "$WORKDIR/bin-$arch" \
    --version "$ver" --arch "$arch" --out "$out" >"$out.log" 2>&1 \
    || { [ -n "$cur_fail" ] || cur_fail="build failed: $(tail -n 3 "$out.log" | tr '\n' ' ')"; return 1; }
}
# pkg <dir> <glob>: the single file matching the glob.
pkg() { ls "$1"/$2 2>/dev/null | head -n 1; }

fail_with() { [ -n "$cur_fail" ] || cur_fail="$1"; }
same_set() { # dirA dirB: every package is byte-identical
  local f
  for f in "$1"/*; do
    cmp -s "$f" "$2/$(basename "$f")" || { fail_with "$(basename "$f") differs between builds"; return 1; }
  done
  [ "$(ls "$1" | wc -l)" = "$(ls "$2" | wc -l)" ] || { fail_with "different package sets"; return 1; }
}
# refuses <reason-regex> <command...>: the command must fail and say why.
refuses() {
  local re="$1" out rc; shift
  out="$("$@" 2>&1)"; rc=$?
  [ "$rc" -ne 0 ] || { fail_with "accepted; wanted a refusal matching /$re/"; return 1; }
  printf '%s' "$out" | grep -Eq "$re" || { fail_with "refused for another reason (wanted /$re/): $(printf '%s' "$out" | tail -n 2 | tr '\n' ' ')"; return 1; }
}
accepts() {
  local out; out="$("$@" 2>&1)" || { fail_with "refused: $(printf '%s' "$out" | tail -n 2 | tr '\n' ' ')"; return 1; }
}

# --- build refusals ---------------------------------------------------------------------------

case_build_refuses_without_epoch() {
  refuses 'SOURCE_DATE_EPOCH is unset' env -u SOURCE_DATE_EPOCH bash "$BUILD" --nfpm "$NFPM" \
    --bin "$WORKDIR/bin-amd64" --version "$VER" --arch amd64 --out "$(fresh)"
}
case_build_refuses_non_numeric_epoch() {
  refuses 'is not a number' env SOURCE_DATE_EPOCH=yesterday bash "$BUILD" --nfpm "$NFPM" \
    --bin "$WORKDIR/bin-amd64" --version "$VER" --arch amd64 --out "$(fresh)"
}
case_build_refuses_dirty_out() {
  local d; d="$(fresh)"; mkdir -p "$d"; touch "$d/stale.deb"
  refuses 'is not empty' env SOURCE_DATE_EPOCH=$EPOCH bash "$BUILD" --nfpm "$NFPM" \
    --bin "$WORKDIR/bin-amd64" --version "$VER" --arch amd64 --out "$d"
}
case_nfpm_refuses_unrendered_manifest() {
  local d; d="$(fresh)"; mkdir -p "$d"
  # From the repo root, so the manifest's relative sources resolve and only the token can refuse.
  refuses 'Parsing time' bash -c 'cd "$1" && shift && exec "$@"' _ "$REPO_ROOT" \
    env RELAY_PKG_VERSION=1.0.0 RELAY_PKG_ARCH=amd64 RELAY_DAEMON_BIN="$WORKDIR/bin-amd64" \
    "$NFPM" pkg -f "$REPO_ROOT/daemon/packaging/nfpm/relay-daemon.yaml" -p deb -t "$d/"
}

# --- reproducibility --------------------------------------------------------------------------

rebuild_differs_by() { # label, env assignments...: a second build with them equals the first
  local a b; a="$(fresh)"; b="$(fresh)"
  build "$a" amd64 $EPOCH "$VER" TZ=UTC LC_ALL=C || return
  build "$b" amd64 $EPOCH "$VER" "$@" || return
  same_set "$a" "$b"
}
case_rebuild_is_byte_identical_across_TZ() { rebuild_differs_by TZ=Pacific/Kiritimati; }
case_rebuild_is_byte_identical_across_locale() {
  local loc=C; locale -a 2>/dev/null | grep -qx 'C.utf8' && loc=C.utf8
  rebuild_differs_by LC_ALL="$loc"
}
case_rebuild_is_byte_identical_across_GOMAXPROCS() { rebuild_differs_by GOMAXPROCS=1; }
case_rebuild_is_byte_identical_across_inputs() {
  # A second copy of everything package-daemon.sh reads, with other mtimes, built under another
  # umask and cwd. The checkout itself is never touched.
  local a b c="$WORKDIR/repo-copy" f; a="$(fresh)"; b="$(fresh)"
  rm -rf "$c"; mkdir -p "$c/scripts" "$c/daemon/packaging"
  cp "$BUILD" "$c/scripts/"
  cp -r "$REPO_ROOT/daemon/packaging/nfpm" "$REPO_ROOT/daemon/packaging/templates.d" \
    "$REPO_ROOT/daemon/packaging/relay-daemon.service" "$REPO_ROOT/daemon/packaging/relay-daemon.env.example" \
    "$c/daemon/packaging/"
  cp "$REPO_ROOT/daemon/policy.default.toml" "$c/daemon/"
  find "$c" -type f -exec touch -d '2001-01-01' {} +
  build "$a" amd64 $EPOCH "$VER" || return
  f="$c/scripts/package-daemon.sh"
  ( umask 077; cd "$WORKDIR" && env SOURCE_DATE_EPOCH=$EPOCH bash "$f" --nfpm "$NFPM" --bin "$WORKDIR/bin-amd64" \
      --version "$VER" --arch amd64 --out "$b" >"$b.log" 2>&1 ) \
    || { fail_with "build from the copy failed: $(tail -n 3 "$b.log" | tr '\n' ' ')"; return; }
  same_set "$a" "$b"
}

case_dev_version_builds_reproducibly() {
  local a b c d v
  a="$(fresh)"; b="$(fresh)"; c="$(fresh)"
  build "$a" amd64 $EPOCH "$VER" && build "$b" amd64 $EPOCH "$VER" && same_set "$a" "$b" || return
  v="$(printf '%s' "$VER" | tr - '~')"
  [ -f "$a/relay-daemon_${v}-1_amd64.deb" ] || fail_with "deb name does not carry the version: $(ls "$a" | tr '\n' ' ')"
  [ "$(dpkg-deb -f "$(pkg "$a" 'relay-daemon_*.deb')" Version)" = "${v}-1" ] || fail_with "deb Version field is not ${v}-1"
  d="$(fresh)"
  build "$c" amd64 $EPOCH "$VER.dirty" && build "$d" amd64 $EPOCH "$VER.dirty" && same_set "$c" "$d" || return
  [ "$(rpm -qp --qf '%{VERSION}' "$(pkg "$c" 'relay-daemon-*.rpm')")" = "${v}.dirty" ] || fail_with "dirty rpm version is not ${v}.dirty"
}

case_relay_read_independent_of_target_arch() {
  local a b; a="$(fresh)"; b="$(fresh)"
  build "$a" amd64 $EPOCH "$VER" && build "$b" arm64 $EPOCH "$VER" || return
  cmp -s "$(pkg "$a" 'relay-read_*.deb')" "$(pkg "$b" 'relay-read_*.deb')" || fail_with "relay-read .deb differs by target arch"
  cmp -s "$(pkg "$a" 'relay-read-*.rpm')" "$(pkg "$b" 'relay-read-*.rpm')" || fail_with "relay-read .rpm differs by target arch"
}

case_epoch_is_what_is_pinned() {
  local a b f bad
  a="$(fresh)"; b="$(fresh)"
  build "$a" amd64 $EPOCH "$VER" TZ=Pacific/Kiritimati || return
  build "$b" amd64 $((EPOCH + 86400)) "$VER" TZ=Pacific/Kiritimati || return
  cmp -s "$(pkg "$a" 'relay-daemon_*.deb')" "$(pkg "$b" 'relay-daemon_*.deb')" && fail_with "a different epoch left the .deb unchanged"
  cmp -s "$(pkg "$a" 'relay-daemon-*.rpm')" "$(pkg "$b" 'relay-daemon-*.rpm')" && fail_with "a different epoch left the .rpm unchanged"
  local want; want="$(date -u -d "@$EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
  for f in "$a"/*; do
    bad="$(TZ=Pacific/Kiritimati bash "$GUARD" list "$f" | awk -v w="$want" '$5 != w')"
    [ -z "$bad" ] || fail_with "$(basename "$f") has an entry not at $want: $bad"
  done
  for f in "$a"/*.rpm; do
    [ "$(rpm -qp --qf '%{BUILDTIME}' "$f")" = "$EPOCH" ] || fail_with "$(basename "$f") BUILDTIME is not the epoch"
    [ "$(rpm -qp --qf '%{BUILDHOST}' "$f")" = relay-release ] || fail_with "$(basename "$f") BUILDHOST is not relay-release"
  done
}

# --- contents ---------------------------------------------------------------------------------

DAEMON_DEB_LIST='d 0755 0 0 /usr
d 0755 0 0 /usr/bin
f 0755 0 0 /usr/bin/relay-daemon
d 0755 0 0 /usr/lib
d 0755 0 0 /usr/lib/systemd
d 0755 0 0 /usr/lib/systemd/system
f 0644 0 0 /usr/lib/systemd/system/relay-daemon.service
d 0755 0 0 /usr/share
d 0755 0 0 /usr/share/relay-daemon
f 0644 0 0 /usr/share/relay-daemon/policy.default.toml
f 0644 0 0 /usr/share/relay-daemon/relay-daemon.env.example'
DAEMON_RPM_LIST='f 0755 0 0 /usr/bin/relay-daemon
f 0644 0 0 /usr/lib/systemd/system/relay-daemon.service
f 0644 0 0 /usr/share/relay-daemon/policy.default.toml
f 0644 0 0 /usr/share/relay-daemon/relay-daemon.env.example'

case_daemon_layout_exact() {
  local a f got want; a="$(fresh)"
  build "$a" amd64 $EPOCH "$VER" || return
  for f in "$a"/relay-daemon*; do
    case "$f" in *.deb) want="$DAEMON_DEB_LIST" ;; *) want="$DAEMON_RPM_LIST" ;; esac
    got="$(bash "$GUARD" list "$f" | awk '{print $1, $2, $3, $4, $6}')"
    [ "$got" = "$want" ] || fail_with "$(basename "$f") layout differs: $got"
    printf '%s\n' "$got" | grep -Eq ' /(etc|var)(/|$)' && fail_with "$(basename "$f") has an /etc or /var entry"
    [ -z "$(bash "$GUARD" conffiles "$f")" ] || fail_with "$(basename "$f") has configuration files"
  done
  bash "$GUARD" payload "$(pkg "$a" 'relay-daemon_*.deb')" /usr/share/relay-daemon/policy.default.toml "$REPO_ROOT/daemon/policy.default.toml" \
    || fail_with "the packaged reference Policy is not the checkout's"
}

case_catalog_layout_exact() {
  local a f got want_file='f 0644 0 0 /etc/relay-daemon/templates.d/relay-read/catalog.toml' want_deb; a="$(fresh)"
  want_deb='d 0755 0 0 /etc
d 0755 0 0 /etc/relay-daemon
d 0755 0 0 /etc/relay-daemon/templates.d
d 0755 0 0 /etc/relay-daemon/templates.d/relay-read
'"$want_file"
  build "$a" amd64 $EPOCH "$VER" || return
  for f in "$a"/relay-read*; do
    got="$(bash "$GUARD" list "$f" | awk '$1 == "f" {print $1, $2, $3, $4, $6}')"
    [ "$got" = "$want_file" ] || fail_with "$(basename "$f") layout differs: $got"
    [ "$(bash "$GUARD" list "$f" | grep -c '^[^fd] ')" = 0 ] || fail_with "$(basename "$f") has a non-file entry"
    case "$f" in
      *.deb)
        got="$(bash "$GUARD" list "$f" | awk '{print $1, $2, $3, $4, $6}')"
        [ "$got" = "$want_deb" ] || fail_with "$(basename "$f") full listing differs: $got"
        ;;
    esac
    bash "$GUARD" payload "$f" /etc/relay-daemon/templates.d/relay-read/catalog.toml "$CATALOG" || fail_with "$(basename "$f") catalog differs"
    [ -z "$(bash "$GUARD" conffiles "$f")" ] || fail_with "$(basename "$f") has configuration files"
    bash "$GUARD" maintscripts "$f" "$SCRIPTS" || fail_with "$(basename "$f") has maintainer scripts"
  done
  dpkg-deb -f "$(pkg "$a" 'relay-read_*.deb')" Depends | grep -qx 'relay-daemon' || fail_with "deb does not depend on relay-daemon"
  dpkg-deb -f "$(pkg "$a" 'relay-read_*.deb')" Architecture | grep -qx all || fail_with "deb is not arch all"
  rpm -qpR "$(pkg "$a" 'relay-read-*.rpm')" | grep -qx 'relay-daemon' || fail_with "rpm does not require relay-daemon"
  rpm -qp --qf '%{ARCH}' "$(pkg "$a" 'relay-read-*.rpm')" | grep -qx noarch || fail_with "rpm is not noarch"
}

# --- payload and embedded scripts -------------------------------------------------------------

BUILT=""
built() { # build once, share
  if [ -z "$BUILT" ]; then BUILT="$(fresh)"; build "$BUILT" amd64 $EPOCH "$VER" || { BUILT=""; return 1; }; fi
}
case_payload_equal() {
  built || return
  accepts bash "$GUARD" payload "$(pkg "$BUILT" 'relay-daemon_*.deb')" /usr/bin/relay-daemon "$WORKDIR/bin-amd64"
  accepts bash "$GUARD" payload "$(pkg "$BUILT" 'relay-daemon-*.rpm')" /usr/bin/relay-daemon "$WORKDIR/bin-amd64"
}
case_payload_refuses_a_different_binary() {
  built || return
  refuses 'differs from' bash "$GUARD" payload "$(pkg "$BUILT" 'relay-daemon_*.deb')" /usr/bin/relay-daemon "$WORKDIR/bin-arm64"
  refuses 'differs from' bash "$GUARD" payload "$(pkg "$BUILT" 'relay-daemon-*.rpm')" /usr/bin/relay-daemon "$WORKDIR/bin-arm64"
}
case_payload_refuses_missing_member() {
  built || return
  refuses 'exactly 1' bash "$GUARD" payload "$(pkg "$BUILT" 'relay-daemon_*.deb')" /usr/bin/absent "$WORKDIR/bin-amd64"
  refuses 'is not a regular file' bash "$GUARD" payload "$(pkg "$BUILT" 'relay-daemon_*.deb')" /usr/bin "$WORKDIR/bin-amd64"
}
case_maintscripts_equal_the_committed_sources() {
  built || return
  accepts bash "$GUARD" maintscripts "$(pkg "$BUILT" 'relay-daemon_*.deb')" "$SCRIPTS"
  accepts bash "$GUARD" maintscripts "$(pkg "$BUILT" 'relay-daemon-*.rpm')" "$SCRIPTS"
}
case_maintscripts_refuse_a_changed_script() {
  built || return
  local d="$WORKDIR/changed-scripts"; rm -rf "$d"; cp -r "$SCRIPTS" "$d"
  echo '# changed' >>"$d/deb-postinst.sh"; echo '# changed' >>"$d/rpm-postun.sh"
  refuses 'embedded postinst differs' bash "$GUARD" maintscripts "$(pkg "$BUILT" 'relay-daemon_*.deb')" "$d"
  refuses 'embedded POSTUN differs' bash "$GUARD" maintscripts "$(pkg "$BUILT" 'relay-daemon-*.rpm')" "$d"
}

# deb_with_member <deb> <member>: a copy of the .deb whose control archive also holds <member>.
deb_with_member() {
  local src="$1" member="$2" t out; t="$(fresh)"; out="$t.deb"
  dpkg-deb -R "$src" "$t" && printf '#!/bin/sh\ntrue\n' >"$t/DEBIAN/$member" && chmod 0755 "$t/DEBIAN/$member" \
    && dpkg-deb --root-owner-group -b "$t" "$out" >/dev/null 2>&1 || return 1
  echo "$out"
}
deb_hook_case() { # member package-glob
  built || return
  local f; f="$(deb_with_member "$(pkg "$BUILT" "$2")" "$1")" || { fail_with "could not repack the .deb"; return; }
  refuses 'control members are' bash "$GUARD" maintscripts "$f" "$SCRIPTS"
}
case_maintscripts_refuse_a_deb_config_script() { deb_hook_case config 'relay-daemon_*.deb'; }
case_maintscripts_refuse_a_deb_triggers_member() { deb_hook_case triggers 'relay-daemon_*.deb'; }
case_maintscripts_refuse_a_deb_templates_member() { deb_hook_case templates 'relay-daemon_*.deb'; }
case_maintscripts_refuse_a_deb_member_in_relay_read() { deb_hook_case config 'relay-read_*.deb'; }

# rpm_with_hook <nfpm-rpm-script-key>: a relay-daemon .rpm built from the manifest with one more
# rpm script hook; prints its path.
rpm_with_hook() {
  local key="$1" m="$WORKDIR/hook-$1.yaml" o; o="$(fresh)"; mkdir -p "$o"
  sed -e "s|@SOURCE_DATE_EPOCH@|2023-11-14T22:13:20Z|" \
      -e "s|^  buildhost: relay-release\$|&\n  scripts:\n    $key: daemon/packaging/nfpm/scripts/rpm-pre.sh|" \
      "$REPO_ROOT/daemon/packaging/nfpm/relay-daemon.yaml" >"$m"
  grep -q "^ *$key:" "$m" || return 1
  ( cd "$REPO_ROOT" && env RELAY_PKG_VERSION=1.0.0 RELAY_PKG_ARCH=amd64 RELAY_DAEMON_BIN="$WORKDIR/bin-amd64" \
      SOURCE_DATE_EPOCH=$EPOCH "$NFPM" pkg -f "$m" -p rpm -t "$o/" >/dev/null 2>&1 ) || return 1
  pkg "$o" '*.rpm'
}
rpm_hook_case() { # nfpm-key TAG
  local f; f="$(rpm_with_hook "$1")" || { fail_with "could not build an .rpm with a $1 hook"; return; }
  [ "$(rpm -qp --qf "%{$2}" "$f")" != "(none)" ] || { fail_with "the fixture .rpm has no $2 hook"; return; }
  refuses "embeds a $2 hook" bash "$GUARD" maintscripts "$f" "$SCRIPTS"
}
case_maintscripts_refuse_an_rpm_pretrans() { rpm_hook_case pretrans PRETRANS; }
case_maintscripts_refuse_an_rpm_posttrans() { rpm_hook_case posttrans POSTTRANS; }
case_maintscripts_refuse_an_rpm_verify_script() { rpm_hook_case verify VERIFYSCRIPT; }
# nfpm cannot write rpm triggers, so a rpm wrapper reports one for the real package.
rpm_trigger_case() { # TAG
  built || return
  local shim; shim="$(fresh)"; mkdir -p "$shim"
  printf '#!/bin/sh\ncase "$*" in *"%%{%s}"*) printf "trigger body"; exit 0 ;; esac\nexec %s "$@"\n' "$1" "$(command -v rpm)" >"$shim/rpm"
  chmod +x "$shim/rpm"
  refuses "embeds a $1 hook" env PATH="$shim:$PATH" bash "$GUARD" maintscripts "$(pkg "$BUILT" 'relay-daemon-*.rpm')" "$SCRIPTS"
}
case_maintscripts_refuse_an_rpm_trigger_script() { rpm_trigger_case TRIGGERSCRIPTS; }
case_maintscripts_refuse_an_rpm_file_trigger_script() { rpm_trigger_case FILETRIGGERSCRIPTS; }

# --- the release guard ------------------------------------------------------------------------

AMD="" ARM="" DIST=""
mk_dist() { # sets DIST to a fresh dist directory that the guard accepts
  local d; d="$(fresh)"
  if [ -z "$AMD" ]; then
    AMD="$(fresh)"; ARM="$(fresh)"
    build "$AMD" amd64 $EPOCH "$VER" && build "$ARM" arm64 $EPOCH "$VER" || { AMD=""; return 1; }
  fi
  mkdir -p "$d"
  cp "$AMD"/* "$d/"
  cp "$ARM"/relay-daemon* "$d/" # relay-read is arch-independent: one copy
  cp "$WORKDIR/bin-amd64" "$d/relay-daemon-$VER-x86_64-unknown-linux-musl"
  cp "$WORKDIR/bin-arm64" "$d/relay-daemon-$VER-aarch64-unknown-linux-musl"
  cp "$REPO_ROOT/daemon/packaging/relay-daemon.service" "$REPO_ROOT/daemon/packaging/relay-daemon.env.example" "$d/"
  sums "$d"
  DIST="$d"
}
sums() { ( cd "$1" && sha256sum relay-* >SHA256SUMS ); }
release() { bash "$GUARD" release "$1" "$VER" "${2:-$SCRIPTS}" "${3:-$CATALOG}"; }

case_release_guard_accepts_a_good_dist() {
  local d; mk_dist || return; d="$DIST"
  accepts release "$d"
}
case_release_guard_refuses_a_package_missing_from_SHA256SUMS() {
  local d f; mk_dist || return; d="$DIST"
  f="$(cd "$d" && ls relay-daemon_*_amd64.deb)"
  grep -v " $f\$" "$d/SHA256SUMS" >"$d/S" && mv "$d/S" "$d/SHA256SUMS"
  refuses "not exactly one line for relay-daemon_" release "$d"
}
case_release_guard_refuses_a_package_of_another_version() {
  local d other="0.0.8-0.dev+g0123456789ab" arch; mk_dist || return; d="$DIST"
  for arch in x86_64 aarch64; do
    mv "$d/relay-daemon-$VER-$arch-unknown-linux-musl" "$d/relay-daemon-$other-$arch-unknown-linux-musl"
  done
  sums "$d"
  refuses 'has Version' bash "$GUARD" release "$d" "$other" "$SCRIPTS" "$CATALOG"
}
case_release_guard_refuses_a_different_env_example() {
  local d; mk_dist || return; d="$DIST"
  echo '# tampered' >>"$d/relay-daemon.env.example"; sums "$d"
  refuses 'relay-daemon.env.example differs' release "$d"
}
case_release_guard_refuses_a_different_unit() {
  local d; mk_dist || return; d="$DIST"
  echo '# tampered' >>"$d/relay-daemon.service"; sums "$d"
  refuses 'relay-daemon.service differs' release "$d"
}
case_release_guard_refuses_a_different_release_binary() {
  local d; mk_dist || return; d="$DIST"
  echo x >>"$d/relay-daemon-$VER-aarch64-unknown-linux-musl"; sums "$d"
  refuses '/usr/bin/relay-daemon differs' release "$d"
}
case_release_guard_refuses_a_changed_committed_script() {
  local d s; mk_dist || return; d="$DIST"
  s="$WORKDIR/rel-scripts"; rm -rf "$s"; cp -r "$SCRIPTS" "$s"; echo '# changed' >>"$s/deb-preinst.sh"
  refuses 'embedded preinst differs' release "$d" "$s"
}
case_release_guard_refuses_a_different_catalog() {
  local d; mk_dist || return; d="$DIST"
  echo '# changed' >"$WORKDIR/other-catalog.toml"
  refuses 'catalog.toml differs' release "$d" "$SCRIPTS" "$WORKDIR/other-catalog.toml"
}

# --- the static script check ------------------------------------------------------------------

scripts_variant() { # file, sed-script: a copy of the scripts with one edit; prints the directory
  local d; d="$(fresh)"; cp -r "$SCRIPTS" "$d"
  sed -i -e "$2" "$d/$1"
  echo "$d"
}
case_scripts_check_accepts_the_real_scripts() { accepts bash "$GUARD" scripts "$SCRIPTS"; }
inject() { # name reason file line
  local d; d="$(scripts_variant "$3" "/^set -eu\$/a $4")"
  refuses "$2" bash "$GUARD" scripts "$d"
}
case_scripts_check_refuses_systemctl_start() { inject x 'systemctl start is not allowed' deb-prerm.sh '    systemctl start relay-daemon.service'; }
case_scripts_check_refuses_systemctl_restart() { inject x 'systemctl restart is not allowed' deb-postinst.sh 'systemctl restart relay-daemon.service'; }
case_scripts_check_refuses_systemctl_enable_now() { inject x 'systemctl enable is not allowed' rpm-post.sh 'systemctl enable --now relay-daemon.service'; }
case_scripts_check_refuses_an_absolute_systemctl() { inject x 'absolute path' rpm-preun.sh '/usr/bin/systemctl stop relay-daemon.service'; }
case_scripts_check_refuses_rm_with_a_variable() { inject x 'variable expansion' deb-postrm.sh 'rm -rf "$x"'; }
case_scripts_check_refuses_chmod() { inject x 'chmod, chown and install' rpm-pre.sh 'chmod 0600 /etc/relay-daemon/relay-daemon.env'; }
case_scripts_check_refuses_install_in_command_position() { inject x 'chmod, chown and install' rpm-pre.sh 'install -m 0600 /etc/relay-daemon/a /etc/relay-daemon/b'; }
case_scripts_check_refuses_a_bare_second_argument() { inject x 'positional parameters' deb-postinst.sh 'echo "$2"'; }
case_scripts_check_refuses_a_bare_first_argument() { inject x 'positional parameters' deb-prerm.sh 'echo $1'; }
case_scripts_check_refuses_a_path_outside_the_prefixes() { inject x 'outside the allowed prefixes' deb-prerm.sh 'cat /etc/passwd'; }
case_scripts_check_refuses_dev_null() { inject x 'outside the allowed prefixes' deb-prerm.sh 'true 2>/dev/null'; }
case_scripts_check_refuses_a_missing_set_eu() {
  local d; d="$(scripts_variant rpm-pre.sh '/^set -eu$/d')"
  refuses 'missing set -eu' bash "$GUARD" scripts "$d"
}
case_scripts_check_refuses_a_diverged_shared_block() {
  local d; d="$(scripts_variant rpm-pre.sh 's/mkdir \/var/mkdir -p \/var/')"
  refuses "shared block 'observe' differs" bash "$GUARD" scripts "$d"
}

# --- runner -----------------------------------------------------------------------------------

run_case() {
  local fn="$1"
  cur_fail=""
  n=$((n + 1))
  "$fn"
  if [ -n "$cur_fail" ]; then
    fail=$((fail + 1)); echo "FAIL: ${fn#case_}: $cur_fail" >&2
  else
    echo "ok:   ${fn#case_}"
  fi
}

while IFS= read -r fn; do
  run_case "$fn"
done < <(declare -F | awk '{print $3}' | grep '^case_')

echo
if [ "$fail" -ne 0 ]; then echo "package-guard-test: $fail of $n cases FAILED" >&2; exit 1; fi
echo "package-guard-test: all $n cases passed"
