#!/usr/bin/env bash
# Proves the relay-daemon maintainer scripts behave as the package promises: first install,
# upgrade, remove, purge and erase, under both the dpkg and the rpm argument conventions.
# Hermetic: bash, sh, sed, grep, find, stat and coreutils; no root, no packages, no network.
#
# Each script runs under `sh` (dash on Debian and Ubuntu, so a bashism fails) from a copy whose
# four literal path prefixes are rewritten into a fake root under `mktemp -d`, with a fake
# `systemctl` first on PATH. The committed scripts keep their literal paths. After the rewrite
# the copy is checked for any absolute path left outside the fake root, so an unrelocated path
# fails the test and never reaches the host.
#
# NOT `set -e`: every case must run and be reported, not stop at the first failure.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
SCRIPTS="$REPO_ROOT/daemon/packaging/nfpm/scripts"
WORKDIR="$(mktemp -d)" || { echo "FAIL: mktemp -d failed" >&2; exit 1; }
trap 'case "${WORKDIR:-}" in /*) rm -rf "$WORKDIR" ;; esac' EXIT
case "$WORKDIR" in
  /*) ;;
  *) echo "FAIL: mktemp returned a non-absolute path: '$WORKDIR'" >&2; exit 1 ;;
esac

fail=0
n=0
cur_fail=""
UMASK=022
FAKE_FAIL=""

# --- the fake root ---------------------------------------------------------------------------

R=""
MARK=""
new_root() { # systemd present|absent
  R="$(mktemp -d "$WORKDIR/root.XXXXXX")"
  case "$R" in
    *'|'* | *'&'* | *'\'*) echo "FAIL: fake root '$R' has a character special to sed" >&2; exit 1 ;;
  esac
  MARK="$R/var/lib/relay-daemon-package"
  mkdir -p "$R/s" "$R/bin" "$R/var/lib" "$R/etc" "$R/usr/share/relay-daemon"
  cp "$REPO_ROOT/daemon/policy.default.toml" "$REPO_ROOT/daemon/packaging/relay-daemon.env.example" \
    "$R/usr/share/relay-daemon/"
  chmod 0644 "$R"/usr/share/relay-daemon/*
  [ "${1:-absent}" = present ] && mkdir -p "$R/run/systemd/system"
  : >"$R/systemctl.log"; : >"$R/systemctl.all"; : >"$R/stdout"; : >"$R/stderr"
  cat >"$R/bin/systemctl" <<FAKE
#!/bin/sh
echo "\$*" >> "$R/systemctl.log"
echo "\$*" >> "$R/systemctl.all"
[ -z "\${FAKE_SYSTEMCTL_FAIL:-}" ] || exit 1
exit 0
FAKE
  chmod +x "$R/bin/systemctl"
  local f
  for f in "$SCRIPTS"/*.sh; do
    sed -e "s|/etc/relay-daemon|$R/etc/relay-daemon|g" \
        -e "s|/var/lib/relay-daemon|$R/var/lib/relay-daemon|g" \
        -e "s|/usr/share/relay-daemon|$R/usr/share/relay-daemon|g" \
        -e "s|/run/systemd/system|$R/run/systemd/system|g" "$f" >"$R/s/$(basename "$f")"
    # Any absolute path left once the fake root is masked would act on the host.
    if grep -Ev '^[[:space:]]*#' "$R/s/$(basename "$f")" | sed "s|$R|FAKEROOT|g" \
        | grep -Eq '(^|[^[:alnum:]_.$/-])/[A-Za-z]'; then
      echo "FAIL: $(basename "$f") still names an absolute path outside the fake root after relocation" >&2
      exit 1
    fi
  done
}

# sc <script> [args...]: run one maintainer script in the fake root; sets RC.
sc() {
  local name="$1"; shift
  ( umask "$UMASK"; exec env PATH="$R/bin:$PATH" ${FAKE_FAIL:+FAKE_SYSTEMCTL_FAIL=1} \
      sh "$R/s/$name.sh" "$@" ) >>"$R/stdout" 2>>"$R/stderr"
  RC=$?
}

# must <script> [args...]: sc, and a non-zero exit fails the case.
must() {
  sc "$@"
  [ "$RC" -eq 0 ] || { [ -n "$cur_fail" ] || cur_fail="$* exited $RC: $(tail -n 3 "$R/stderr" | tr '\n' ' ')"; }
}

# --- assertions ------------------------------------------------------------------------------

expect() { # description, test command...
  local d="$1"; shift
  "$@" || { [ -n "$cur_fail" ] || cur_fail="$d"; }
}
mode_is() { [ "$(stat -c %a "$1" 2>/dev/null)" = "${2#0}" ]; }
absent() { [ ! -e "$1" ] && [ ! -L "$1" ]; }
present() { [ -e "$1" ] || [ -L "$1" ]; }
same_file() { cmp -s "$1" "$2"; }
has_text() { [ "$(cat "$1" 2>/dev/null)" = "$2" ]; }
log_is() { [ "$(cat "$R/systemctl.log")" = "$1" ]; }
created_is() { [ "$(sort "$MARK/created" 2>/dev/null)" = "$(printf '%s\n' "$@" | sort)" ]; }
no_line() { ! grep -q "$1" "$2"; }
clear_log() { : >"$R/systemctl.log"; }
empty_dir() { [ -d "$1" ] && [ -z "$(ls -A "$1")" ]; }

# snapshot: the type, mode and content hash of everything the scripts may touch.
snapshot() {
  ( cd "$R" && find etc var other usr run -printf '%y %m %p -> %l\n' 2>/dev/null | sort
    find etc var other -type f -exec sha256sum {} + 2>/dev/null | sort )
}
unchanged() { # snapshot-file: the tree equals the snapshot taken earlier
  [ "$(snapshot)" = "$(cat "$1")" ]
}

# --- sequences, one per argument convention ---------------------------------------------------

first_install() { # deb|rpm
  if [ "$1" = deb ]; then must deb-preinst install; must deb-postinst configure
  else must rpm-pre 1; must rpm-post 1; fi
}
upgrade() {
  if [ "$1" = deb ]; then
    must deb-prerm upgrade 1.0; must deb-preinst upgrade 1.0; must deb-postinst configure 1.0; must deb-postrm upgrade 1.0
  else must rpm-pre 2; must rpm-post 2; must rpm-preun 1; must rpm-postun 1; fi
}
remove() { # remove (deb) or erase (rpm)
  if [ "$1" = deb ]; then must deb-prerm remove; must deb-postrm remove
  else must rpm-preun 0; must rpm-postun 0; fi
}
ETC=""; STATE=""
paths() { ETC="$R/etc/relay-daemon"; STATE="$R/var/lib/relay-daemon"; }

# --- cases -----------------------------------------------------------------------------------

case_first_install_places_everything() { # conv
  local um
  for um in 022 000; do
    UMASK=$um; new_root present; paths
    first_install "$1"
    expect "umask $um: /etc/relay-daemon is not 0755" mode_is "$ETC" 0755
    expect "umask $um: policy.d is not an empty 0755 directory" mode_is "$ETC/policy.d" 0755
    expect "umask $um: policy.d is not empty" empty_dir "$ETC/policy.d"
    expect "umask $um: policy.toml is not 0644" mode_is "$ETC/policy.toml" 0644
    expect "umask $um: policy.toml differs from the reference default" same_file "$ETC/policy.toml" "$R/usr/share/relay-daemon/policy.default.toml"
    expect "umask $um: env file is not 0600" mode_is "$ETC/relay-daemon.env" 0600
    expect "umask $um: env file differs from the example" same_file "$ETC/relay-daemon.env" "$R/usr/share/relay-daemon/relay-daemon.env.example"
    expect "umask $um: state directory is not 0700" mode_is "$STATE" 0700
    expect "umask $um: marker directory is not 0700" mode_is "$MARK" 0700
    expect "umask $um: created is not the five yes lines" created_is made_etc=yes made_policy_dir=yes placed_policy=yes placed_env=yes made_state=yes
    expect "umask $um: the first-install flag is left behind" absent "$MARK/first-install"
    expect "umask $um: systemctl log is not daemon-reload, preset" log_is $'daemon-reload\npreset relay-daemon.service'
  done
  UMASK=022
}

case_first_install_empty_second_argument() { # deb only
  new_root present; paths
  must deb-preinst install; must deb-postinst configure ""
  expect "the policy was not placed" present "$ETC/policy.toml"
  expect "no preset ran" log_is $'daemon-reload\npreset relay-daemon.service'
}

case_first_install_without_systemd_runs_no_systemctl() {
  new_root absent; paths
  first_install "$1"
  expect "systemctl ran without /run/systemd/system" log_is ""
  expect "the policy was not placed" present "$ETC/policy.toml"
  expect "the env file was not placed" present "$ETC/relay-daemon.env"
}

case_preset_failure_does_not_fail_the_install() {
  new_root present; paths
  FAKE_FAIL=1
  first_install "$1"
  FAKE_FAIL=""
  expect "the policy was not placed" present "$ETC/policy.toml"
  expect "the state directory was not created" present "$STATE"
}

case_missing_arguments_are_safe() {
  new_root present; paths
  mkdir -p "$ETC"; mkdir -p "$STATE"
  snapshot >"$R/snap"
  local s
  for s in deb-preinst deb-postinst deb-prerm deb-postrm rpm-pre rpm-post rpm-preun rpm-postun; do
    must "$s"
    must "$s" ""
  done
  must deb-postrm abort-install
  expect "a script with no arguments changed the tree" unchanged "$R/snap"
  expect "a script with no arguments called systemctl" log_is ""
}

case_existing_policy_file_is_never_rewritten_or_purged() {
  new_root present; paths
  mkdir -p "$ETC"; printf 'operator policy\n' >"$ETC/policy.toml"
  first_install "$1"
  expect "policy.toml was rewritten by the first install" has_text "$ETC/policy.toml" "operator policy"
  expect "created records a policy the package did not place" no_line placed_policy "$MARK/created"
  upgrade "$1"
  expect "policy.toml was rewritten by the upgrade" has_text "$ETC/policy.toml" "operator policy"
  : >"$R/stdout"
  remove "$1"
  if [ "$1" = deb ]; then must deb-postrm purge; fi
  expect "policy.toml changed by remove/purge/erase" has_text "$ETC/policy.toml" "operator policy"
  expect "the listing names policy.toml" no_line policy.toml "$R/stdout"
}

case_fragment_composed_policy_is_never_purged() {
  new_root present; paths
  mkdir -p "$ETC/policy.d"; printf 'one\n' >"$ETC/policy.d/10-one.toml"
  first_install "$1"
  expect "the package placed a policy beside existing fragments" absent "$ETC/policy.toml"
  printf 'config management policy\n' >"$ETC/policy.toml"
  printf 'two\n' >"$ETC/policy.d/20-two.toml"
  ( cd "$ETC" && find policy.d policy.toml -printf '%y %m %p\n'; sha256sum policy.toml policy.d/*.toml ) | sort >"$R/policy-before"
  : >"$R/stdout"
  remove "$1"
  if [ "$1" = deb ]; then must deb-postrm purge; fi
  ( cd "$ETC" && find policy.d policy.toml -printf '%y %m %p\n'; sha256sum policy.toml policy.d/*.toml ) 2>&1 | sort >"$R/policy-after"
  expect "policy.toml or policy.d changed by remove/purge/erase" cmp -s "$R/policy-before" "$R/policy-after"
  expect "the listing names policy.toml" no_line policy.toml "$R/stdout"
  expect "the listing names policy.d" no_line policy.d "$R/stdout"
}

case_existing_env_file_is_kept() {
  new_root present; paths
  mkdir -p "$ETC"; printf 'operator env\n' >"$ETC/relay-daemon.env"
  first_install "$1"
  expect "env file was rewritten" has_text "$ETC/relay-daemon.env" "operator env"
  remove "$1"
  if [ "$1" = deb ]; then must deb-postrm purge; fi
  expect "env file did not survive" has_text "$ETC/relay-daemon.env" "operator env"

  new_root present; paths
  mkdir -p "$ETC"; ln -s "$R/nowhere" "$ETC/relay-daemon.env"
  first_install "$1"
  expect "the dangling env symlink was written through" absent "$R/nowhere"
  remove "$1"
  if [ "$1" = deb ]; then must deb-postrm purge; fi
  expect "the dangling env symlink did not survive" test -L "$ETC/relay-daemon.env"
}

case_symlinked_etc_dir_is_never_written_through() {
  new_root present; paths
  mkdir -p "$R/other"; ln -s "$R/other" "$ETC"
  first_install "$1"
  expect "something was placed under the symlink target" empty_dir "$R/other"
  expect "no stderr note about the symlink" grep -q 'placed no Policy' "$R/stderr"
  expect "created records an /etc placement" no_line 'made_etc\|made_policy_dir\|placed_policy\|placed_env' "$MARK/created"
  remove "$1"
  if [ "$1" = deb ]; then must deb-postrm purge; fi
  expect "the symlink target changed" empty_dir "$R/other"
  expect "the symlink did not survive" test -L "$ETC"
}

case_existing_state_dir_is_kept() {
  new_root present; paths
  mkdir -p "$STATE"; printf 'id\n' >"$STATE/key.pem"
  first_install "$1"
  remove "$1"
  if [ "$1" = deb ]; then must deb-postrm purge; fi
  expect "the pre-existing state survived purge" has_text "$STATE/key.pem" "id"
}

case_upgrade_changes_nothing() {
  new_root present; paths
  first_install "$1"
  printf 'edited policy\n' >"$ETC/policy.toml"; printf 'edited env\n' >"$ETC/relay-daemon.env"
  clear_log; snapshot >"$R/snap"
  upgrade "$1"
  expect "the upgrade changed the tree" unchanged "$R/snap"
  expect "the upgrade ran more than daemon-reload" log_is "daemon-reload"
}

case_stale_flag_never_turns_an_upgrade_into_a_preset() {
  new_root present; paths
  first_install "$1"
  touch "$MARK/first-install"; clear_log; snapshot >"$R/snap"
  if [ "$1" = deb ]; then must deb-postinst configure 1.0; else must rpm-post 2; fi
  expect "a stale flag changed the tree" unchanged "$R/snap"
  expect "a stale flag ran preset" no_line preset "$R/systemctl.log"
}

case_remove_stops_disables_and_keeps_everything() {
  new_root present; paths
  first_install "$1"
  clear_log; snapshot >"$R/snap"
  remove "$1"
  expect "remove did not stop, disable, then reload" log_is $'stop relay-daemon.service\ndisable relay-daemon.service\ndaemon-reload'
  expect "remove changed the tree" unchanged "$R/snap"

  new_root absent; paths
  first_install "$1"
  remove "$1"
  expect "without systemd only disable may run" log_is "disable relay-daemon.service"
}

case_purge_removes_only_what_the_package_created() { # deb
  new_root present; paths
  first_install deb
  printf 'frag\n' >"$ETC/policy.d/10-frag.toml"; printf 'id\n' >"$STATE/key.pem"
  remove deb; must deb-postrm purge
  expect "policy.toml survived purge" absent "$ETC/policy.toml"
  expect "env file survived purge" absent "$ETC/relay-daemon.env"
  expect "state directory survived purge" absent "$STATE"
  expect "marker directory survived purge" absent "$MARK"
  expect "an operator fragment was deleted" has_text "$ETC/policy.d/10-frag.toml" "frag"
  expect "no kept message" grep -q kept "$R/stderr"

  new_root present; paths
  first_install deb
  remove deb; must deb-postrm purge
  expect "purge left /etc entries behind" empty_dir "$R/etc"
  expect "purge left the state directory" absent "$STATE"
  expect "purge left the marker directory" absent "$MARK"
}

case_deb_reinstall_from_config_files_keeps_created() { # deb
  new_root present; paths
  first_install deb
  remove deb
  clear_log
  must deb-preinst install 1.0; must deb-postinst configure 1.0
  expect "a reinstall from config-files ran preset" no_line preset "$R/systemctl.log"
  expect "a reinstall from config-files dropped created" created_is made_etc=yes made_policy_dir=yes placed_policy=yes placed_env=yes made_state=yes
  expect "a reinstall from config-files left the first-install flag" absent "$MARK/first-install"
  must deb-prerm remove; must deb-postrm remove; must deb-postrm purge
  expect "purge kept policy.toml the package placed" absent "$ETC/policy.toml"
  expect "purge kept the env file the package placed" absent "$ETC/relay-daemon.env"
  expect "purge kept the state directory the package made" absent "$STATE"
  expect "purge left /etc entries behind" empty_dir "$R/etc"
}

case_deb_purge_never_follows_a_symlink_that_replaced_etc() { # deb
  new_root present; paths
  first_install deb
  remove deb
  mv "$ETC" "$R/moved-etc"
  mkdir -p "$R/other"; printf 'victim policy\n' >"$R/other/policy.toml"; printf 'victim env\n' >"$R/other/relay-daemon.env"
  mkdir "$R/other/policy.d"
  ln -s "$R/other" "$ETC"
  must deb-postrm purge
  expect "purge deleted policy.toml through the symlink" has_text "$R/other/policy.toml" "victim policy"
  expect "purge deleted the env file through the symlink" has_text "$R/other/relay-daemon.env" "victim env"
  expect "purge removed policy.d through the symlink" test -d "$R/other/policy.d"
  expect "the symlink did not survive" test -L "$ETC"
}

case_rpm_erase_deletes_nothing_and_lists_created_paths() { # rpm
  new_root present; paths
  first_install rpm
  snapshot >"$R/snap"; : >"$R/stdout"
  must rpm-preun 0; must rpm-postun 0
  expect "erase changed the tree" unchanged "$R/snap"
  local p
  for p in "$ETC" "$ETC/policy.d" "$ETC/policy.toml" "$ETC/relay-daemon.env" "$STATE" "$MARK"; do
    expect "the listing omits $p" grep -qx "  $p" "$R/stdout"
  done
  expect "the listing has other paths" test "$(grep -c '^  /' "$R/stdout")" -eq 6
}

# --- runner ----------------------------------------------------------------------------------

check_clean_log() { # never start, restart, enable or --now, in any case
  grep -Eq '(^|[[:space:]])(start|restart|try-restart|reload-or-restart|enable)([[:space:]]|$)|--now' "$R/systemctl.all"
}

run_case() { # function convention
  local fn="$1" conv="${2:-}" label
  label="${fn#case_}${conv:+[$conv]}"
  cur_fail=""; FAKE_FAIL=""; UMASK=022
  n=$((n + 1))
  "$fn" ${conv:+"$conv"}
  if check_clean_log; then [ -n "$cur_fail" ] || cur_fail="systemctl was asked to start, restart or enable"; fi
  if [ -n "$cur_fail" ]; then
    fail=$((fail + 1)); echo "FAIL: $label: $cur_fail" >&2
  else
    echo "ok:   $label"
  fi
}

for conv in deb rpm; do
  run_case case_first_install_places_everything "$conv"
  run_case case_first_install_without_systemd_runs_no_systemctl "$conv"
  run_case case_preset_failure_does_not_fail_the_install "$conv"
  run_case case_existing_policy_file_is_never_rewritten_or_purged "$conv"
  run_case case_fragment_composed_policy_is_never_purged "$conv"
  run_case case_existing_env_file_is_kept "$conv"
  run_case case_symlinked_etc_dir_is_never_written_through "$conv"
  run_case case_existing_state_dir_is_kept "$conv"
  run_case case_upgrade_changes_nothing "$conv"
  run_case case_stale_flag_never_turns_an_upgrade_into_a_preset "$conv"
  run_case case_remove_stops_disables_and_keeps_everything "$conv"
done
run_case case_first_install_empty_second_argument
run_case case_missing_arguments_are_safe
run_case case_purge_removes_only_what_the_package_created
run_case case_deb_reinstall_from_config_files_keeps_created
run_case case_deb_purge_never_follows_a_symlink_that_replaced_etc
run_case case_rpm_erase_deletes_nothing_and_lists_created_paths

echo
if [ "$fail" -ne 0 ]; then echo "package-scripts-test: $fail of $n cases FAILED" >&2; exit 1; fi
echo "package-scripts-test: all $n cases passed"
