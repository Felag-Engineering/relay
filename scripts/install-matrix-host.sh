#!/usr/bin/env bash
# Drives one install-matrix row from the CI runner: builds the platform's image, boots it as a
# systemd-as-PID-1 container and runs scripts/install-matrix-row.sh phase by phase inside it
# (docs/specs/daemon-installation.md DI-33).
#
#   install-matrix-host.sh <platform-id> <deb|rpm> <privileged: true|false> <fips: true|false> <pkgdir>
#   install-matrix-host.sh --no-systemd debian-13 deb <pkgdir>
#
# <pkgdir> is absolute and holds old/, new/ and VERSION as the workflow's build job lays them
# out; it is mounted read-only at /pkgs. The container is the one place a reboot ("after a
# systemd restart") can be done from, which is why the phases are driven from here.
#
# `--privileged` is added only for a row whose workflow entry says so, and the step summary
# records yes or no for every row, so a row that needed it is visible. The no-systemd row runs
# the same image with `sleep infinity` as PID 1 and installs the packages where systemd is not
# running.
#
# The container is always removed. On failure the journal, the failed units, the phase logs
# and the container's own log are printed; the secrets in the row's state directory (the admin
# password and API Token) are never printed.
set -euo pipefail

NAME=relay-matrix
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  echo "usage: $0 <platform-id> <deb|rpm> <true|false> <true|false> <pkgdir>" >&2
  echo "       $0 --no-systemd debian-13 deb <pkgdir>" >&2
  exit 2
}

NO_SYSTEMD=no
if [ "${1:-}" = --no-systemd ]; then
  [ "$#" -eq 4 ] || usage
  NO_SYSTEMD=yes
  ID=$2 FAMILY=$3 PKGDIR=$4 PRIVILEGED=false FIPS=false
else
  [ "$#" -eq 5 ] || usage
  ID=$1 FAMILY=$2 PRIVILEGED=$3 FIPS=$4 PKGDIR=$5
fi

[[ $ID =~ ^[a-z0-9.-]+$ ]] || { echo "install-matrix-host: bad platform id '$ID'" >&2; exit 2; }
[ -f "$REPO/docker/install-matrix/$ID.Dockerfile" ] \
  || { echo "install-matrix-host: no docker/install-matrix/$ID.Dockerfile" >&2; exit 2; }
case "$FAMILY" in deb | rpm) ;; *) echo "install-matrix-host: family must be deb or rpm" >&2; exit 2 ;; esac
case "$PRIVILEGED" in true | false) ;; *) echo "install-matrix-host: privileged must be true or false" >&2; exit 2 ;; esac
case "$FIPS" in true | false) ;; *) echo "install-matrix-host: fips must be true or false" >&2; exit 2 ;; esac
case "$PKGDIR" in /*) ;; *) echo "install-matrix-host: pkgdir must be absolute" >&2; exit 2 ;; esac
[ -f "$PKGDIR/VERSION" ] || { echo "install-matrix-host: no $PKGDIR/VERSION" >&2; exit 2; }

IMAGE="relay-install-matrix:$ID"
ARCH="$(uname -m)"

in_container() { docker exec "$NAME" "$@"; }

phase() {
  echo "::group::$ID $ARCH: phase $1"
  local rc=0
  docker exec -e "ROW_FAMILY=$FAMILY" "$NAME" bash /usr/local/sbin/install-matrix-row "$1" || rc=$?
  echo "::endgroup::"
  return "$rc"
}

# wait_boot: systemd reaches `running` or `degraded`. Any other state, or no answer in time,
# fails with diagnostics (the EXIT trap prints them) within about five minutes, well inside the
# job's timeout.
wait_boot() {
  local state="" deadline=$((SECONDS + 240))
  while ((SECONDS < deadline)); do
    state="$(docker exec "$NAME" timeout 60 systemctl is-system-running --wait 2>&1 || true)"
    case "$state" in
      running) return 0 ;;
      degraded)
        echo "systemd is degraded; failed units:"
        in_container systemctl --failed --no-pager || true
        return 0
        ;;
    esac
    sleep 3
  done
  echo "install-matrix-host: systemd never reached running or degraded (last answer: $state)" >&2
  return 1
}

# diagnostics: everything a failure needs, and none of the row's secret files.
diagnostics() {
  echo "::group::diagnostics for $ID $ARCH"
  in_container systemctl --failed --no-pager || true
  in_container journalctl --no-pager -b -n 300 || true
  in_container bash -c 'for f in /root/install-matrix/*.log; do [ -f "$f" ] && { echo "--- $f"; cat "$f"; }; done' || true
  docker logs "$NAME" 2>&1 | tail -n 100 || true
  echo "::endgroup::"
}

write_summary() {
  local result=$1
  [ -n "${GITHUB_STEP_SUMMARY:-}" ] || return 0
  local yes_no=no
  if [ "$PRIVILEGED" = true ]; then yes_no=yes; fi
  {
    echo "### Install matrix: $ID on $ARCH"
    echo
    echo "| platform | arch | privileged | result |"
    echo "|---|---|---|---|"
    echo "| $ID | $ARCH | $yes_no | $result |"
    echo
    in_container cat /root/install-matrix/summary 2>/dev/null | sed 's/^/- /' || true
    echo
  } >>"$GITHUB_STEP_SUMMARY"
}

on_exit() {
  local rc=$?
  trap - EXIT
  set +e
  local result=pass
  if [ "$rc" -ne 0 ]; then
    result=FAIL
    diagnostics
  fi
  write_summary "$result"
  docker rm -f "$NAME" >/dev/null 2>&1
  exit "$rc"
}
trap on_exit EXIT

docker build --pull -t "$IMAGE" -f "$REPO/docker/install-matrix/$ID.Dockerfile" "$REPO/docker/install-matrix"

run_args=(run -d --name "$NAME" --hostname relay-matrix.test --cgroupns=host
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock
  -v "$PKGDIR:/pkgs:ro"
  -v "$REPO/scripts/install-matrix-row.sh:/usr/local/sbin/install-matrix-row:ro")
if [ "$PRIVILEGED" = true ]; then run_args+=(--privileged); fi
run_args+=("$IMAGE")
if [ "$NO_SYSTEMD" = yes ]; then run_args+=(sleep infinity); fi
docker "${run_args[@]}"

if [ "$NO_SYSTEMD" = yes ]; then
  phase no-systemd
  exit 0
fi

wait_boot
phase install
docker restart "$NAME" >/dev/null
wait_boot
phase after-boot
phase join
phase upgrade
phase remove
phase purge
phase cycles
if [ "$FIPS" = true ]; then phase fips; fi
