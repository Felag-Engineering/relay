#!/usr/bin/env bash
# scripts/daemon-privilege-audit.sh
#
# Reproducible-evidence helper for the v0.0.8 privileged-daemon syscall/capability
# audit (docs/operations/daemon-privilege-posture.md, "Syscall and capability
# surface" section). It runs ONLY the unprivileged `systemd-analyze` commands that
# are available on an ordinary dev box, and prints the exact numbers that
# document cites so its claims stay checkable as the daemon's Operations change.
#
# What this script does NOT do: it does not strace, seccomp-audit, or otherwise
# trace a running daemon. That requires a real systemd host, root, and a live
# daemon process — none of which are available here. Section C below is a
# commented-only reference for that live procedure; it is never executed.
#
# Not wired into any Make target or CI lane (confirmed: this repo's lint targets
# are Go/Rust/devharness only — there is no shellcheck gate). Exits 0 on success.
#
# Usage: scripts/daemon-privilege-audit.sh [UNIT]
#   UNIT defaults to daemon/packaging/relay-daemon.service, resolved relative to
#   the current working directory — run this from the repo root.

set -euo pipefail

UNIT="${1:-daemon/packaging/relay-daemon.service}"

# The recommended base allowlist for a systemd system service, and the concrete
# subgroups this script flattens to derive a checkable syscall count. Keep this
# list in sync with `systemd-analyze syscall-filter @system-service`'s own
# `@group` references if a future systemd version changes them.
SYSTEM_SERVICE_SUBGROUPS="@aio @basic-io @chown @default @file-system @io-event @ipc @keyring @memlock @network-io @process @resources @setuid @signal @sync @timer @system-service"

section() {
  local title="$1"
  echo
  echo "=== ${title} ==="
}

# Section A: static unit validation — runnable unprivileged, on this box.
check_verify() {
  local unit="$1"
  local verify_output unexpected_lines

  echo "\$ systemd-analyze verify \"${unit}\""
  verify_output="$(systemd-analyze verify "${unit}" 2>&1 || true)"
  printf '%s\n' "${verify_output}"

  # Off this host there is no /usr/local/bin/relay-daemon installed, so
  # `systemd-analyze verify` always reports that one complaint. Tolerate
  # exactly that line; any OTHER line (a malformed directive, a bad value)
  # is a real regression and must fail the gate.
  unexpected_lines="$(printf '%s\n' "${verify_output}" \
    | grep -v -F 'is not executable: No such file or directory' \
    | grep -v '^[[:space:]]*$' || true)"

  if [[ -n "${unexpected_lines}" ]]; then
    echo "FAIL: systemd-analyze verify reported unexpected issues:" >&2
    printf '%s\n' "${unexpected_lines}" >&2
    exit 1
  fi
  echo "OK: only the expected off-host 'not executable' complaint."
}

check_security_exposure() {
  local unit="$1"
  local security_output exposure_line

  echo "\$ systemd-analyze security --offline=true \"${unit}\""
  security_output="$(systemd-analyze security --offline=true "${unit}")"
  exposure_line="$(printf '%s\n' "${security_output}" | grep 'Overall exposure')"
  echo "${exposure_line}"
}

# Section B: syscall-group vocabulary — the allowlist basis.
print_syscall_vocabulary() {
  local flattened_count

  echo "\$ systemd-analyze syscall-filter @system-service"
  systemd-analyze syscall-filter @system-service
  echo
  echo "@system-service is systemd's documented recommended base SystemCallFilter"
  echo "allowlist for a general system service; docs/operations/daemon-privilege-posture.md"
  echo "derives the daemon's candidate filter from it."

  # Flatten @system-service's subgroups (plus its own direct members) into one
  # deduplicated set of concrete syscalls — the checkable basis for the doc's
  # "every syscall the daemon and its children issue is in @system-service" claim.
  flattened_count="$(
    for group in ${SYSTEM_SERVICE_SUBGROUPS}; do
      systemd-analyze syscall-filter "${group}"
    done \
      | grep -vE '^[[:space:]]*@|^[[:space:]]*#|^[[:space:]]*$' \
      | sed 's/^[[:space:]]*//' \
      | sort -u \
      | wc -l
  )"
  echo
  echo "Flattened @system-service concrete syscall count on this systemd version: ${flattened_count}"
}

# Section C: the LIVE privileged trace. This is documentation only — a heredoc
# printed to stdout — and is NEVER executed by this script or by CI.
print_live_trace_procedure() {
  cat <<'EOF'
LIVE PRIVILEGED TRACE (run on a real systemd host — NOT runnable here)
------------------------------------------------------------------------
This box has no strace/perf/auditctl and no passwordless sudo, and the
dev-fleet runs daemons under Docker rather than systemd, so none of the
following can run here. This block is reference only; #224 (apply-and-verify)
is where it gets run for real.

Environment: a real systemd host, relay-daemon installed at
/usr/local/bin/relay-daemon under relay-daemon.service, policy.toml + an
Enrollment Token in place, seccomp/audit available.

1. Syscall union including children (seccomp is inherited across execve):

     strace -f -qq -e trace=all -o /tmp/relay-trace.log \
       -p "$(systemctl show -p MainPID --value relay-daemon)"

   While that is attached, drive one of each Operation (system.facts,
   file.read, service.restart, pkg.install, and a representative
   Policy-permitted Raw Exec) from the Relay. Then extract the syscall set:

     grep -oE '^[0-9]+ +[a-z_]+\(' /tmp/relay-trace.log \
       | sed -E 's/^[0-9]+ +([a-z_]+)\(/\1/' \
       | sort -u

   Map each syscall to its @group (`systemd-analyze syscall-filter <group>`)
   and diff against @system-service; anything outside it is a candidate
   addition, trace-validated rather than guessed.

2. Seccomp audit-mode alternative (no strace needed): set
   `SystemCallFilter=@system-service` plus `SystemCallLog=@system-service` in
   the unit (or run under the kernel's SECCOMP_RET_LOG action) and read
   `journalctl -u relay-daemon | grep SECCOMP` for any denied syscall while
   exercising every Operation.

3. Capability confirmation: run under the candidate CapabilityBoundingSet and
   confirm file.read of a non-root-owned, otherwise-unreadable file still
   succeeds (exercises CAP_DAC_READ_SEARCH), and that pkg.install succeeds
   only under the pkg-install.conf drop-in, not under the strict baseline.

Placement note (load-bearing for reproducing the doc's numbers): the
candidate SystemCallFilter=/SystemCallArchitectures=/MemoryDenyWriteExecute=
lines go WITHIN the unit's [Service] section — e.g. immediately after the
existing RestrictAddressFamilies=... line, before [Install]. Pasting them
after [Install] instead does NOT error loudly: systemd only logs a
low-visibility "Unknown key ... in section [Install], ignoring" warning per
line, the directives silently no-op, and `systemd-analyze security
--offline=true` keeps reporting the unmodified 3.7 exposure instead of the
expected 2.1 — verified against a scratch copy of the unit while producing
the numbers in docs/operations/daemon-privilege-posture.md. Applying the
candidate to the shipped unit is #224's job, not this script's or this
issue's; do it only against a scratch copy.
EOF
}

main() {
  if [[ ! -f "${UNIT}" ]]; then
    echo "ERROR: unit file not found at ${UNIT}; run from the repo root or pass a path" >&2
    exit 1
  fi

  section "A. Static unit validation (runnable unprivileged, this box)"
  check_verify "${UNIT}"
  echo
  check_security_exposure "${UNIT}"

  section "B. Syscall-group vocabulary (allowlist basis)"
  print_syscall_vocabulary

  section "C. Live privileged trace procedure (reference only, never executed here)"
  print_live_trace_procedure

  echo
  echo "Done. See docs/operations/daemon-privilege-posture.md for the derivation this feeds."
}

main
