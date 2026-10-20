# IaC upgrade workflow

How relay-daemon (and Relay) upgrades flow through the customer's config management, using the
release artifacts (ADR-0014, [release-artifacts.md](release-artifacts.md)). The model in one
sentence:

> **The daemon never self-upgrades and the Relay never pushes binaries.** Config management
> installs; the Relay's only lever is refusing to *dispatch* to below-minimum Nodes.

A self-upgrade channel would be RCE on the executor: the most privileged binary in the system
accepting new code over the connection it is designed to distrust (ADR-0002). The daemon binary
is a root-owned artifact updated exactly like the Policy file, through the reviewed IaC
pipeline.

## The upgrade loop

1. **A release is cut.** Pushing `v<version>` publishes
   `relay-daemon-<version>-<arch>-unknown-linux-musl`,
   `relay-<version>-<arch>-unknown-linux-gnu` (`<arch>` is `x86_64` or `aarch64`), `SHA256SUMS`
   and its cosign bundle `SHA256SUMS.sigstore.json` ([release-artifacts.md](release-artifacts.md)).
2. **The operator updates the pin** in config management: the version string *and* the expected
   sha256 line copied from `SHA256SUMS`. The operator's copy of the digest is the trust anchor:
   pinning only the version proves download integrity, not provenance. `cosign verify-blob` on
   `SHA256SUMS` adds provenance, as release-artifacts.md shows.
3. **The Relay upgrades first** (ADR-0014: daemons lag behind within the min-version window,
   never the other way around), by the same verify-then-install sequence on the Relay hosts
   ([relay-install.md](relay-install.md)).
4. **Config management rolls the daemon artifact** across the fleet and restarts the unit. The
   daemon's graceful shutdown drains in-flight Tasks (bounded by `RELAY_SHUTDOWN_GRACE_SECS`,
   default 30 s) and the at-most-once dedup store survives the restart (ADR-0004), so a restart
   mid-Job never re-executes a Task.
5. **The operator raises `reach.min_daemon_version`** in the Relay's `relay.toml` once the
   rollout should be complete, applies it with a SIGHUP, and watches the registry.

## Ansible-flavored rollout

The role from [enrollment.md](enrollment.md) upgrades by pin change: the `get_url` task's
`checksum:` fails before install on any mismatch, and the restart handler completes the swap.

```yaml
# group_vars/prod.yml — the upgrade IS this diff, reviewed like any other
relay_daemon_version: "X.Y.Z"          # was: the previously pinned release
relay_daemon_sha256: "<sha256 line for the new artifact, from SHA256SUMS>"
```

```yaml
# roles/relay_daemon/handlers/main.yml
- name: restart relay-daemon
  ansible.builtin.systemd:
    name: relay-daemon
    state: restarted
```

```yaml
# The fetch task from enrollment.md already notifies the handler on change:
- name: Fetch relay-daemon artifact (digest verified BEFORE install)
  ansible.builtin.get_url:
    url: "https://github.com/Felag-Engineering/relay/releases/download/\
          v{{ relay_daemon_version }}/relay-daemon-{{ relay_daemon_version }}-x86_64-unknown-linux-musl"
    dest: /usr/bin/relay-daemon
    mode: "0755"
    checksum: "sha256:{{ relay_daemon_sha256 }}"
  notify: restart relay-daemon

- name: Confirm installed binary self-identifies as the pin
  ansible.builtin.command: /usr/bin/relay-daemon --version
  register: daemon_version_out
  changed_when: false
  failed_when: relay_daemon_version not in daemon_version_out.stdout
```

Roll in batches with `serial:` for a canary wave; the version gate (below) makes mixed-version
fleets legible rather than dangerous.

## The minimum-version gate (the Relay's side)

`reach.min_daemon_version` in `relay.toml` ([relay-install.md](relay-install.md)) sets the
minimum relay-daemon semver. Its properties (ADR-0014):

- **Below-minimum Nodes still connect**, heartbeat, and appear in the registry flagged
  `outdated`, but the Job engine refuses to send them Tasks. Refusing the *connection* would
  make stale daemons invisible mid-upgrade; the registry is the upgrade dashboard.
- **Refusals are per-Task outcomes** (`version_refused`), so a Job against a mixed fleet
  reports honestly per Node rather than failing wholesale. A Policy preflight shows the same
  as an `outdated: true` hint per verdict.
- The version compared is the daemon's build-stamped `--version`, which the release workflow
  guarantees equals the artifact filename and git tag ([version-stamping.md](version-stamping.md)).
  Dev builds sort below any release or prerelease target, so a prerelease minimum
  (e.g. `0.1.0-beta`) is safe to set.
- The gate is Relay configuration, never settable through the Control API (invariant 11). A
  malformed value refuses startup (and a SIGHUP reload, which leaves the running value in
  force); unset means the gate is off.

Watch progress with `list_nodes` (MCP): each Node reports its `daemon_version` in `Hello`, and
the derived `outdated` flag flips as the rollout lands. When no Node is `outdated`, the window
is closed.

## What NOT to build

Rejected alternatives (ADR-0014): a self-updating daemon; Relay-pushed binaries via an
Operation; hard connection rejection below min-version. Each undoes a security or observability
property this workflow depends on. Upgrading via Raw Exec (`curl … | install …` through the
execution path) is the same anti-pattern with extra steps: it turns the reviewed IaC pipeline
into an unreviewed wire push, and Policy should deny it.
