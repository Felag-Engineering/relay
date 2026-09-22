# IaC upgrade workflow

How relay-daemon (and Relay) upgrades flow through the customer's config
management, consuming the CD release artifacts (ADR-0014,
[release-artifacts.md](release-artifacts.md)). The one-sentence model:

> **The daemon never self-upgrades and the Relay never pushes binaries.** Config
> management installs; the Relay's only lever is refusing to *dispatch* to
> below-minimum Nodes.

A self-upgrade channel would be RCE-on-the-executor — the most privileged binary
in the system accepting new code over the very connection it is designed to
distrust (ADR-0002). The daemon binary is therefore a root-owned artifact updated
exactly like the Policy file: through the reviewed IaC pipeline.

## The upgrade loop

1. **A release is cut.** Pushing `v<version>` publishes
   `relay-daemon-<version>-x86_64-unknown-linux-musl`,
   `relay-<version>-x86_64-unknown-linux-gnu`, and `SHA256SUMS`
   ([release-artifacts.md](release-artifacts.md)).
2. **The operator updates the pin** in config management: the version string
   *and* the expected sha256 line copied from `SHA256SUMS` (the operator's copy
   of the digest is the trust anchor — pinning only the version proves download
   integrity, not provenance).
3. **The Relay upgrades first** (ADR-0014 ordering rule: daemons lag behind
   within the min-version window, never the other way around). Same
   verify-then-install sequence, on the far fewer Relay hosts
   ([relay-install.md](relay-install.md)).
4. **Config management rolls the daemon artifact** across the fleet and restarts
   the unit. The daemon's graceful shutdown drains in-flight Tasks (bounded by
   `RELAY_SHUTDOWN_GRACE_SECS`, default 30 s) and the at-most-once dedup store
   survives the restart (ADR-0004), so a restart mid-Job never re-executes a
   Task.
5. **The operator raises `-min-daemon-version`** on the Relay once the rollout
   should be complete, and watches the registry.

## Ansible-flavored rollout

The same role from [enrollment.md](enrollment.md) upgrades by pin change — the
`get_url` task's `checksum:` fails before install on any mismatch, and the restart
handler completes the swap:

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
    url: "https://github.com/Felag-Engineering/gleipnir-relay/releases/download/\
          v{{ relay_daemon_version }}/relay-daemon-{{ relay_daemon_version }}-x86_64-unknown-linux-musl"
    dest: /usr/local/bin/relay-daemon
    mode: "0755"
    checksum: "sha256:{{ relay_daemon_sha256 }}"
  notify: restart relay-daemon

- name: Confirm installed binary self-identifies as the pin
  ansible.builtin.command: /usr/local/bin/relay-daemon --version
  register: daemon_version_out
  changed_when: false
  failed_when: relay_daemon_version not in daemon_version_out.stdout
```

Roll in batches with `serial:` if you want a canary wave; the version gate (below)
makes mixed-version fleets legible rather than dangerous.

## The minimum-version gate (the Relay's side)

`-min-daemon-version` / `RELAY_MIN_DAEMON_VERSION` on the Relay
([relay-install.md](relay-install.md)) sets the minimum relay-daemon semver.
Deliberate properties (ADR-0014):

- **Below-minimum Nodes still connect**, heartbeat, and appear in the registry —
  flagged `outdated` — but the Job engine refuses to send them Tasks. Refusing
  the *connection* instead would make stale daemons invisible mid-upgrade; the
  registry is the upgrade dashboard.
- **Refusals are per-Task outcomes** (`version_refused`), so a Job against a
  mixed fleet reports honestly per Node rather than failing wholesale. A Policy preflight
  surfaces the same as an `outdated: true` hint per verdict.
- The version compared is the daemon's build-stamped `--version`, which the
  release workflow guarantees equals the artifact filename and git tag
  ([version-stamping.md](version-stamping.md)).
- The gate is Relay startup config — file/flag/env only, never settable through
  the Control API (invariant #11). A malformed value refuses Relay startup;
  empty means the gate is off.

Watch progress with `list_nodes` (MCP): each Node reports its `daemon_version`
truthfully in `Hello`, and the derived `outdated` flag flips as the rollout lands.
When no Node is `outdated`, the window is closed.

> **Prerelease caveat (#261, unresolved):** do not set `min-daemon-version` to a
> *prerelease* version (e.g. `0.1.0-beta`) — the `-dev` suffix scheme currently
> sorts dev builds of a prerelease line *above* the prerelease itself, making the
> gate fail-open for that one shape of target. Details in
> [release-artifacts.md](release-artifacts.md). Stable targets are unaffected.

## What NOT to build

Rejected alternatives, recorded so nobody reintroduces them as "improvements"
(ADR-0014): a self-updating daemon; Relay-pushed binaries via an Operation; hard
connection rejection below min-version. Each undoes a security or observability
property this workflow depends on. Upgrading via Raw Exec (`curl … | install …`
through the execution path) is the same anti-pattern with extra steps — it turns
the reviewed IaC pipeline into an unreviewed wire push and should be denied by
Policy in any sane fleet.
