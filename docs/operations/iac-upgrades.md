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

1. **A release is cut.** Pushing `v<version>` publishes the daemon and Relay packages
   (`.deb` and `.rpm`, each for `amd64` and `arm64`), the binaries
   (`relay-daemon-<version>-linux-<arch>`, `relay-<version>-linux-<arch>`), the Ansible role,
   `SHA256SUMS` and its cosign bundle `SHA256SUMS.sigstore.json`
   ([release-artifacts.md](release-artifacts.md)).
2. **The operator updates the pin** in config management: the version string *and* the expected
   sha256 digest for each package file you install, copied from `SHA256SUMS`. The operator's copy
   of the digest is the trust anchor: pinning only the version proves download integrity, not
   provenance. `cosign verify-blob` on `SHA256SUMS` adds provenance, as release-artifacts.md
   shows, and is checked when the pin is taken, before the digest goes into config management.
3. **The Relay upgrades first** (ADR-0014: daemons lag behind within the min-version window,
   never the other way around). A packaged Relay: install the newer verified Relay package on
   its host, then `systemctl restart relay` (the package runs `daemon-reload` only;
   [relay-install.md](relay-install.md)). A Compose-deployed Relay: bump the deployment pin to
   the new release's image digest ([release-artifacts.md](release-artifacts.md), "Bump the
   deployment pin after each release"; [relay-install.md](relay-install.md) §7, "Upgrades").
4. **Config management installs the newer daemon package** across the fleet and restarts the
   unit. The daemon's graceful shutdown drains in-flight Tasks (bounded by
   `RELAY_SHUTDOWN_GRACE_SECS`, default 30 s) and the at-most-once dedup store survives the
   restart (ADR-0004), so a restart mid-Job never re-executes a Task.
5. **The operator raises `reach.min_daemon_version`** in the Relay's `relay.toml` once the
   rollout should be complete, applies it with a SIGHUP, and watches the registry.

## Ansible-flavored rollout

The release's `relay_daemon` role ([enrollment.md](enrollment.md)) never upgrades: it installs
only where `/usr/bin/relay-daemon` is absent, so an upgrade is your own task. In this example the
signature was checked when the pin was taken (step 2), and `get_url`'s `checksum:` checks the
downloaded file on the Node against the pinned digest before it lands; a mismatch fails the
task.

```yaml
# group_vars/prod.yml — the upgrade IS this diff, reviewed like any other
relay_daemon_version: "X.Y.Z"          # was: the previously pinned release
relay_daemon_pkgversion: "{{ relay_daemon_version | replace('-', '.') }}"   # a prerelease's "-" is "." in the file name (release-artifacts.md)
relay_daemon_deb_sha256: "<64-hex sha256 digest of the new .deb, from SHA256SUMS>"
relay_daemon_rpm_sha256: "<64-hex sha256 digest of the new .rpm, from SHA256SUMS>"
```

```yaml
# Goes in your play's `handlers:`. It is yours, not the role's.
handlers:
  - name: restart relay-daemon
    ansible.builtin.systemd:
      name: relay-daemon
      state: restarted
```

A play that also applies the release's role can notify `relay_daemon : Restart relay-daemon`
instead.

```yaml
- name: Fetch relay-daemon package (digest verified BEFORE install)
  ansible.builtin.get_url:
    url: "https://github.com/Felag-Engineering/relay/releases/download/\
          v{{ relay_daemon_version }}/relay-daemon_{{ relay_daemon_pkgversion }}-1_amd64.deb"
    dest: "/var/tmp/relay-daemon_{{ relay_daemon_pkgversion }}-1_amd64.deb"
    mode: "0644"
    checksum: "sha256:{{ relay_daemon_deb_sha256 }}"

- name: Install the verified package
  ansible.builtin.apt:
    deb: "/var/tmp/relay-daemon_{{ relay_daemon_pkgversion }}-1_amd64.deb"
  notify: restart relay-daemon

# On an rpm Node: the same two tasks with the .x86_64.rpm file,
# relay_daemon_rpm_sha256 and ansible.builtin.dnf. On arm64: the arm64 / aarch64
# file and its own digest.

- name: Confirm installed binary self-identifies as the pin
  ansible.builtin.command: /usr/bin/relay-daemon --version
  register: daemon_version_out
  changed_when: false
  failed_when: relay_daemon_version not in daemon_version_out.stdout
```

Roll in batches with `serial:` for a canary wave; the version gate (below) makes mixed-version
fleets legible rather than dangerous.

## Before upgrading a Node that ran v0.1.0

The pre-release v0.1.0 kept the join string in the environment file: its package placed an empty
`RELAY_JOIN=` line there, and its `relay-daemon join` wrote the string to it. The current daemon
reads no join string and **refuses to start while `RELAY_JOIN` is set**, empty included, so a
Node upgraded with the line still in place restarts every 5 s and never reconnects. Remove the
line **before** the new artifact and the restart land, in the same play:

```yaml
- name: Remove RELAY_JOIN from the environment file (required before the v0.1.0 upgrade)
  ansible.builtin.lineinfile:
    path: /etc/relay-daemon/relay-daemon.env
    regexp: '^RELAY_JOIN='
    state: absent
```

An enrolled Node does not need the line: it reconnects from its persisted identity. A line that
held a live join string also held a live Enrollment Token, and removing the line does not
invalidate it. Let it expire, or revoke it if it is believed leaked, knowing that revocation
cascades to every Node enrolled under it ([enrollment.md](enrollment.md)). Backups and images of
the Node taken before the upgrade still carry the line.

## Before upgrading onto the release that adds the Policy directory

**A Policy key this release does not recognise loads as deny-all.** Earlier releases ignored
such a key, so a Policy with a mistyped `[[denny]]` or `alow = [...]` ran with that line silently
dropped. This release reads it as a parse error, and the Node then denies every Task. The rule
covers the Policy file and every fragment in the Policy directory.

Before restarting any Node onto this release, run **this release's** `relay-daemon policy
check`, in CI or from the new artifact on a staging host, over the Policy file and the Policy
directory exactly as config management pushes them. An older binary ignores the key and passes:

```console
$ relay-daemon policy check policies/web-prod.toml --policy-dir policies/web-prod.d
```

The check reports an unrecognised key as an error and exits `1`. Fix the Policy, push it, and
then roll the binary. If a Node restarted first, it reports the deny-all fingerprint
`e3b0c442…b855`, and its journal line `policy load failed; using deny-all policy` names the key
([policy-as-code.md](policy-as-code.md)).

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
