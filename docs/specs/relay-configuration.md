# Relay configuration

**Status:** designed, not built, as of `2026-10-16`.
**Claim prefix:** `RC`

## Purpose

Relay configuration is what an operator fixes about a Relay: where it listens, which CA it signs
with, which identity provider it believes, how far one dispatch may reach, which dispatches wait
for a human, and whether the Console exists at all.

It is **two tiers, split by what an attacker gains from changing the setting.**

- The **security floor** is set by whoever administers the Relay's host, outside Relay, in
  **one configuration file** the Relay reads itself (ADR-0043), and nothing Relay runs or
  accepts can write it. It is the small set that decides *who may authenticate at all* and
  *whether the gate exists*: listeners and TLS material, the identity provider Relay believes,
  the authentication windows, the approval notification path, and whether the Console may
  execute.
- **Operator settings** are runtime objects in the Relay's store, changed by a human `admin` in
  the Console with step-up re-authentication, audited, taking effect on the next request. They
  are the dials an operator genuinely turns as a fleet grows and confidence grows with it —
  including the blast caps and the approval-gate rules.

The tiering is the whole point: administering a Relay should not mean editing a file and
restarting a service, and no dial an operator turns should hand a stolen credential the ability
to authenticate as somebody else.

## Surfaces

| Surface | Access to the capability |
|---|---|
| **The host** | The security floor: today `RELAY_*` environment variables and flags (RC-2); designed, one configuration file (RC-12) |
| **Admin Console** | Today nothing. Designed: every operator setting, read and changed by a human `admin` with step-up (RC-29), and the non-secret floor, read-only (RC-33) |
| **Control API** | No configuration write route exists, and none may be added (RC-11). Designed: reads the non-secret operator settings (RC-31) |
| **MCP** | No configuration write tool (RC-11). Designed: reads the non-secret operator settings (RC-31) |
| **The `relay` binary's local subcommands** | `bootstrap-token` and `console-password` (RC-1); designed, `relay init` replacing both (RC-28). First-boot acts that exist only because no credential can yet exist to perform them over the wire (ADR-0030) |

## Behaviour

- **RC-1** The `relay` binary's local subcommands `bootstrap-token` and `console-password`
  create the founding admin's first API Token and first Console credential, run on the Relay's
  host.
- **RC-2** The Relay reads its settings from command-line flags and `RELAY_*` environment
  variables; where both set a value, the environment wins.
- **RC-3** The shipped example environment file covers every setting the binary reads.
- **RC-4** With no optional setting given, the Relay comes up with the gRPC listener only: no
  control plane, no Console, no OAuth and no approval notification.
- **RC-5** The approval-gate rules file and the approval webhook secret file are each opened
  without following a symlink, checked on that descriptor and read from it; a directory is
  refused, and a gate-rules file that cannot be loaded fails closed rather than loading no rules.
- **RC-6** The shipped systemd unit runs the Relay as an unprivileged Unix account with an empty
  capability set and a read-only filesystem outside its state directory.
- **RC-7** The release publishes a Relay container image to the registry, signed keylessly at its
  digest, running as an unprivileged uid; the deployment stack pins it by digest and runs it with a
  read-only root filesystem, every capability dropped and one durable volume.

## Refusals

- **RC-8** A gate-rules file that is group- or world-writable is refused at load.
- **RC-9** A webhook secret file readable or writable by group or world is refused at start,
  naming the mode.
- **RC-10** OAuth configured with an issuer but without an audience or a public URL refuses
  start.
- **RC-11** No MCP tool and no Control API route writes any configuration. There is no endpoint
  to refuse it.

## Governing ADRs and invariants

- **Invariant 11 / ADR-0010** — the invariant this capability implements, narrowed on
  2026-09-15 from *"configuration is unreachable from any API"* to *"no credential can change the
  terms on which credentials are accepted"*. Recorded in ADR-0010's amendment of that date. Its
  secret-file clause was reworded on 2026-10-15 (ADR-0033; ADR-0010's amendment of that date):
  its headline now names the Relay process alongside credentials — *neither a credential nor the
  Relay itself* can change the terms — and secrets never pass through the environment or the
  command line; the Relay can read them and cannot rewrite them, except key material it
  generates.
- **Invariant 10 / ADR-0009, ADR-0026** — Console-only settings are an adapter offering less, not
  a parallel control path. `console_execution` stays root-owned.
- **Invariant 5 / ADR-0004, ADR-0012** — the blast caps remain enforced on the Relay before
  dispatch; only where they are set changed. Both ADRs carry a 2026-09-15 amendment saying so.
- **ADR-0027** — the approval gate. Amended 2026-09-15: its rules are store-backed and
  Console-edited; the webhook path stays root-owned.
- **ADR-0024** — OAuth issuer, audience, claim, scope and public URL are security floor.
- **ADR-0023** — no shared control-plane secret exists in configuration; the first credential is
  bootstrapped locally.
- **ADR-0030** — bounds the local subcommands. Amended 2026-09-15: when `relay init` lands it
  **replaces** `bootstrap-token` and `console-password` rather than joining them. Amended
  2026-10-15: the package, not `init`, writes the configuration file.
- **Invariant 14 / ADR-0014** — the minimum daemon version stays the Relay's only lever over
  daemon versions; it becomes an operator setting.
- **ADR-0033** — amended 2026-10-15: the Relay installs from an OS package rather than
  `relay-install.sh`, and the container image is a production path (RC-19 to RC-23).
- **ADR-0043** — one configuration file the Relay reads itself, one check, one state directory,
  and a clean break from `RELAY_*` floor variables (RC-12 to RC-18, RC-21).

## Seams and proof

Configuration is read into one value at startup — and, once RC-21 lands, replaced wholesale on a
successful reload. Operator settings will be read through a store-backed settings seam the
capability layer consults (RC-29), never a package-level variable a surface can reach; the
Console's settings screens will call that seam, and no other adapter will hold a writer.

### What proves each claim

| Claim | Proven by | Seam |
|---|---|---|
| RC-3 | `TestRelayEnvExampleCoversTheConfigSurface`, `TestRelayEnvExemptionsAreReal` | packaging |
| RC-5 | `TestLoadFailsClosed`, `TestLoadRefusesSymlink`, `TestLoadRefusesDirectory` | approval |
| RC-9 | `TestSecretFilePermissionsAreEnforced` | approval notify |

Claims with **no row**, and so nothing checking them: RC-1, RC-2, RC-4, RC-6, RC-7 (asserted by
the release workflow and image guard, not a test), RC-8, RC-10, RC-11 (an absence).

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| *(none)* | Configuration has no scale-dependent contract | *(none)* |

## Designed, not built

| Claim | Statement | Milestone |
|---|---|---|
| RC-12 | The security floor lives in one TOML configuration file the Relay reads itself: `/etc/relay/relay.toml` by default, or the path one command-line flag, `--config`, names. That path is the only configuration the Relay accepts from outside the file; the binary otherwise accepts `--version`, `--help` and its subcommands (ADR-0043). | v0.6.5 — Install Path: relay init, join string, packages |
| RC-13 | No setting is read from the environment or the command line. A `RELAY_*` variable for a setting found in the environment refuses start and names that setting's place in the file. | v0.6.5 — Install Path: relay init, join string, packages |
| RC-14 | A secret is a value in the configuration file, or a path to a file holding it, for material another tool manages and rotates. Either way it never passes through the environment or the command line (invariant 11). | v0.6.5 — Install Path: relay init, join string, packages |
| RC-15 | At start and on every reload the Relay refuses to run if it could write its configuration file or any file the configuration names, or if any account but it and root could read the configuration file or any file holding a secret. It could write a file when it owns the file on a filesystem mounted writable, when a mode bit or access-control list grants it or one of its groups write, when any directory on the file's resolved path is owned by or writable by it, or when it runs as root or holds any capability (ADR-0043). | v0.6.5 — Install Path: relay init, join string, packages |
| RC-16 | Each file the check covers is opened without following a symlink, checked on that descriptor and read from it, so nothing can change between the check and the read; a path that is a symlink is refused. | v0.6.5 — Install Path: relay init, join string, packages |
| RC-17 | Everything the Relay generates — its CA private key and its store — lives in its state directory, owned by the Relay's uid. The Relay refuses to start if that directory or the key is readable by any other account. | v0.6.5 — Install Path: relay init, join string, packages |
| RC-18 | No secret value, inline or in a file, and no approval webhook URL, appears on any surface, in any log or audit record, or in any refusal message. A parse or validation error names the key and the line, never the value; a reload's audit record names a changed secret setting, never its value. | v0.6.5 — Install Path: relay init, join string, packages |
| RC-19 | The CA directory, store path and certificate hostname have no defaults: unset is a refusal naming the setting. Every value is validated at start and at reload, and an invalid one is a refusal naming the setting, never a warning and a fallback to a default. A missing or unreadable configuration file is a refusal. | v0.6.5 — Install Path: relay init, join string, packages |
| RC-20 | A configuration that cannot work is refused at start — the Console enabled without the control plane, OAuth settings without an issuer. One that is coherent but probably a mistake, such as a mutate cap above the read cap, starts with a prominent warning. | v0.6.5 — Install Path: relay init, join string, packages |
| RC-21 | `SIGHUP` re-reads the configuration file from the path given at start and applies RC-15 before anything else. The reload is all-or-nothing: an invalid value, or a changed bind-time setting — listen addresses, CA directory, store path, certificate hostname — refuses the whole reload, logs the setting and that a restart is required, and leaves the running configuration untouched. A failed reload never exits the process. Every reload is audited as a host-lever act listing what changed. | v0.6.5 — Install Path: relay init, join string, packages |
| RC-22 | Until store-backed operator settings exist (RC-29), the read and mutate blast caps, the minimum daemon version, the `state:cert-expiring` fraction, the enrollment rate limits, burst and tracked-IP ceiling, the Node cap and the approval-gate rules file's path are values in the configuration file, validated like every other value, with built-in defaults where absent. | v0.6.5 — Install Path: relay init, join string, packages |
| RC-23 | The release publishes the Relay as `.deb` and `.rpm` packages for each architecture, on the platforms and under the CI rule `daemon-installation.md` sets for its packages, where the edited configuration an upgrade must preserve is the configuration file. A package wraps the release's guarded binary byte for byte, is reproducible, built twice and compared, is listed in the release `SHA256SUMS`, and carries no signature of its own before v1.0.0. | v0.6.5 — Install Path: relay init, join string, packages |
| RC-24 | The Relay package installs the Relay's Unix account, the binary, the hardened unit, the configuration file and the state directory, and prints a configuration guide that carries no secret, also installed as documentation. It enables the Relay on a first install only, only where systemd is running, honouring the distribution's presets, and an upgrade never changes enablement. It never starts the Relay and never runs the first-boot command. | v0.6.5 — Install Path: relay init, join string, packages |
| RC-25 | The Relay package writes the configuration file once, at first install, only if none exists, and never again: the host's fully qualified name as the certificate hostname, the CA directory and store path inside the state directory, the control plane and Admin Console enabled, and the control-plane listener bound to loopback. The file is generated, not package-owned configuration, so no upgrade rewrites it. | v0.6.5 — Install Path: relay init, join string, packages |
| RC-26 | Removing the Relay package keeps configuration and state. `apt purge` removes configuration and moves the CA and the store aside together, re-owned by root and readable by nobody else, and prints where; it never deletes them, never splits them, and never deletes the Relay's Unix account. Purge deletes only paths the package itself created. `.rpm` removal never deletes state and prints the paths to delete by hand. | v0.6.5 — Install Path: relay init, join string, packages |
| RC-27 | The Relay container image takes its configuration file, and any secret files it names, as a read-only mount: nothing about the floor is in the container's environment, so inspecting the container shows a mount path, not settings or secrets. The deployment stack runs it unprivileged, with no capabilities, a read-only root filesystem, and the CA and store on one durable volume. | v0.6.5 — Install Path: relay init, join string, packages |
| RC-28 | `relay init`, run in a terminal on the Relay's host, performs the first-boot acts — the founding admin's first API Token and first Console credential — and replaces `relay bootstrap-token` and `relay console-password` (ADR-0030). The package's guide names it. | v0.6.5 — Install Path: relay init, join string, packages |
| RC-29 | Operator settings — the blast caps, approval-gate rules, minimum daemon version, `state:cert-expiring` fraction, enrollment rate limits, Node cap, audit and Job retention and page-size limits — are runtime objects in the store with built-in defaults, changed in the Console by a human `admin` with step-up on every change, audited with the setting, its old value, its new value and who changed it, and applied to the next request. | v0.7.0 — Admin Console: Administration & Execution |
| RC-30 | Once RC-29 holds, an operator setting found in the configuration file refuses start rather than being silently ignored. | v0.7.0 — Admin Console: Administration & Execution |
| RC-31 | Non-secret operator settings are readable by any authenticated Account on MCP, the Control API and the Console, so an AI-agent can name the cap it hit. | v0.7.0 — Admin Console: Administration & Execution |
| RC-32 | The blast caps and approval-gate rules are written only from the Console: no MCP tool and no Control API route writes them, and none may be added (invariant 10). | v0.7.0 — Admin Console: Administration & Execution |
| RC-33 | The Console renders the non-secret security floor, read-only; file paths, the CA directory and every value RC-18 covers are not rendered. | v0.7.0 — Admin Console: Administration & Execution |
| RC-34 | Per-Account Console preferences are stored per Account, not fleet-wide. | v0.7.0 — Admin Console: Administration & Execution |

The image is a supported deployment path now, and is called production once a human hardening
review of its documented deployment has closed; until then its documentation says so (ADR-0033).
Never capture an image of a host after the Relay has first started: the CA private key would
travel with it.

## Out of scope

- The founding admin Account, Token minting, step-up and OAuth session semantics —
  `accounts-and-access.md`. This spec owns only where their bounds are set.
- Enrollment Tokens, join strings and bundles — `enrollment.md`.
- What the blast caps, approval gates and Freeze *do* — `execution.md`, `approval.md`,
  `freeze.md`.
- Configuring the relay-daemon on a Node, which is flags and environment from the customer's
  config management — `daemon-installation.md`.
- Relay's own health, metrics and logs — `observability.md`.
- Rotating CA or TLS material, which is an operation rather than a setting.

## Accepted residual risk

**A compromised human Console session can widen the fleet's ceiling.** With the blast caps and
approval-gate rules in the store and no root-set bound above them, an attacker holding a human
`admin` session and that Account's password can raise the mutate cap to the whole fleet and
remove every approval gate, then dispatch within the limits they just set. Step-up and the audit
trail are the controls; neither prevents it.

This was decided deliberately: a root-set ceiling above the Console value was offered and
declined in favour of one source of truth per setting. It is **R15** in
`docs/security/threat-model.md`, accepted by the owner on 2026-09-15 — invariant 11's "the API
can never raise its own limits" becomes "the API cannot, and a human in the Console can".

**A purged Relay host keeps its CA private key.** No package operation destroys the CA, so
`apt purge` moves the state directory — CA and store together — aside instead of deleting it,
and the key stays on disk until someone deletes it by hand. Losing the CA by one mistyped command
would force the whole fleet to enroll again, and that was judged the worse outcome. Accepted by
the owner on 2026-10-15 and recorded as **R34**. The compensating controls: the moved directory is
root-owned and unreadable to every other account; purge prints where it went; and the
documentation that describes purge says to delete it, or destroy the host, when the Relay is gone
for good.

**R35 is closed by design** (ADR-0043): a container's floor is a read-only mounted file, not
injected environment, so inspecting the container no longer reveals it. It stays open until
#864 builds that. Who can *write* a deployment's configuration source is the operator's own
infrastructure, documented rather than policed.

## Future work

- **A root-set ceiling above the operator settings**, if the residual risk above proves real in
  practice.
- **Live reload of TLS material**, beyond the server certificate re-issue that already happens.
- **Configuration history in the Console** — who changed which dial and when, rendered from the
  audit trail rather than kept separately.

## Open questions

- **Does a second Relay against the same store see a settings change?** Single-Relay is assumed
  throughout; if that ever stops being true, store-backed settings need a cache-invalidation
  story that startup-only configuration never needed.
- **The operator runbook describes retired mechanisms** — the shared control-plane credential,
  "no packaged unit exists", and, since 2026-10-15, its Compose section's container-as-evaluation
  framing and its secret-file modes. Stale documentation rather than an open decision, but it is
  what an operator reads first; ADR-0033's amendment lists it for update.

## Retired

None.
