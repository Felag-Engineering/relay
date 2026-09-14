# Daemon installation

**Status:** stub — aspirational, not yet worked through with the owner (`2026-09-13`).

## Purpose

A Node joins the fleet only after something puts the relay-daemon on it. At fleet scale that
something is the customer's config management, not a person. This capability covers what that
config management is handed and what it does with it: the release artifacts, the verified
install, the local files the daemon reads (Policy, Templates, its env config), the hardened
service definition, upgrades, and taking a Node back out.

It exists because the daemon's per-Node footprint is the product's biggest adoption cost and
also the reason the product can be trusted. Installing it has to be quick at 100k Nodes and
still verify-then-install, so that the thing that distrusts the operator isn't delivered by
`curl | sh`.

## Surfaces

| Surface | Today |
|---|---|
| Release artifacts | A `relay-daemon` binary under `SHA256SUMS`. No OS packages and no `relay-install.sh` exist yet, although ADR-0033 decides both. |
| Service definition | A hardened systemd unit and an example `EnvironmentFile`, shipped as packaging for config management to place. |
| Daemon-local files | The env file (address, CA bundle, Policy and template paths, `node:` Labels, state dir, Enrollment Token), Policy, the template directory, and the state directory holding identity and dedup markers. |
| relay-daemon subcommands | Offline only: `--version`, `policy check`, `dump-operation-schema`. |
| Enrollment bundles | A rendered Ansible or shell artifact, minted with its Enrollment Token (`enrollment.md` owns this). |
| Relay / MCP / Control API / Console | None. The Relay never installs, configures or upgrades a daemon. That absence is deliberate (invariant 14), not a missing feature. |

## Behaviour

_To be established by interrogation._

Candidate claims, from the ADRs and the code — each to be confirmed, changed or dropped:

- Every installable artifact ships under the release's `SHA256SUMS`, and the documented install always verifies the digest before the artifact is executed.
- The daemon is installed, configured and upgraded only by the customer's config management. It never self-upgrades, and the Relay never pushes a binary.
- The daemon's OS package installs the shipped default read-only Policy as a conffile, so a fresh Node comes up read-only rather than deny-all. An upgrade never overwrites a Policy the operator has edited.
- A missing or unreadable Policy file means deny-all. A Policy or template file that is group- or world-writable is refused.
- Node code requests file modes and never forces them. The operator's umask is a ceiling nothing in the daemon widens. A umask that makes the state directory unusable fails loudly, and no Task runs unrecorded.
- The shipped unit runs the daemon as root, bounded to `CAP_DAC_READ_SEARCH`, with `/etc` read-only, so even a compromised daemon cannot rewrite its own Policy or Templates.
- The Enrollment Token is used only when no identity is persisted, and is inert on every later start.
- A freshly installed Node needs only its config file and its `node:` Labels to enroll. After that, config management stays authoritative for the Relay address.
- There is no daemon container image.
- Decommissioning a Node is a Relay-side revoke plus config management removing the daemon and its state directory.

## Refusals

_To be established by interrogation._

Candidate claims, from the ADRs and the code — each to be confirmed, changed or dropped:

- The daemon refuses to start if its identity or dedup store cannot be opened.
- The daemon refuses a Policy or template file whose ownership or mode is unsafe.
- There is no install path that skips digest verification.

## Governing ADRs and invariants

- **ADR-0033** — no `curl | sh`. The installer ships inside the release. The daemon gets OS packages before the Relay does. Policy is installed as a conffile, never overwritten. No hosted repository before v1.0.0. No daemon image.
- **ADR-0014** — upgrades flow only through config management. The daemon never self-upgrades and the Relay never pushes binaries.
- **ADR-0036** — a declared file mode is a ceiling, and nothing in node code may widen what the operator's umask removed.
- **ADR-0032** — the rendered enrollment playbook pins a daemon version and digest built into the Relay. The OS package is the intended end state. The boundary with `enrollment.md` runs through this ADR.
- **ADR-0022** — the shipped default Policy allows reads with a confidentiality deny-list. Mutate and Raw Exec are opt-in.
- **ADR-0002** — Policy is a local, root-owned file. No installation path may deliver or change it over the wire.
- **ADR-0037** *(Proposed, not accepted)* — an agentless SSH tier with no daemon at all. See Open questions.
- **Invariant 14** — the installation path is config management's, and never the Relay's.
- **Invariant 2** — nothing installed can let the Relay write Policy.
- **Invariant 4** — the state directory's modes protect at-most-once. ADR-0036 shows the umask interaction fails closed.

## Seams and proof

_Not yet written._

## Out of scope

- Minting Enrollment Tokens, rendering bundles, identity issuance and revocation → `enrollment.md`.
- The connection a running daemon holds, and the minimum-version gate → `node-connection.md`.
- What Policy may say and how it is evaluated → `policy.md`. What a Template may define → `operations-and-templates.md`.
- Installing and configuring the Relay host, `relay init`, the Relay's unit and env file → `relay-configuration.md`.
- Authoring Policy for a customer. Policy authoring stops at the clipboard (invariant 2).
- A hosted package repository. ADR-0033 rules it out before v1.0.0.

## Open questions

1. **What is the day-one install artifact?** ADR-0033 decides OS packages for the daemon first and a `relay-install.sh`, but neither exists. Today it is a bare binary plus unit and env file placed by hand or by a playbook. Is the `.deb`/`.rpm` still the intended shape, and which distributions must it cover?
2. **How is the Enrollment Token supplied?** Today it sits in plaintext in a `0600` env file, and the packaging notes call that interim, pointing at systemd `LoadCredential=`. Is the token-in-env-file posture acceptable for beta, or must it move before a real fleet?
3. **The join string versus today's config.** ADR-0031 says a fresh Node's config is two lines, `RELAY_JOIN` and `RELAY_NODE_LABELS`, and removes `RELAY_CA_BUNDLE_PATH`. The daemon still needs the CA bundle path and the address. Is the two-line install the contract this spec should state?
4. **Where does the shipped default Policy land when there is no package?** The conffile decision prevents "enrolls, looks healthy, denies everything". A Node installed from the bare binary still hits that trap. Should the daemon or the playbook guarantee a default, or is deny-all the correct outcome for a bare install?
5. **Which config-management tools are first-class?** The rendered bundles are Ansible and shell. Are Puppet, Chef and Salt out, documented-only, or rendered formats?
6. **What exactly does decommissioning promise?** Today it is a revoke plus removing the daemon and state directory. Should uninstalling leave the Policy and templates behind (conffile semantics), and should the Relay ever notice that a revoked Node's daemon is still dialling?
7. **Upgrade restarts and in-flight Tasks.** An upgrade is an artifact swap followed by a restart. What should happen to a Task running when config management restarts the daemon: a grace period (there is a shutdown-grace setting today), then what outcome?
8. **Policy and Template reload.** A Policy change is a file push plus a daemon restart. Is restart-to-reload the intended contract, or is an in-place reload wanted? How does that interact with the `/etc` read-only unit?
9. **The `pkg.install` privilege exception.** The unit documents a drop-in that relaxes `ProtectSystem` and the capability bound for Nodes running `pkg.install` or filesystem-mutating Raw Exec. Is shipping that relaxation part of installation, or something the customer must choose to do?
10. **Is the hardened unit's syscall filter verified on a real systemd host?** The unit says the live check is still a required manual step. Does beta ship it as the default before that check?
11. **Does agentless SSH belong in this capability?** ADR-0037 proposes an agentless SSH tier to remove the per-Node install cost this spec exists to manage. Is it a live option, and if so is it "installation: none" here, a tier in `execution.md`, or out of realm?
12. **Non-systemd and non-Linux Nodes.** Only a systemd unit ships. Are OpenRC, containers-as-hosts or other operating systems out of realm, or unaddressed?
13. **Does the rendered playbook's pinned daemon version** (ADR-0032) ever conflict with a customer pinning their own version, and which one wins?

## History

- `2026-09-13` — stub created to name the capability.
