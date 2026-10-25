# Joining a Node is one command

**Status:** Accepted (owner decision 2026-10-22).

ADR-0050 (2026-10-23) supersedes decision 4's scope of `relay:` labels: a mint names initial
tags instead.

Behaviour: `docs/specs/enrollment.md` and `docs/specs/daemon-installation.md`.

This ADR supersedes in part ADR-0032, ADR-0030, ADR-0031 and ADR-0006, and amends ADR-0033:

- ADR-0032 decisions 1 to 4 and 6: rendering a join string as an Enrollment Bundle, its formats
  and what it pins. Decision 5, the `admin` floor on a mint, stands.
- ADR-0030's rendered enrollment artifact and its bundle-rendering capability.
- ADR-0031's amendment of 2026-10-21, where a mint form defaults to one use.
- ADR-0006's amendment of 2026-10-22, where enrollment's `relay:` key set is the scope alone.
- ADR-0033's release artifacts gain the Ansible role.

## Decision

Adding Nodes is two pastes and nothing to clean up, and no secret lands on a Node. An admin says
how many Nodes a token is for; it is good for exactly that many joins and expires in two hours
by default, so nobody has to revoke it. Relay shows the command, `sudo relay-daemon join`, and
the join string to paste at its prompt; the string is never part of a command line, a file or a
shell history on the Node. Fleets use an SSH loop or the release's Ansible role. Labels at mint
are optional, because every Node gets `relay:node-id`. Cloud VMs wait for attestation rather
than carry a token in user data.

## The decisions

1. **A mint form asks how many Nodes.** On the Console and in `relay init`, the use limit is the
   number the admin names and the expiry defaults to two hours. A used-up or expired token is
   dead; revoking stays available and is never a required step. The Control API keeps explicit
   values and no defaults.
2. **The command and the string are shown apart.** A freshly minted join string is shown once,
   beside the command that consumes it. A person runs `sudo relay-daemon join` and pastes the
   string at its prompt, which neither echoes nor reaches a shell history (ADR-0031 as amended
   2026-10-21). Relay renders no Ansible, shell or other Bundle: each format would be another
   template inside Relay, and the set would grow toward config management, which is out of realm.
3. **Fleets feed the string from the operator's side.** An SSH loop pipes it from the operator's
   machine into `relay-daemon join` on each Node; the Ansible role each release ships passes it
   from the operator's vault on standard input. Neither writes it to the Node's disk or command
   line. The role installs its own release's daemon package, places no Policy fragment, and
   changes nothing on an enrolled Node; upgrades stay the customer's to run (ADR-0014). It is a
   release artifact like the packages (ADR-0033): listed in `SHA256SUMS` and installed by
   download, verify, install.
4. **Scope is optional; every Node gets `relay:node-id`.** A token's scope is zero or more
   `relay:` Labels. Enrollment's key set is the scope plus `relay:node-id`, the Relay-assigned
   Node ID, which only the enrollment action writes (invariant 7) and no scope may name. Quarantine
   and other security-lane work can therefore single out any Node, however it was minted.
5. **`relay:enrollment-token` stays reserved and unwritten.** No action writes it and no scope may
   name it. A leaked token's Nodes are cut off together by revoking the token, which cascades to
   every Node it enrolled; fencing them off without revoking is an accepted gap (threat-model R44)
   and waits in the roadmap (`roadmap: relay/quarantine`).
6. **No cloud-init path in the MVP.** A token in user data outlives the join, readable on the Node
   and from the metadata service. New cloud VMs join by platform attestation once it exists
   (`roadmap: relay/enrollment-is-an-approval`), which needs no secret at all.

## Why

The steps a person took were bookkeeping, not security: assembling a command, choosing Labels
before knowing what they were for, and revoking a token that had done its job. A forgotten revoke
left a live token behind, so removing the step removes a risk. The comparable products confirm the
shape: Kubernetes and Teleport pin the controller's CA with a hash in the join, AWS Systems Manager
bounds an activation by a registration count and an expiry, and Teleport and SPIRE send cloud
fleets to instance identity instead of tokens. Relay's prompt is stricter than their command-line
tokens, at the cost of one extra paste.

## What changes

- `enrollment.md`: EN-31 and EN-36 reworded; EN-37, EN-38 and EN-39 designed; EN-34 retired.
- `daemon-installation.md`: DI-45 designed; DI-35 retired; its bundle text and Ansible-role future
  work reconciled. `relay-configuration.md` RC-28 and `selectors-and-labels.md` follow.
- `GLOSSARY.md`: *Enrollment Bundle* retired; *Enrollment Token* updated.
- The threat model: the enrollment boundary row, R16 and R36, and R44 for decision 5.
- `quarantine-node.md`, the spec index, and the Console's incident-ladder screen drop
  `relay:enrollment-token`; `docs/design/console/09-add-nodes.md` is redesigned at v0.7.0.
- ADR-0006, 0030, 0031, 0032 and 0033 each carry a note pointing here.

## Alternatives

- **Keep Bundles.** Every format is another template to keep correct inside Relay, and the release
  role does the same job with no rendering.
- **Show one line with the string inside.** Simplest to copy, and it puts the token in the Node's
  shell history, which ADR-0031 exists to prevent.
- **Keep cloud-init with an accepted risk**, as most products do. Defensible, but it would ship a
  path that breaks the property just fixed, where attestation removes the secret instead.
- **Stamp `relay:enrollment-token` too.** Revocation already answers a leaked token.
