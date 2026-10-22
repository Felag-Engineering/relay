# Joining a Node is one command

**Status:** Accepted (owner decision 2026-10-22).

Behaviour: `docs/specs/enrollment.md` and `docs/specs/daemon-installation.md`. This ADR supersedes
ADR-0032 decisions 1 to 4 (rendering a join string as an Enrollment Bundle, and its formats) and
ADR-0030's rendered enrollment playbook; ADR-0032 decision 5, the `admin` floor on a mint,
stands.

## Decision

Adding Nodes to Relay is one copied line. An admin says how many Nodes a token is for; the token
is good for exactly that many joins and expires in hours, so it dies on its own and nobody has
to remember to revoke it. Relay shows the join string once, already inside the command that
joins a Node, and renders no install artifacts of its own. Each release ships a static Ansible
role and cloud-init config that run that same command. Choosing `relay:` Labels at mint is
optional, because Relay stamps every Node with `relay:node-id`, which lets the security lane
address any one Node without trusting it.

## The decisions

1. **A mint form asks how many Nodes.** On every surface that offers a form (the Console,
   `relay init`), the use limit is the number of Nodes the admin names and the expiry defaults to
   two hours. A used-up or expired token is dead; revoking stays available and is never a
   required step. The Control API keeps explicit values and no defaults.
2. **The join command is shown, not rendered.** Wherever a person is shown a freshly minted join
   string, it appears once, inside the one command that joins a Node, ready to copy. Relay
   renders no Ansible, shell or other Bundle: the formats ADR-0032 named would grow one at a
   time into config management, which is out of realm.
3. **Static install files ship with each release.** An Ansible role and a cloud-init config
   install the daemon package and pipe a join string the caller supplies into
   `relay-daemon join`. They carry no token, and rerunning them on an enrolled Node changes
   nothing. They are release artifacts like the packages (ADR-0033), versioned and signed with
   them.
4. **Scope is optional; every Node gets `relay:node-id`.** A token's scope is zero or more
   `relay:` Labels. Every enrollment stamps `relay:node-id`, the Relay-assigned Node ID, written
   only by the enrollment action (invariant 7) and refused in any scope (ADR-0006 as amended
   2026-10-22). Quarantine and other security-lane work can therefore single out any Node, however
   it was minted.
5. **`relay:enrollment-token` is not stamped.** A leaked token's Nodes are cut off together by
   revoking the token, which cascades to every Node it enrolled. Fencing them off without
   revoking it waits in the roadmap.

## Why

The steps a person had to take were bookkeeping, not security: assembling a command, choosing
Labels before knowing what they were for, and revoking a token that had already done its job.
A forgotten revoke left a live token behind, so removing the step removes a risk. The one
security decision a person still makes, how many Nodes a token may enroll and for how long, is
the one the form now asks for.

## Alternatives

- **Keep Bundles.** Every format is another template inside Relay to keep correct, and the
  release files do the same job with no rendering.
- **Keep the scope required.** One more decision at the moment a person least knows its answer,
  and it would still leave Nodes with no individual handle.
- **Stamp `relay:enrollment-token` too.** Revocation already answers a leaked token.
