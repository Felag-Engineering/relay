# Enrollment is an approval

**Status:** shaping (`2026-10-22`). Origin: the enrollment spec migration of 2026-10-21
(#1134); milestone *v0.8.2 — Enrollment: Pending and Approval* exists and is empty.

## Problem

A Node joins the fleet by presenting a reusable Enrollment Token inside a join string. The
token is a bearer secret carrying `relay:` scope, the namespace the security lane targets, so
it has to reach the Node, rest there until first start, and be kept from everything else that
runs on it. Threat-model rows R16, R36 and R41 bound the consequences rather than close them.

## Proposal

A Node arrives **pending**, carrying only the Relay address and the CA fingerprint, which are
not secrets and may live in a package default or an image. It pins the CA, submits a CSR with
its declared `node:` Labels, Facts and whatever **proof** it has, and the Relay signs nothing.
An **enrollment approval** is the one Relay action that releases it: it assigns the Node ID,
signs the CSR, stamps the Node's `relay:` Labels, and records the proof and the approver. Three
proofs: none, where a human `admin` with step-up approves against a verification code the
daemon derives from its own key and prints on the host; an Enrollment Token, which releases
the pending Node on its own with the token's scope as its Labels, consumed under its use
limit; and a platform attestation, whose shape is reserved and whose verifiers are each a
later decision, releasing only through an enrollment rule that maps the attested identity to
Labels. A pending Node expires after 24 hours, is capped and rate-limited as the certless
Enroll RPC is, and re-submits on its reconnect backoff. Machine Accounts never approve one,
and MCP exposes no enrollment surface.

## Changes

`enrollment.md` gains the pending and approval claims under v0.8.2; `daemon-installation.md`
loses the join string as the only path. ADR-0006 (the enrollment action stamps `relay:`) and
ADR-0031 (the join string) are amended; ADR-0044 is amended narrowly so the Console may
approve an *enrollment*, which has no requesting surface, while dispatch approvals stay out of
it. Invariant 6's certless exception widens from one RPC to the pending submission and its
release, and stays bounded: a pending Node receives nothing usable before approval. Invariant
7 is unchanged: an approval stamps only the token's scope or the rule's fixed mapping, never a
human-typed set. Consumers: `selectors-and-labels.md`, `approval.md` (which does not reach
enrollment approvals), `audit-and-read-lane.md`, `query.md`, `quarantine-node.md`, the
glossary, the threat model.

## Objections

1. **The join string is already being taken off the Node (ADR-0031 amendment, #1135); is the
   rest needed?** — Yes: the human path still needs a secret to reach the host, and an
   autoscaling fleet has no safe channel for one. Tokens stay the bulk path, minted bounded.
2. **A daemon-side hard deny of its own files would be simpler.** — Rejected by ADR-0021 and
   not reopened: it hides a rule from the Policy an operator reads, and the leak was through
   `/proc`, which a path deny would not have closed.
3. **Keying an enrollment rule on hostname or source address is what fleets expect.** — Every
   one of those is the Node's own word. A rule keys on a proof only. Owner ruling 2026-10-21.
4. **Who approves, and may MCP?** — A human `admin` with step-up, on the Console or the
   Control API. Never a machine Account, never MCP. Owner ruling 2026-10-21.
5. **May the approver type the `relay:` Labels?** — No. Only a token's scope or a rule's fixed
   mapping is stamped, so invariant 7's one-writer rule holds. Owner ruling 2026-10-22.
6. **The Console deciding approvals contradicts ADR-0044.** — ADR-0044's reason is that an
   in-band decision must come from the surface that created the request. An enrollment has no
   requesting surface, so the amendment is narrowed to enrollment only. Owner ruling
   2026-10-22.
7. **Pipeline-signed identities (config management has the CSR signed through the API) would
   avoid the queue.** — Subsumed by pipeline approval against the verification code, which
   moves nothing secret at all.
8. **What a rejection does to the daemon, and whether `tag:` Labels are applied at approval
   once `tag:` has storage.** — open; decided at `/spec-author`.
