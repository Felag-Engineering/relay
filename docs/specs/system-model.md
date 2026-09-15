# System Model

**Status:** stub — deferred by the owner on `2026-09-14`; not in the first pass.

## Purpose

A flat list of Nodes tells an AI-agent what exists; it does not tell it what *matters*. The
System Model is a persistent, shared map of the fleet as a connected system — **Services**
(named groupings of Nodes), **Dependencies** between them, and **Annotations** carrying what
someone learned — so an AI-agent investigating an incident can reason about impact and ripple
effects instead of rediscovering the fleet's shape every session.

It is **advisory**. It informs which Selector an AI-agent chooses and how it reasons about blast
radius; it never executes, never widens anything, and is never a description of how the fleet
*should* be.

## Surfaces

Nothing reaches this capability yet. It is unbuilt and scheduled for milestone v1.1.0, after
the v1 contracts freeze, as additive-only work.

ADR-0008 designs it for MCP — reads as Resources, writes as Tools — and the v1.1.0 milestone
adds Control API parity. The Admin Console reserves a rollup component for a later view.

## Behaviour

_To be established by interrogation._

Candidate claims, from the ADRs and the code — each to be confirmed, changed or dropped:

- The semantic layer is Services, Dependencies and Annotations; a Service is a named Selector,
  a Dependency is a directed edge between Services, an Annotation is free text on any entity.
- Nodes and their Labels are grounding facts imported from the registry; nothing written
  through the System Model changes a Node or a `relay:` label.
- An AI-agent may create, update and delete Services, Dependencies and Annotations whenever it
  sees fit.
- Every mutation records its author (which AI-agent or which human), a timestamp, and an
  optional reason.
- The model is stored as human-readable YAML under version control, one commit per change, so a
  human can read, diff, blame, edit and revert it directly.
- A Service used for execution desugars to its Selector and passes through Selectors → Policy →
  blast cap exactly as a hand-written Selector would.
- The model never causes anything to run: there is no reconciler, scheduler or trigger reading
  it.

## Refusals

_To be established by interrogation._

Candidate claims, from the ADRs and the code — each to be confirmed, changed or dropped:

- An attempt to create, edit or delete a Node, or any `relay:` label, through the model is
  refused.
- A Service definition never grants reach its Selector would not already have.
- An Annotation is never a targeting input.

## Governing ADRs and invariants

- **Invariant 9** (ADR-0008) — the model is advisory, its grounding facts are AI-immutable, and
  it is never a desired-state spec; this capability is the thing that invariant describes.
- **ADR-0008** — the design: git-backed YAML, the three entity kinds, provenance, MCP exposure,
  desired-state reconciliation rejected permanently.
- **Invariant 7** (ADR-0020) — ADR-0020 rejected Services as a grouping mechanism *because* the
  model must never feed Selectors, which sits in tension with ADR-0008's "a Service desugars to
  a Selector" (see *Open questions*).
- **Invariants 1, 3, 5, 12** — whatever a Service resolves to still meets Policy, deny-beats-allow
  and the blast cap unchanged.
- **Invariant 10** — model reads and writes are capability-layer methods; MCP and the Control API
  are adapters.

## Seams and proof

_Not yet written._

## Out of scope

- Selector grammar, the Label namespaces and who writes each — `selectors-and-labels.md`.
- Operator grouping of Nodes for targeting — that is `tag:` labels (ADR-0020), in
  `selectors-and-labels.md`.
- Dispatch and the blast-radius cap — `execution.md`.
- Node reads and the registry — `query.md`.
- Desired-state reconciliation, drift remediation, and convergence toward a spec — out of realm
  permanently (`AGENTS.md`, ADR-0008).
- Scheduled health checks (Expectations) — deferred work in `docs/deferred.md`, not this spec.
- Incident memory and long-horizon reasoning that belongs to an AI-agent harness rather than
  to Relay.

## Decided in interrogation

- `2026-09-14` — **The System Model stays in Relay's scope, deferred.** Not designed or built in the
  first pass; this spec remains a stub. The owner sees a strong case for the model being recorded
  and available in Relay, and is open to moving it out. The two cases, for when it is picked up:
  - *In Relay:* one shared, audited record of what Services run where, available to every
    consumer — Gleipnir, other AI-agents, humans on the Console — rather than locked inside one
    AI-agent's memory.
  - *Out of Relay (into Gleipnir or another consumer):* it is the AI-agent's understanding of the
    fleet — intelligence, not mechanism — and Relay stays the arms and hands; a second store and a
    second audit trail (git) sit awkwardly beside the Relay's own.

## Open questions

1. **Is the System Model still wanted in Relay?** Since ADR-0008, Gleipnir has become a separate
   first-party app that already keeps its own memory. If the model is "intelligence", it may
   belong in the AI-agent harness; if it is shared mechanism every harness should see, it
   belongs here. Which is it?
2. **What is it for, operationally?** Name the question an AI-agent asks that the model answers
   and `list_nodes` plus labels does not. If the answer is "which Nodes are payments", `tag:`
   labels already do that.
3. **May a Service be used as a target?** ADR-0008 says a Service desugars to a Selector;
   ADR-0020 says the model never feeds Selectors. One of those has to give.
4. **Git-backed YAML or the Relay's store?** ADR-0008 chose git for free diff, blame and revert.
   The Relay otherwise persists to its store, HA wants Postgres (`docs/deferred.md`), and a git
   working tree is a second persistence mechanism with its own backup, locking and HA story.
5. **One audit trail or two?** Git commits carry provenance, and every capability action is also
   audited. Is a model change an audit record, a commit, or both — and which is authoritative?
6. **Can a human edit the YAML directly on disk**, bypassing the capability layer? ADR-0008
   treats that as a feature; invariant 10 treats any path around the capability layer as
   suspect.
7. **Which grounding facts are immutable?** ADR-0008 predates `tag:` and `state:`. May an
   AI-agent write `tag:` labels through the model, and does the model import `node:`, `tag:`
   and `state:` at all?
8. **Is full AI-agent write access right?** ADR-0008 bounds it with provenance and revert, and
   defers entry locking. A jailbroken AI-agent can rewrite the map that the *next* AI-agent
   trusts — is that acceptable, or must some entries be human-pinned from day one?
9. **Is it shared across AI-agents and Accounts, or scoped?** One map per Relay means one
   Account's edits steer every other AI-agent's reasoning.
10. Should a Service or Dependency be allowed to **reference a Node that no longer exists**, and
    what happens to the model when a Node is revoked?
11. Does the model ever inform **approval** — e.g. "this touches a Service marked critical" as a
    gate rule — or does that make an advisory model load-bearing?
12. Is **v1.1.0** still the right slot, or should the decision whether to build it at all be
    taken before the v1 freeze so the contracts do not need to anticipate it?

## History

- `2026-09-13` — stub created to name the capability.
