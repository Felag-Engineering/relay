# AGENTS.md

Instructions for AI agents working in this repository. Read this fully before making changes.
It holds what every session needs; procedure lives in `docs/agents/`, read when the task
reaches it.

## What this is

Relay is a **fleet-administration control plane**: it runs administrative commands on a fleet
of Linux servers and is drivable by an AI orchestrator. It is **security-critical by nature:
it is remote code execution as a service.** Treat every change to the execution, Policy,
transport or auth paths as security-sensitive.

The product is **Relay**. **Gleipnir** is the separate first-party AI-agent system that drives
it: a consumer of Relay, never a component of it (ADR-0016).

Orient in this order: [docs/how-relay-works.md](docs/how-relay-works.md) for the product in
plain words, the invariants below, [GLOSSARY.md](GLOSSARY.md) for the language, then
[docs/specs/](docs/specs/) for the capability you are touching. The [ADRs](docs/adr/) are the
decision log behind both: read one to learn or change a why. [README.md](README.md) is the
outside view.

## Ubiquitous language — use it exactly

[GLOSSARY.md](GLOSSARY.md) is canonical: every term, and the synonyms this project rejected.
An `_Avoid_` line is a decision, not a suggestion. Use the canonical term in code, comments,
commits, issue titles, test names and prose. The pair that must never be confused:

- **relay-daemon**: the non-AI Rust daemon on each Node. **Never call it "agent".**
- **AI-agent**: the AI orchestrator. The only thing called "agent", and always qualified.

Internal identifiers say `Relay` / `RELAY_`, never "gleipnir" (ADR-0016).

## Architecture invariants — do not violate without a new ADR

**Status: current as of 2026-09-21.** Every invariant below is a constraint the code is
expected to satisfy today, except where the gap table names otherwise. The date says when this
section was last audited against the code, not when it was last edited.

These are load-bearing decisions. If a task seems to require breaking one, **stop and flag it**;
it needs an ADR, not a quiet workaround.

1. **Nothing on the wire can compose or escalate a command.** A Task's arguments may never
   change which command runs, append a second one, or reach past what the Operation's author
   fixed. Execution is three tiers ordered by trust, each holding the line its own way: **Native**
   Operations by argv and never `/bin/sh`; **Template** Operations by a structure fixed in a
   root-owned local file, with no slot value ever part of the text the Template's shell parses;
   **Raw Exec**, the caller-supplied, exceptional tier, by being argv-only and regex-gated by
   Policy. New vocabulary is Templates, never new Natives: the Native vocabulary is frozen at
   four. Per-tier mechanism lives in `docs/specs/execution.md`. (ADR-0001, ADR-0021)
2. **Policy is locally-rooted and remotely-immutable.** The Relay may *query* a Node's Policy; it
   may **never** modify it over the wire. The daemon enforces; the Relay only reads. (ADR-0002)
3. **Deny-by-default, deny-beats-allow,** with argument-level granularity. (ADR-0002)
4. **At-most-once Task execution.** Tasks carry unique IDs; the daemon dedups across reconnects.
   Never make execution at-least-once. (ADR-0004)
5. **Blast-radius cap is enforced on the Relay before dispatch.** (ADR-0004)
6. **mTLS everywhere; the daemon refuses an untrusted Relay.** Node identity is its client cert.
   (ADR-0005, 0006)
7. **Labels are namespaced, and each namespace has exactly one writer.** Four namespaces, each
   immutable from every side but its own author: `node:` is written by the Node's own config
   management and never by the Relay; `relay:` by the Relay and never by the Node; `tag:` by a
   human Account through the control plane, never by an AI-agent or the Node; `state:` by
   nobody at all: it is Relay-derived from the registry, evaluated at Selector-resolution time
   from a closed vocabulary. No Account writes a `relay:` label directly: each `relay:` key is
   written only as the side effect of the Relay action that defines it. **The security lane
   targets only labels no Node can write.** Remediation and secret distribution target `relay:`
   and only `relay:`. Where a quarantine is engaged, which only ever reduces what may run, it may
   target `relay:` or `tag:`; lifting one targets `relay:` only. `node:` and `state:` are for
   routine targeting and are never a security-lane target. A compromised Node can forge its own
   `node:` labels, and can influence `state:` by lying in `Hello`, but never `relay:` or `tag:`.
   (ADR-0006, ADR-0020, ADR-0034, ADR-0050)
8. **`/proto` is the single source of truth** for the wire protocol and Operation vocabulary.
   Change the contract there; regenerate both sides. Don't hand-edit generated code. (ADR-0007)
9. **A fleet model is advisory; its grounding facts are AI-immutable.** Where Relay keeps a
   model of the fleet, it is never a desired-state spec: Relay does not auto-reconcile, ever.
   What Relay observed is always distinguishable from what anyone wrote; no AI-agent writes its
   grounding facts (Nodes, their identity, `relay:` labels); and the model never bypasses
   Selectors → Policy → blast cap. (ADR-0008, ADR-0051)
10. **One capability layer; every interface is an adapter over it.** Ports and adapters: the
    capability layer is the single implementation of what may be done, who may do it, and how it
    is recorded, decided there and never per interface. An adapter exposes that layer and
    **narrows only**: it may offer less than the layer allows, and it may never widen it,
    reimplement any part of it, or decide anything itself. Which surface exposes what is in the
    capability specifications, not here. Reaching a Node any other way is a parallel control
    path, and there is never a reason to build one; the `no_dispatch` structural guard covers
    each adapter. Where the Console executes, it does so preflight-by-default, with step-up
    re-authentication on a mutate apply, role-gated by the capability layer, and behind a switch
    set by whoever administers the Relay's host. (ADR-0009, ADR-0010, ADR-0026, ADR-0049,
    ADR-0052)
11. **Neither a credential nor the Relay itself can change the terms on which credentials
    are accepted.** The configuration that bounds *who may authenticate, and how recently they
    proved it* (listeners, which CA and TLS material are used, auth bootstrap, the identity
    provider Relay believes, session and step-up windows, and the approval notification path)
    is the **security floor**. It is set by whoever administers the Relay's host, outside
    Relay, and nothing Relay runs or accepts can write it: no API, no request, and not the Relay
    process. Key material the Relay generates (its CA key, the certificates it issues) is the
    Relay's own, not floor. Configuration that only bounds *reach* (blast caps, approval-gate
    rules, the minimum daemon version, rate and capacity limits) may be a runtime object,
    changed only by a human Account with step-up re-authentication, and audited. Secrets never
    pass through the environment or the command line; the Relay can read them and cannot
    rewrite them, except key material it generates itself. (ADR-0004, ADR-0010, ADR-0012,
    ADR-0027, ADR-0033, ADR-0043, ADR-0052)
12. **Policy is evaluated only by the daemon's live engine**, including hypotheticals
    (`PolicyQuery`, the Policy preflight). Never reimplement Policy evaluation on the Relay side.
    (ADR-0011, ADR-0049)
13. **Every Operation declares a risk class (`read` | `mutate`)**; blast caps are chosen by
    class, Raw Exec always takes the mutate-cap, and the class is security-relevant contract
    that no caller can set or loosen. Where the class is reported by Nodes rather than fixed in
    `/proto`, a dispatch takes the most restrictive class the Nodes it reaches report.
    (ADR-0012, ADR-0042)
14. **The daemon never self-upgrades and the Relay never pushes binaries.** Daemon upgrades
    flow only through the customer's config management; the Relay's lever is the
    dispatch-level minimum-version gate. (ADR-0014)

**The numbering is a public interface.** The threat model maps all fourteen to the boundaries
they defend, and the glossary, the specs and Go source comments cite them by number. Amend an
invariant in place and record the amendment in the ADR that makes it. **Never renumber or drop
one.**

**Amending one is not finished until its consumers are updated:** the threat model (nothing in
it notices an amendment), the capability specs that cite the invariant, `GLOSSARY.md`, and the
ADRs the amending ADR amends. Each records the amendment on its own page.

### Known gaps between these invariants and the code

Left in place deliberately: correcting invariant text needs an ADR amendment in front of a
human, which is a separate change. **Until that lands, believe this table over the invariant
text above.** **A row is deleted by the PR that closes its issue**: removing it is part of that
issue's definition of done, and that rule is the only thing keeping the table honest.

| # | The clause | What is actually true today | Tracked |
|---|---|---|---|
| 7 | Legacy `relay:` scope labels | `tag:` labels are stored on the Node record and written only through the capability layer's tag write, by a human Account at `operator` or above, on the Control API and the Console; `tag:` Selector terms resolve on every surface. A token's labels are written as initial tags, and on upgrade earlier scope labels are copied to tags (ADR-0050). What is not yet true, on Relays installed before that change only: the earlier `relay:` scope labels stay beside their tag copies, so `relay:` still holds keys no Relay action defines, and Nodes enrolled before `relay:node-id` existed lack it. Quarantine, the one later action that would write `relay:` labels, is cut from the MVP (`roadmap: relay/quarantine`). Behaviour detail in `docs/specs/selectors-and-labels.md`. | #1201 |

### Writing or amending an invariant

**A constraint, not a status report.** Write *"where X happens, it happens thus"*, never
*"X happens."* A constraint stays true across the milestone that builds it; a status claim goes
stale the moment it ships or slips.

**The property, not the mechanism that currently delivers it.** A mechanism-shaped invariant
breaks when a second mechanism satisfies the same property differently, as the Template tier
did to invariant 1's "argv, never `/bin/sh`". Mechanisms belong in the capability specification.

If a constraint genuinely cannot avoid asserting that something exists, it belongs in the gap
table with its issue number until it does.

## When documents and the code disagree

**Stop and escalate. Do not resolve it in either direction.** The right direction depends on
which statement disagreed, and getting it backwards is expensive: an agent that found a Policy
write path and "fixed the document to match the code" would amend away invariant 2.

| Conflict | What it means | Who resolves |
|---|---|---|
| An invariant ↔ the code | Either a security defect in the code, or a defect in this file | A human, always |
| A capability spec ↔ the code | Either the spec is stale, or the code has the bug the spec correctly describes | A human, always |
| A capability spec ↔ an ADR or an invariant | The spec is subordinate: the presumption is that the spec is the defect | A human, always |

A capability spec binds only once it is migrated to the claim format (Status `current` or
`designed, not built`). An `aspirational` or `stub` spec is intent, and drift from it is
expected; the invariant row always applies. Only ADRs and the invariants carry human sign-off by
construction, so nothing else silently wins against the code.

This governs a disagreement you **discover**. When you are **making** a change, the spec leads:
the capability specification first, then the code, in the same PR.

## Out of realm — proposed, and deliberately rejected

Each is a "no" with an authority behind it, so you may refuse the work outright. An issue never
redefines one; if a task appears to require one, stop and flag it.

- **Configuration management.** Relay is response and fleet administration. *If Ansible could
  check it in check-mode, it is out of realm.* (Owner decision.)
- **Desired-state reconciliation.** A fleet model is advisory. Relay does not converge a
  fleet toward a spec, ever. (Invariant 9)
- **Host telemetry.** Relay reports telemetry about itself and the fleet's relationship to it.
  It never collects or forwards metrics, logs or traces from Nodes; an AI-agent reads host state
  on demand through read Operations. (`docs/proposals/relay-does-not-carry-host-telemetry.md`)
- **Software distribution.** The Relay never pushes binaries and the daemon never
  self-upgrades. (Invariant 14)
- **Central Policy authorship.** The Relay may read a Node's Policy and may never write it.
  Policy authoring stops at the clipboard. (Invariant 2)
- **A general-purpose remote shell.** Raw Exec is a conspicuous, regex-gated exception to a
  typed vocabulary, not the primary path. (Invariant 1)
- **Widening the `relay` binary.** It may perform an act only if no credential could exist
  to perform it over the wire; a bootstrap command with no stated boundary becomes the removed
  CLI again, one convenient verb at a time. (ADR-0030)

## Pre-release mode

Until v1.0.0, the goal is a fleet up in 30 minutes, as simply and as securely as possible:

- **Simple and conservative beats complete.** Prefer a fixed, documented limit to a mechanism,
  and the narrower behaviour to the configurable one. Never relax an invariant to get there.
- **Decide LOW and INFO findings yourself.** Fix what is in scope and cheap; record the rest
  in the PR body. Escalate only a real trade-off: a security-posture change, behaviour a user
  sees, or a decision that is hard to reverse.
- **A gap outside the issue's scope is a proposed follow-up** in the PR body, never a fix cycle
  and never a reason to stop.
- **Fix only the docs your change makes false.** Name any others in the PR body.
- **Spend context on the change.** Grep `GLOSSARY.md` for the terms you touch; read a log by
  its failures, never whole.

## How to work here

The full chain (spec, design, decompose, implement), its human gates and the authority table
are [docs/agents/workflow.md](docs/agents/workflow.md); its *How to work here* section is the
step-by-step. The rules no session may skip:

- **Read before writing:** the glossary terms you touch and the capability spec; its ADRs
  only while that spec is `aspirational` or `stub` (`workflow.md`, step 1).
- **If you are implementing, you read a spec's claims and never write them.** A change that
  would make a claim in a migrated spec untrue is a stop-and-escalate. Bugs never get specs.
- **Contract-first.** Wire or Operation changes start in `/proto`, then regenerate.
- **`make verify` is the gate before a PR, not `make build test lint`.** A skipped gate is not a
  passed gate; say so in the PR body. Toolchains and commands: [CONTRIBUTING.md](CONTRIBUTING.md).
- **Promote before the issue closes.** Behaviour → the spec; a decision → an ADR; language → the
  glossary; reasoning → the decided proposal. A closed issue is not a record.
- **Security posture.** Never weaken Policy, never add an implicit shell to an Operation, never
  log secrets (tokens, private keys), never make the Relay able to mutate Node Policy. When in
  doubt on the daemon (privileged) side, prefer the more restrictive option and flag it.

## Code comments

A comment says what the code cannot: why it is this way, what it must never do, what would
break. No issue or PR numbers in shipped code (a test may cite the issue it regresses); cite the
spec claim or the invariant, an ADR only where the trade-off itself is the reason, and where
none holds the reason, state it. Present tense, never what the code used to do.
Short headers; rationale that needs a page belongs in an ADR. Match this section, not older,
denser neighbours. `make lint-comments` enforces the first rule.

## Routines & merge authority

This repo is **product-only** and is built largely by a Claude-driven loop, interactively and
as unattended cloud routines ([docs/agents/routines.md](docs/agents/routines.md)).

**Nothing merges autonomously. A person is always the merge authority.** On a repo that ships
remote code execution this does not relax because a run is unattended. If you are implementing
an issue: **stay in scope**, open a PR and never merge, and **stop and flag a human** rather
than guess on a hard call.

**Always escalate, never try to land without review:** anything on the security surface
(`docs/agents/security-surface.txt` is the one list), any failed build, any high-severity
review finding. Editing an invariant is never a docs chore.

**Running unattended changes what you have, not what you may do.** If a skill or command the
workflow depends on is missing, say so and stop; do not improvise the pipeline by hand. An
escalation you cannot deliver becomes a PR left unmerged with the reason stated plainly. Never
let a thinner environment become a weaker standard of proof.

## Agent skills

Agent skills read their per-repo configuration from `docs/agents/`; keep it current, because an
unattended routine uses it instead of asking: the issue tracker (`issue-tracker.md`, GitHub Issues on
`Felag-Engineering/relay`, milestones human-owned), the triage labels (`triage-labels.md`;
`decision` and `idea` are human-owned and never loop work), the domain rules (`domain.md`), the
routines and their `loop:halt` kill switch (`routines.md`), and the workflow (`workflow.md`).
