# Capability specifications

A capability is **an aspect of the system that should exist** — a coherent piece of what Relay
does. Each spec describes what that aspect does **today**, across every surface that reaches it.

A capability specification is **durable**: maintained as the capability evolves, not left to
go stale once a feature ships. It answers "what does Relay actually do here?" for anyone,
human or agent, who has to work on it.

**Reading these from outside.** A spec's Status banner (`aspirational`, `stub`,
`designed, not built`, `current`) records how far that spec has migrated to the claim format
below — not how much of the capability is built. For the product view — what each capability
does today on MCP, the Control API and the Admin Console — read [`STATUS.md`](../STATUS.md).

## The establishing phase — per spec, not per repo

**A spec binds the loop only once it has been migrated to the claim format**, which
`TEMPLATE.md` describes and `scripts/check-docs.sh` enforces: Behaviour and Refusals hold only
what is true of `main` today, every claim carries an ID, and everything decided-but-unbuilt sits
under *Designed, not built* with a milestone. Migration happens one spec at a time, in an
interactive session (`/spec-author --migrate <spec>`), using `/spec-drift` to sort the claims.

Until then a spec is `aspirational` (worked through with the owner, drift from the code
expected) or `stub` (named, not yet worked through). Such a spec is **context, not a
requirement**: an implementing agent works from its issue, the ADRs and the invariants, which
bind as always, and treats the spec as intent. A disagreement between an unmigrated spec and
the code is not an escalation.

The establishing phase ends when no spec carries either legacy status. Nothing else changes
that day: the rules below already apply to every migrated spec.

## Who writes these

**A human does, co-authored, in an interactive session** — never an unattended run. The same
holds for ADRs, `GLOSSARY.md` and the invariants. `/spec-author` is that session: an agent
interrogates, drafts, argues and revises; the human decides, and the artifact is theirs.

The loop that implements issues **reads** these and complies with them. If its work would make
a claim untrue, it stops and escalates so a human can update the spec first; it neither edits
the claim nor proceeds. That is *When documents and the code disagree* in
[`AGENTS.md`](../../AGENTS.md), applied one step earlier.

The loop does maintain a spec's *evidence*: the generated Proof block and the Status line. It
also promotes a claim from *Designed, not built* into Behaviour when the PR that makes it true
lands — same ID, same words. The authority table in
[`docs/agents/workflow.md`](../agents/workflow.md) is the full split.

## Two layers

A spec is written for two readers at once (ADR-0046). Its *Purpose* is plain prose, at most
120 words, for an owner deciding or a customer auditing: what the capability is for and what
it refuses to be. Everything below binds the loop. The shape is `TEMPLATE.md`, exactly:
Purpose, Surfaces, Behaviour, Refusals, Designed when any, Out of scope, a Proof block that
`make spec-proof` generates from the tests, and a Retired list. Nothing else: residual risk
lives in the threat model's register, future work in the private roadmap or an issue labelled
`idea`, an open question in an issue labelled `decision`, and the governing ADRs on one
`**Governed by:**` line. A spec stays under 250 lines outside its Proof block. A spec still in
the earlier shape is listed in `docs/agents/docs-ratchet.txt`; the PR that next touches it
migrates it and drops its line.

The reason for the asymmetry: milestones, issues, tests and benchmarks all decompose from these
specs, so an error here propagates everywhere downstream — and a document an unattended agent
may rewrite to match its own change cannot also constrain it.

## Claims and status

A spec is a set of **claims** — single statements a test can be pointed at — each with a stable
ID `<PREFIX>-<n>`. The prefix is declared in the spec's header and is unique across this
directory; `n` is never reused. Designs, issues and PR proof rows cite claims by ID.

A claim lives in one of two places, and status follows from which:

| Status | Means | Cleared by |
|---|---|---|
| `current as of <date>` | Every claim is in Behaviour or Refusals and was checked against the code on that date; *Designed, not built* is absent | Re-checking it against the code and moving the date |
| `designed, not built, as of <date>` | Behaviour is true today **and** *Designed, not built* has rows tagged with a milestone | The loop promoting the last Designed claim, which moves the line to `current` |
| `aspirational — …` | Legacy, unmigrated: intent worked through with the owner, drift expected, not binding | `/spec-author --migrate` |
| `stub — …` | Legacy, named but not worked through | `/spec-author` |

`check-docs` enforces the first two shapes and ignores the last two. There is no `draft`: a spec
change is a PR, and the human merging it is the approval.

## The two tiers

| Tier | Lives in | Lifespan | Answers |
|---|---|---|---|
| **Capability specification** | **here** | **Durable — maintained as the capability evolves** | **What does this capability currently do, across every surface?** |
| Implementation specification | A GitHub issue | Disposable — dies with its PR | How does *this change* get made? |

Above both sit the fourteen architecture invariants in [`AGENTS.md`](../../AGENTS.md), which
neither tier may contradict.

## Granularity is a judgement call

**No hard rule says what earns its own file.** A capability may be a section of a larger spec
or a spec of its own, whichever reads better. Nothing here follows a package boundary or an
architectural layer: `enrollment` and `accounts-and-access` live outside the capability-layer
package and still warrant specs.

Two decompositions are wrong, and only two:

- **Per surface.** Invariant 10 makes the control plane surface-independent: MCP, the Control
  API and the Admin Console are adapters over the same decisions. A spec per surface states the
  same behaviour three times and drifts the moment one adapter changes. What a surface does *on
  its own* — the Console's session, CSRF/CSP, step-up windows, the `console_execution` flag —
  is an aspect like any other and may have a file (`console.md`, decided 2026-09-20); what it
  exposes of another capability belongs in that capability's Surfaces table.
- **Per milestone.** A document organised around when work shipped rots the day that work
  closes.

A useful signal: **if three or more specs reference an aspect, it wants its own file** — which
is why `selectors-and-labels.md` exists.

## The boundary against the other docs

| Question | Where it lives |
|---|---|
| What is Relay, and why is it shaped that way? | `README.md`, then `docs/how-relay-works.md` |
| How do we work, and what must always be true? | `AGENTS.md` |
| What do we call things? | `GLOSSARY.md` |
| Why is the system shaped this way? | `docs/adr/`, one page each |
| What was argued, and what was decided against? | `docs/proposals/`, for decided proposals |
| What risk was accepted, by whom? | the register in `docs/security/threat-model.md` |
| What does capability X do today? | here |
| What are we building, in what order, and when is it done? | GitHub milestones and issues |
| How does this one change get made? | Its GitHub issue |

## Conventions

- `docs/specs/<capability>.md`, kebab-case, named for the aspect it covers — never for a
  milestone or a surface.
- **The file is canonical; the issue is the work item.** An implementation issue links here,
  and any decision an issue comment changes is folded back into this file before the PR merges.
- **Keep it current.** A change that alters what a capability does is not finished until its
  spec says so. A spec describing behaviour the code no longer has is worse than none, because
  it is believed.
- **If a migrated spec and the code disagree, stop and escalate** — do not resolve it in
  either direction (*When documents and the code disagree* in [`AGENTS.md`](../../AGENTS.md)).
  That governs a disagreement you *discover*; when you are *making* a change, the spec leads
  and the code follows in the same PR, through the chain in
  [`docs/agents/workflow.md`](../agents/workflow.md).
- Name modules, interfaces, and contracts. **Never file paths or code snippets** — they go
  stale within a sprint. The one exception is a snippet that encodes a decision more precisely
  than prose can (a state machine, a schema, a type shape), trimmed to the decision.
- Use `GLOSSARY.md` vocabulary throughout, including the `_Avoid_` rules.
- Describe behaviour, not implementation. If the *how* is worth recording, ask whether it is
  an ADR.

## Promote what outlives the change

An implementation specification is a GitHub issue and is **disposable** — a closed issue is
not a record. Before the PR merges, lift everything in it that outlives the change:

- Behaviour that is now true of the system → **the capability specification here**.
- A decision that is hard to reverse **and** surprising without context **and** the result of a
  real trade-off → an **ADR**, cited by number rather than re-argued here; the argument itself
  → the **proposal** the ADR links.
- Work agreed in principle but not decided → a **proposal** in the private roadmap, or an issue
  labelled `idea`; an open question → an issue labelled `decision`.
- A shift in domain language → **`GLOSSARY.md`**, in the same change.
- A change to an architecture invariant → **`AGENTS.md`** plus an amendment recorded in its
  ADR, which is a conversation with a human and never a quiet edit.

If a decision touches Policy, execution, transport, mTLS, auth, `/proto`, blast caps, or label
authority, it is not yours to settle in a spec at all — see the escalation list in `AGENTS.md`.

## The capability set

This is the current decomposition, not a closed set: a capability may still split or merge.
Rows marked *stub* exist so the capability is named.

| Spec | Covers |
|---|---|
| `execution.md` | Dispatch, fan-out, the blast-radius cap, at-most-once Tasks, the three Operation tiers, Raw Exec, cancellation |
| `selectors-and-labels.md` | The four namespaces and who writes each, the closed `state:` vocabulary, resolution-time evaluation, what a compromised Node can forge |
| `policy-preflight.md` | Daemon-evaluated hypotheticals and preflight-before-apply (ADR-0038) |
| `plan.md` | The approved route of execution: steps, the cursor, the derived requirement, the plan hash |
| `approval.md` | Gate rules, callout, decisions and channels, approval Grants and scope |
| `freeze.md` | Emergency Freeze — engage, release, and its survival across a restart |
| `query.md` | Node, registry, Policy and vocabulary reads; `describe_node`; Policy aliases |
| `audit-and-read-lane.md` | The audited read lane, audit records, the retention posture |
| `enrollment.md` | Enrollment Tokens, join strings, identity issuance and revocation |
| `accounts-and-access.md` | Accounts, roles, Grants, API tokens, OAuth sessions, attribution |
| `policy-catalog.md` | First-party opt-in catalog fragments, their release digests, and the Console screen that arranges them into cohorts and exports them; never applied over the wire |
| `policy.md` | The daemon's Policy itself: the local file, deny-by-default and deny-beats-allow, argument-level and canonical matching, the shipped default read Policy |
| `operations-and-templates.md` | The Operation vocabulary and its golden schema, risk classes, the frozen Native set, the local Template catalog |
| `node-connection.md` | The mTLS session, `Hello`, reconnect and dedup, liveness in the registry, the minimum-version gate |
| `relay-configuration.md` | The security floor and the operator settings, secrets as file paths, `relay init`, Relay packaging |
| `daemon-installation.md` | Installing and configuring the relay-daemon on a Node through the customer's config management |
| `quarantine-node.md` | Quarantining a distrusted Node: fencing it off from routine work; engaging may target `relay:` or `tag:`, lifting `relay:` only |
| `system-model.md` *(stub)* | Services, Dependencies and Annotations: the advisory, git-backed model and its AI-immutable grounding facts |
| `observability.md` | What an operator can see of Relay's own health: metrics, logs, and what they must never contain |
| `console.md` *(not yet written)* | What only the Admin Console does: session, CSRF/CSP, step-up windows, the `console_execution` flag, role gating. Screens stay in `docs/design/console/` |

Start from [`TEMPLATE.md`](TEMPLATE.md), and run `/spec-check` before opening the PR.
