# Capability specifications

A capability is **an aspect of the system that should exist** — a coherent piece of what Relay
does. Each spec describes what that aspect does **today**, across every surface that reaches it.

A capability specification is **durable**. It is not a pre-implementation artifact that goes
stale once a feature ships — it is maintained as the capability evolves, and it is the answer
to "what does Relay actually do here?" for anyone, human or agent, who has to work on it.

## The establishing phase — every spec here is aspirational

**Until the spec-driven-development cutover, every file in this directory describes what the
owner wants Relay to do, not what the code does.** That holds whatever a spec's `**Status:**`
line says. The set is being established by interrogating the owner one capability at a time;
drift between a spec and the code is expected, and is the backlog the cutover works through.

While this banner stands:

- **A spec does not bind the code, and a disagreement with the code is not an escalation.** An
  implementing agent works from its issue, the ADRs and the invariants — which bind exactly as
  they always have — and treats a spec as context on intent, never as a requirement it must
  satisfy or a conflict it must stop on.
- **A stub is a legitimate file.** `**Status:** stub` means the capability belongs in the set
  and has not yet been worked through; its *Open questions* are where that session starts.
- The rules below describe how specs work **after** the cutover. The cutover is the change that
  deletes this section, and it is a human's call.

## Who writes these

**A human does, deliberately, in an interactive session.** A capability specification is never
authored or edited by an unattended run. An agent working alongside a human may draft and argue
and revise — that is what interactive sessions are for — but the artifact is human-owned, like
an ADR and like the invariants.

The loop that implements issues **reads** these and complies with them. If its work would make
a statement here untrue, it stops and escalates so a human can update the spec first; it does
not quietly edit the file and it does not quietly proceed. That is the same rule as *When
documents and the code disagree* in [`AGENTS.md`](../../AGENTS.md), applied one step earlier.

The reason for the asymmetry: these are the most impactful artifacts in the repo. Milestones,
issues, tests and benchmarks all decompose from them, so an error here propagates into
everything downstream — and a document an unattended agent may rewrite to match its own change
cannot also be the thing that constrains it.

## Status, and what `draft` means

A spec's `**Status:**` line is the only header metadata. Three states are in use:

| Status | Means | Cleared by |
|---|---|---|
| `current as of <date>` | Describes behaviour the code has today | Re-checking it against the code and moving the date |
| `designed, not built, as of <date>` | The shape is decided; no code implements it | The implementation landing, which moves it to `current` |
| `draft for human approval, checked against the code on <date>` | Drafted in an interactive session, not yet reviewed by a human | **The human merging it**, in the same change that moves the line to `current` |

`draft` is a pre-merge state, not a tier. It does not appear on `main`: a reviewer either
moves the line to `current as of <date>` as part of merging, or the spec does not merge.
That keeps *When documents and the code disagree* unambiguous — every spec on `main`
carries the same authority, and there is no half-approved spec for the conflict table to
be silent about.

## The two tiers

| Tier | Lives in | Lifespan | Answers |
|---|---|---|---|
| **Capability specification** | **here** | **Durable — maintained as the capability evolves** | **What does this capability currently do, across every surface?** |
| Implementation specification | A GitHub issue | Disposable — dies with its PR | How does *this change* get made? |

Above both sit the fourteen architecture invariants in [`AGENTS.md`](../../AGENTS.md), which
neither tier may contradict.

## Granularity is a judgement call

**There is no hard rule about what earns its own file.** A capability may be a section inside a
larger spec, or a spec of its own; the right answer is whichever reads better for the people and
agents who have to use it. Nothing here is tied to a package boundary or an architectural layer
— `enrollment` and `accounts-and-access` live outside the capability-layer package and still
warrant specs, because they are aspects of the system that should exist.

Two decompositions are wrong, and only two:

- **Per surface.** Invariant 10 makes the control plane surface-independent: MCP, the Control
  API and the Admin Console are adapters over the same decisions. A spec per surface states the
  same behaviour three times and drifts the moment one adapter changes.
- **Per milestone.** A document organised around when work shipped rots on the day that work
  closes, which is exactly what a durable document must not do.

A useful signal: **if an aspect is referenced by three or more specs, it wants its own file.**
That is why `selectors-and-labels.md` exists rather than being restated four times.

## The boundary against the other docs

| Question | Where it lives |
|---|---|
| What is Relay, and why is it shaped that way? | `README.md` |
| How do we work, and what must always be true? | `AGENTS.md` |
| What do we call things? | `GLOSSARY.md` |
| Why is the system shaped this way? | `docs/adr/` |
| What does capability X do today? | here |
| What are we building, in what order, and when is it done? | GitHub milestones and issues |
| How does this one change get made? | Its GitHub issue |

## Conventions

- `docs/specs/<capability>.md`, kebab-case, named for the aspect it covers — never for a
  milestone or a surface.
- **The file is canonical; the issue is the work item.** An implementation issue links here,
  and any decision an issue comment changes is folded back into this file before the PR merges.
- **Keep it current.** A change that alters what a capability does is not finished until its
  capability spec says so. A spec that describes behaviour the code no longer has is worse
  than no spec, because it is believed.
- **If a spec and the code disagree, stop and escalate** — do not resolve it in either
  direction. The spec may be stale, or the code may have the bug the spec correctly describes,
  and a spec carries no human sign-off by construction. See *When documents and the code
  disagree* in [`AGENTS.md`](../../AGENTS.md). That governs a disagreement you *discover*; when
  you are *making* a change, the spec leads and the code follows in the same PR.
- Name modules, interfaces, and contracts. **Never file paths or code snippets** — they go
  stale within a sprint. The one exception is a snippet that encodes a decision more precisely
  than prose can (a state machine, a schema, a type shape); trim it to the decision, not a
  working demo.
- Use `GLOSSARY.md` vocabulary throughout, including the `_Avoid_` rules.
- Describe behaviour, not implementation. If the *how* is interesting enough to record, ask
  whether it is an ADR.

## Promote what outlives the change

An implementation specification is a GitHub issue and is **disposable** — a closed issue is
not a record. Before the PR merges, lift everything in it that outlives the change:

- Behaviour that is now true of the system → **the capability specification here**.
- A decision that is hard to reverse **and** surprising without context **and** the result of a
  real trade-off → an **ADR**, cited by number rather than re-argued here.
- A shift in domain language → **`GLOSSARY.md`**, in the same change.
- A change to an architecture invariant → **`AGENTS.md`** plus an amendment recorded in its
  ADR, which is a conversation with a human and never a quiet edit.

If a decision touches Policy, execution, transport, mTLS, auth, `/proto`, blast caps, or label
authority, it is not yours to settle in a spec at all — see the escalation list in `AGENTS.md`.

## The capability set

The list is expected to move as the shape becomes clearer — a capability may split or merge
during the establishing phase — so treat it as the current decomposition rather than a closed
set. Rows marked *stub* exist so the capability is named; their content comes from the
interrogation.

| Spec | Covers |
|---|---|
| `execution.md` | Dispatch, fan-out, the blast-radius cap, at-most-once Tasks, the three Operation tiers, Raw Exec, cancellation |
| `selectors-and-labels.md` | The four namespaces and who writes each, the closed `state:` vocabulary, resolution-time evaluation, what a compromised Node can forge |
| `policy-preflight.md` | Daemon-evaluated hypotheticals and preflight-before-apply. Renamed from `plan-mode.md` by ADR-0038 |
| `plan.md` | The approved route of execution: steps, the cursor, the derived requirement, the plan hash |
| `approval.md` | Gate rules, callout, decisions and channels, approval Grants and scope |
| `freeze.md` | Emergency Freeze — engage, release, and its survival across a restart |
| `query.md` | Node, registry, Policy and vocabulary reads; `describe_node` |
| `audit-and-read-lane.md` | The audited read lane, audit records, the retention posture |
| `enrollment.md` | Enrollment Tokens, join strings, bundles, identity issuance and revocation |
| `accounts-and-access.md` | Accounts, roles, Grants, API tokens, OAuth sessions, attribution |
| `policy.md` *(stub)* | The daemon's Policy itself: the local file, deny-by-default and deny-beats-allow, argument-level and canonical matching, the shipped default read Policy |
| `operations-and-templates.md` *(stub)* | The Operation vocabulary and its golden schema, risk classes, the frozen Native set, the local Template catalog |
| `node-connection.md` *(stub)* | The mTLS session, `Hello`, reconnect and dedup, liveness in the registry, the minimum-version gate |
| `relay-configuration.md` *(stub)* | Operator-set startup config unreachable from any API, secrets as file paths, `relay init`, Relay packaging |
| `daemon-installation.md` *(stub)* | Installing and configuring the relay-daemon on a Node through the customer's config management |
| `quarantine-node.md` *(stub)* | Quarantining a distrusted Node: fencing it off from routine work, targeted only through `relay:` labels |
| `system-model.md` *(stub)* | Services, Dependencies and Annotations: the advisory, git-backed model and its AI-immutable grounding facts |
| `observability.md` *(stub)* | What an operator can see of Relay's own health: metrics, logs, and what they must never contain |

Start from [`TEMPLATE.md`](TEMPLATE.md).
