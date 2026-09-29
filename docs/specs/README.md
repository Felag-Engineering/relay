# Capability specifications

A capability is **an aspect of the system that should exist** — a coherent piece of what Relay
does. Each spec describes what that aspect does **today**, across every surface that reaches it.

A capability specification is **durable**. It is not a pre-implementation artifact that goes
stale once a feature ships — it is maintained as the capability evolves, and it is the answer
to "what does Relay actually do here?" for anyone, human or agent, who has to work on it.

## The establishing phase — per spec, not per repo

**A spec binds the loop only once it has been migrated to the claim format**, which
`TEMPLATE.md` describes and `scripts/check-docs.sh` enforces: Behaviour and Refusals hold only
what is true of `main` today, every claim carries an ID, and everything decided-but-unbuilt sits
under *Designed, not built* with a milestone. Migration happens one spec at a time, in an
interactive session (`/spec-author --migrate <spec>`), using `/spec-drift` to sort the claims.

Until a spec is migrated its status is `aspirational` (worked through with the owner, drift from
the code expected) or `stub` (named, not yet worked through). Such a spec is **context, not a
requirement**: an implementing agent works from its issue, the ADRs and the invariants — which
bind exactly as they always have — and treats the spec as intent. A disagreement between an
unmigrated spec and the code is not an escalation.

The establishing phase ends for the repo when no spec carries either legacy status. Nothing
else changes on that day: the rules below already apply to every migrated spec.

## Who writes these

**A human does, co-authored, in an interactive session.** A capability specification is never
authored or edited by an unattended run. `/spec-author` is that session: an agent interrogates,
drafts, argues and revises; the human decides, and the artifact is theirs, like an ADR and like
the invariants. The same holds for ADRs, `GLOSSARY.md` and the invariants — co-authored, human-
driven, never unattended.

The loop that implements issues **reads** these and complies with them. If its work would make
a claim here untrue, it stops and escalates so a human can update the spec first; it does not
quietly edit the claim and it does not quietly proceed. That is the same rule as *When
documents and the code disagree* in [`AGENTS.md`](../../AGENTS.md), applied one step earlier.

The loop does maintain the parts of a spec that are *evidence* rather than intent: the proof
rows, the Performance rows and the Status line, and it promotes a claim from
*Designed, not built* into Behaviour when the PR that makes it true lands — same ID, same words.
The authority table in [`docs/agents/workflow.md`](../agents/workflow.md) is the full split.

The reason for the asymmetry: these are the most impactful artifacts in the repo. Milestones,
issues, tests and benchmarks all decompose from them, so an error here propagates into
everything downstream — and a document an unattended agent may rewrite to match its own change
cannot also be the thing that constrains it.

## Claims and status

A spec is a set of **claims** — single statements a test can be pointed at — each with a stable
ID `<PREFIX>-<n>`. The prefix is declared in the spec's header and is unique across this
directory; `n` is never reused. IDs are what let a design say which claims it delivers, an issue
name the claims it implements, and a PR's proof rows cite them.

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

**There is no hard rule about what earns its own file.** A capability may be a section inside a
larger spec, or a spec of its own; the right answer is whichever reads better for the people and
agents who have to use it. Nothing here is tied to a package boundary or an architectural layer
— `enrollment` and `accounts-and-access` live outside the capability-layer package and still
warrant specs, because they are aspects of the system that should exist.

Two decompositions are wrong, and only two:

- **Per surface.** Invariant 10 makes the control plane surface-independent: MCP, the Control
  API and the Admin Console are adapters over the same decisions. A spec per surface states the
  same behaviour three times and drifts the moment one adapter changes. What a surface does *on
  its own* — the Console's session, CSRF/CSP, step-up windows, the `console_execution` flag —
  is an aspect like any other and may have a file (`console.md`, decided 2026-09-20); what it
  exposes of another capability belongs in that capability's Surfaces table.
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
- **If a migrated spec and the code disagree, stop and escalate** — do not resolve it in
  either direction. The spec may be stale, or the code may have the bug the spec correctly
  describes. See *When documents and the code disagree* in [`AGENTS.md`](../../AGENTS.md). That
  governs a disagreement you *discover*; when you are *making* a change, the spec leads and the
  code follows in the same PR — through the chain in
  [`docs/agents/workflow.md`](../agents/workflow.md).
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
| `policy-preflight.md` | Daemon-evaluated hypotheticals and preflight-before-apply. Renamed from the plan-mode spec by ADR-0038 |
| `plan.md` | The approved route of execution: steps, the cursor, the derived requirement, the plan hash |
| `approval.md` | Gate rules, callout, decisions and channels, approval Grants and scope |
| `approval-assurance.md` *(stub)* | The approval assurance properties shelved by ADR-0040 pending the permissions rework: out-of-band as a rule requirement, a Relay-verified approver, the grant-issuance floor, second-person rules whose second person Relay authenticated |
| `freeze.md` | Emergency Freeze — engage, release, and its survival across a restart |
| `query.md` | Node, registry, Policy and vocabulary reads; `describe_node` |
| `audit-and-read-lane.md` | The audited read lane, audit records, the retention posture |
| `enrollment.md` | Enrollment Tokens, join strings, bundles, identity issuance and revocation |
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
