# Specs

One file per feature, written before the tickets that implement it.

A spec says **what** to build and **why it was decided that way**. It is disposable: it exists
to get a feature from a shaped conversation into buildable tickets, and it stops being the
source of truth the moment the feature ships. Nothing here is a desired-state document.

## The boundary against the other docs

| Question | Where it lives |
|---|---|
| How do we work? | `CLAUDE.md` |
| What do we call things? | `CONTEXT.md` |
| Why is the system shaped this way? | `docs/adr/` |
| What are we building, in what order, and when is it done? | `ROADMAP.md` |
| What exactly is *this one feature*? | here |

## Conventions

- `docs/specs/<slug>.md`, kebab-case, named for the feature — not the milestone.
- **The file is canonical; the issue is the work item.** Publish a tracking issue that links
  here, then keep the decisions in this file. Comments on the issue that change a decision get
  folded back into the spec.
- Name modules, interfaces, and contracts. **Never file paths or code snippets** — they go
  stale within a sprint. The one exception is a snippet that encodes a decision more precisely
  than prose can (a state machine, a schema, a type shape); trim it to the decision, not a
  working demo.
- Use `CONTEXT.md` vocabulary throughout, including the `_Avoid_` rules.
- A shipped spec stays in the tree. It is the record of what was intended, which is what makes
  a later "why is it like this?" answerable.

## Promote decisions that outlive the feature

The **Implementation Decisions** section is where architecture leaks. A spec is archived when
the feature ships; a decision left inside it becomes invisible, and someone "fixes" it later
not knowing it was deliberate.

If a decision is hard to reverse **and** surprising without context **and** the result of a
real trade-off, it is an ADR. Write the ADR in the same change, and have the spec cite the
number instead of carrying the reasoning.

If a decision touches Policy, execution, transport, mTLS, auth, `/proto`, blast caps, or label
authority, it is not yours to settle in a spec at all — see the escalation list in `CLAUDE.md`.

Start from [`TEMPLATE.md`](TEMPLATE.md).
