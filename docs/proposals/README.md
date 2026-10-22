# Proposals

A proposal is **an idea with a lifecycle**: the one place work that is not yet decided lives,
and the one place the reasoning behind a decision stays once it is. It holds the problem, the
proposed answer, what it would change, and the objections raised against it with their
answers. An ADR records a decision in one page and links here for the argument; a spec records
behaviour and never cites a proposal at all (ADR-0046).

**A proposal never binds.** No spec claim, no issue acceptance criterion and no code comment
may cite one as authority. The loop reads proposals as context and never as a requirement.
`scripts/check-docs.sh` fails a spec or a source comment that references this directory.

## Lifecycle

| Status | Means | Leaves it by |
|---|---|---|
| `idea` | Captured, nobody has argued it yet | `/propose`, or closing it |
| `shaping` | Being grilled and refined with the owner; objections are being answered | The owner accepting or rejecting it |
| `accepted` | Decided. The ADR or the spec claims it became are named under *Outcome* | Nothing; it stays as the record of why |
| `rejected` | Decided against, with the authority named under *Outcome* | Nothing; it stays so the idea is not re-argued |

An issue labelled `idea` is the cheap intake. It becomes a file here when it is worth a page:
when it touches an invariant, an ADR or more than one spec, or when it has been raised twice.
An `accepted` proposal that names no ADR or claim, and a `rejected` one that names no
authority, fail the lint. An item on the out-of-realm list in `AGENTS.md` is `rejected` with
that list as its authority; a proposal does not reopen one.

## Shape

`TEMPLATE.md` is the shape; the lint holds it. At most 120 lines. Status on the third line.
Sections in this order: *Problem*, *Proposal*, *Changes*, *Objections*, and *Outcome* once the
status is `accepted` or `rejected`. Plain prose throughout: the reader is the owner deciding,
or a customer auditing the decision later. Name modules and contracts, never file paths or
code.

## The pipeline

`/propose <file>` is the interactive session that moves a proposal from `idea` to a decision.
It grills the idea with the `proposal-grill` agent, which reads only the documents and
attacks the proposal against the invariants, the ADRs, the out-of-realm list and the threat
model; the owner answers each objection and the answers land under *Objections*; then the
`spec-conflict-reviewer` and the `reader-reviewer` validate the text. An accepted proposal
enters the chain in `docs/agents/workflow.md` at `/spec-author`, which writes the ADR and the
Designed claims. Nothing here runs unattended.

## Where things used to live

`docs/deferred.md` was folded into this directory on 2026-10-22; each of its entries is a
file here with status `idea` or `shaping`. A spec's *Future work* and *Open questions*
sections are retired by the spec's next migration: future work becomes a proposal or an
`idea` issue, an open question becomes an issue labelled `decision`. The pre-ADR design
notes under `docs/design/` move here when next touched, or are deleted when the ADR they
led to exists.
