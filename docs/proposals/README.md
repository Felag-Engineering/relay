# Proposals: decision records

This directory holds the **reasoning behind decisions already made**: the problem, the
proposal, the objections raised against it and the answers the owner gave, and the outcome.
An ADR states a decision in one page and links here for the argument (ADR-0046), so a customer
auditing Relay can see not only what was decided but what was weighed.

**Only decided proposals live here**, with status `accepted` or `rejected`. Ideas still being
argued, and research into where the product may go, are tracked privately in Felag Engineering's
roadmap (ADR-0046, amended 2026-10-22). A public document refers to one by project and slug, as
plain text: `roadmap: relay/n-party-approval`. `scripts/check-docs.sh` fails a proposal here whose
status is `idea` or `shaping`.

**A proposal never binds.** No spec claim, no issue acceptance criterion and no code comment may
cite one as authority; the ADR it led to does. `scripts/check-docs.sh` fails a spec claim or a
source comment that references this directory.

## Shape

`TEMPLATE.md` is the shape, and the lint holds it: status on the third line, then *Problem*,
*Proposal*, *Changes*, *Objections* and *Outcome*, at most 120 lines, plain prose. *Outcome*
names the ADR or the claim IDs an accepted proposal became, or who rejected it and on what
authority.

## How a proposal gets here

`/propose` grills an idea with the owner, in the private roadmap, against the invariants, the
ADRs and the threat model. When the owner decides, the decided proposal is copied here in the
same PR as the ADR it led to, and the roadmap's copy names that ADR in its *Outcome*.
