# Tags are the operator's labels

**Status:** Accepted (owner decision 2026-10-23).

Behaviour: `docs/specs/selectors-and-labels.md`, `docs/specs/enrollment.md` and
`docs/specs/accounts-and-access.md`. This ADR amends ADR-0020 and AGENTS.md invariant 7, and
supersedes in part ADR-0048 decision 4 and ADR-0006's amendment of 2026-10-22, where an
Enrollment Token's scope is a set of `relay:` Labels.

## Decision

People group their Nodes with tags, such as `tag:env=prod` or `tag:team=payments`, and the MVP
builds them. Only a person can write a tag: a human Account at `operator` or above, on a Node's
page in the Console, in bulk over the Nodes a Selector matches, or through the Control API. No
AI-agent and no Node can. Every change is audited. The labels an admin names when minting a join
token are written as each joining Node's first tags, so a fleet is grouped as it arrives and can
be regrouped later without re-enrolling. `relay:` keeps only the keys Relay itself defines.

## The decisions

1. **`tag:` is built for the MVP.** A tag is `tag:key=value`, stored on the Node's record in the
   Relay's store, and valid in any Selector on every surface. ADR-0020's design stands where this
   ADR does not change it: Node-immutable, prefix mandatory, 64 tags per Node.
2. **Only a human Account at `operator` or above writes a tag.** The Console offers it on Node
   detail, and in bulk from the Fleet view: "tag every Node this Selector matches", with a
   confirmation that lists the matched Nodes before anything is written. The Control API offers the
   same two acts. No MCP tool writes a tag and none may be added; a machine Account is refused on
   every surface. Each change is one audit record with the Account, the Node and the old and new
   values. No step-up, as ADR-0020 decided: a tag gates nothing.
3. **A join token's labels are initial tags.** A mint names zero or more `tag:` labels; the
   enrollment writes them on each Node it enrolls, as the minting admin's act, and afterwards they
   are ordinary tags. A mint naming any `relay:` label is refused, naming it. A machine Account
   may mint, as ADR-0032 allows an `admin` to, but its mint may name no initial tag: a tag is
   always a person's act. On upgrade, the `relay:` labels earlier releases wrote from a token a
   human Account minted are copied to tags of the same key and value, attributed to that Account,
   and such a token not yet used writes its scope as initial tags; labels from a machine Account's
   token are not copied, and their Nodes are listed for a person to tag. `relay:node-id` is
   untouched.
4. **`relay:` holds only keys a Relay action defines.** Today that is `relay:node-id`, written by
   enrollment (ADR-0048). The security lane, remediation and secret distribution, targets `relay:`
   only, so it addresses Nodes by `relay:node-id` until a later action defines a group key.
5. **A tag never changes what a gate rule matches.** Gate rules match risk class, Operation,
   Account, Selector namespace and fan-out, never a label value (ADR-0047), so retagging a Node
   cannot move a dispatch out of a gate. It can move a Node into or out of a routine Selector,
   which is what tags are for.

## Why

An operator setting up a fleet thinks in groups: production, the web tier, the payments team. The
join token's `relay:` scope gave them groups only at enrollment and fixed for life, and the
security lane's namespace was carrying everyday grouping. Tags are the namespace ADR-0020 designed
for that traffic. Keeping the writer a person is what makes a tag worth trusting: an AI-agent that
could retag Nodes could redirect the routine Jobs another person aimed at a group.

## What changes

- `selectors-and-labels.md`: the tag claims, the writer rule and the bulk act. `enrollment.md`:
  scope becomes initial tags. `accounts-and-access.md`: the tag write in the role table.
- AGENTS.md invariant 7: `tag:` is written by a human Account through the control plane, never by
  an AI-agent or the Node; the gap row for `tag:` closes when the code lands.
- `GLOSSARY.md`: *Tag* and *Enrollment Token*; the threat model: the tag writer and R13.

## Alternatives

- **Keep labels at enrollment only.** Already built, but regrouping a Node means re-enrolling it.
- **Let AI-agents write tags.** Convenient, and a tag would then be only as trustworthy as the
  AI-agent that wrote it.
- **Keep both `relay:` scope and tags.** Stronger groups for the security lane, at the cost of two
  label kinds that look alike to the person setting up a fleet.
