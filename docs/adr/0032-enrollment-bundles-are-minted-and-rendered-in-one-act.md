# Enrollment bundles are minted and rendered in one act

**Status:** Accepted; decisions 1 to 4 superseded by ADR-0048 (Relay renders no Enrollment Bundle).

Three surfaces need to hand an operator something that joins Nodes to a fleet: `relay init` at
first boot (ADR-0030), `/api/v1` for config management, and the Console from v0.7.0. Invariant
10 says they adapt one capability layer and never build a parallel path. The question is what
that capability is, and it is shaped by a constraint that is easy to design straight past.

**The Enrollment Token's plaintext is returned exactly once.** The Relay stores only its hash.
So an artifact that *contains* a token — a playbook, a shell one-liner, a join string — can only
be produced at the moment of minting. It can never be reproduced afterward, for any token, by
anyone, including the Relay.

An API that separates minting from rendering hides that constraint, and invites an endpoint that
looks obvious and cannot work: `GET /enrollment-tokens/{id}/playbook`. A Console built against
it would discover the problem in review at best, in a demo at worst.

## Decision

**1. One endpoint mints. Rendering is an option on it, not a second endpoint.**

`POST /api/v1/enrollment-tokens` gains an optional `render` field naming zero or more formats,
and returns a `renderings` map alongside the fields it already returns.

Two endpoints that both mint would mean two audit paths, two rate-limit paths, and two places to
get revocation right, in exchange for a noun. The mint stays singular.

**2. Rendering is a pure function** of the join string, the token's scope, and its expiry. No
store access, no side effects, nothing to audit that the mint did not already record. That
purity lets `relay init` call it locally inside its first-boot transaction and the Console call
it over the API, with one implementation.

**3. Formats at beta are `join`, `ansible`, and `shell`** — the bare join string, a playbook,
and the per-Node command. All three render the same three fields, so a fourth is a template, not
an architectural change.

**4. There is deliberately no re-render.** Losing the artifact means minting another token and
revoking the first. That is cheap, correct, and the honest surface of the hash-at-rest property
rather than a workaround for it.

**5. Minting requires `admin`, and that is a prerequisite rather than a footnote.**

**#397** established by probe that `POST /api/v1/enrollment-tokens` authenticated the caller and
never checked their role: a `viewer` could mint a token whose `scope` stamps `relay:` labels, the
namespace reserved for the security-sensitive lane. **E3 depends on #397 being fixed**: rendering
built on an ungated mint would put a playbook-shaped convenience wrapper around a privilege
escalation.

Rendering inherits the floor; there is no lesser tier that may render without minting, because
rendering without minting does not exist.

**6. The rendered playbook pins a daemon version and digest baked into the Relay build.**

The renderer must emit something installable, and the Relay does not otherwise know which daemon
artifact an operator wants. Of the three ways out — placeholders the operator fills, a build-time
constant, or installing from an OS package repository — the build-time constant is chosen for
now: the Relay is built knowing one known-good daemon version and its SHA-256, and renders them
into the playbook's `get_url` + `checksum` pair, preserving the verify-then-install contract
(`release-artifacts.md`) that a placeholder would leave to the operator to remember.

**The OS package is the intended end state** (ADR-0033): the playbook then installs a package and
pins nothing, because the package is the pinned artifact. That migration is deferred, not
declined: package *repository* hosting is a v1.0.0 commitment, and until a repository exists the
playbook would have to fetch and verify a `.deb` by digest anyway — which is what the baked-in
pin already does, with fewer moving parts.

The cost is a coupling: a Relay release names a daemon release, so shipping a daemon without
re-rendering that constant leaves operators installing an older daemon than the Relay knows
about. The `min-daemon-version` gate (ADR-0014) makes that legible rather than silent, and the
constant belongs under the same drift discipline as the packaging samples.

## Consequences

**The Console at v0.7.0 is a template and a copy button.** That is the point. If the Console work
needs backend changes, this ADR was implemented wrong.

**MCP gets this for free, and that is worth saying out loud**: an AI-agent holding an `admin`
Account can expand the fleet it operates. That is inside the Account model, not a hole in it —
the blast cap, Policy, and audit all still apply to whatever those Nodes then do — but "the agent
can add Nodes" belongs in the threat model's description of an `admin` machine Account, not
discovered later.

**The rendered playbook inlines the token** (ADR-0030, interim). Because rendering knows the
expiry, the artifact carries it in a header comment, and the short default TTL keeps the
inlining tolerable. Both properties live in the renderer, so the later switch to a
`{{ vault_… }}` placeholder is a template change in one place.

**`relay init` calls the capability, not a copy of it.** ADR-0030's falsifier — deleting
`docker/bootstrap.sh` — also tests this one: that script minted through the real Control API, and
whatever replaces it must keep doing so.
