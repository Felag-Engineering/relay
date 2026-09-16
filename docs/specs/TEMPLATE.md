# <Capability name>

**Status:** current as of `<YYYY-MM-DD>`.
**Claim prefix:** `XX`

The date says when this spec was last checked against the code, not when it was last edited.
Status and claim prefix are the only header metadata: which surfaces reach this capability,
which ADRs govern it, and which invariants it touches all have their own sections below, and a
hand-maintained summary of a section two hundred lines down is a second source of truth that
nothing checks. The first version of `execution.md` carried one and it disagreed with its own
body, in both directions, within two days.

The prefix is two or three capital letters, unique across `docs/specs/`. Every claim in this
file is `**XX-n**`; `n` is never reused, so a retired claim leaves a gap and a History line.

## Purpose

What this capability is for, in the user's terms. Who reaches for it and what becomes possible.
Not a solution in disguise, and not a description of the code.

## Surfaces

How the capability is reached, per surface — tool names, API operations, Console screens. Name
them; never file paths. If a surface deliberately does not expose it, say so and say why: an
absence a reader can't distinguish from an oversight will get "fixed".

## Behaviour

The normative section: what this capability does **today**, on `main`. What is checked, in what
order, by whom, and what the caller gets back. Be precise about *where* each thing is enforced —
Relay-side authorization, the blast-radius cap before dispatch, and the daemon's live Policy
engine are three different places, and conflating them is how invariant 12 gets violated.

Write it as **claims**: one statement per bullet that a test could be pointed at, each with its
ID. Prose between claims is fine for orientation, but the claim is the unit.

- **XX-1** <a single statement about what the system does today>
- **XX-2** <another>

If a claim here is not true of the code, one of the two is a bug. A claim that is *decided but
not yet true* does not belong here — it belongs in *Designed, not built* below, and the loop
promotes it up when the PR that makes it true lands.

## Refusals

What this capability refuses, and what the caller is told. Cover the unhappy paths, the roles
that must be turned away, and every wall a jailbroken AI-agent would hit. Denials are a
product surface: a refusal that does not explain itself sends an agent looking for Raw Exec.

Refusals are claims too, with IDs from the same sequence.

- **XX-3** <what is refused, to whom, and what they are told>

## Governing ADRs and invariants

The ADRs that constrain this capability and the numbered `AGENTS.md` invariants it touches, each
with a sentence on *how* it binds here. If a change would contradict one, stop — that is a new
ADR in front of a human, not a spec edit. If it touches nothing, say so explicitly; that is a
useful claim to have reviewed.

## Seams and proof

Where this is tested. Prefer an existing seam to a new one, and the highest seam available —
the fewer seams across the codebase, the better. Name new ones explicitly and justify them.
Note whether `make verify` is sufficient, or whether changes here need `make test-integration`
or the dev fleet.

### What proves each claim

One row per claim above that something actually asserts. The loop maintains this table: the PR
that makes a claim true adds its row in the same change.

Naming test functions is a deliberate exception to the "never file paths" rule. A test name is
stable enough to cite, the link is verifiable, and a named test that no longer exists is a
signal the behaviour moved. Cite the test, never the file it lives in.

| Claim | Proven by | Seam |
|---|---|---|
| XX-1 | `TestName` | capability · MCP · API · compile-time · e2e |

**A claim with no row is a claim nothing checks.** List those IDs under the table rather than
dropping the claim or inventing a test that does not exist; they are the testing issue's backlog.

### Performance

The spec states the shape; the benchmark states the number. **Never quote a measured value
here** — it is environment-dependent and goes stale by nobody deciding anything, which is the
same failure mode as putting a headcount in an invariant.

| Characteristic | Contract | Measured by |
|---|---|---|
| <what varies with scale> | <what a caller may depend on> | `BenchmarkName` or *(none)* |

Keep three kinds of claim apart:

- **Contractual** — a caller may depend on it. It is behaviour, and belongs above as well.
- **Scale acceptance** — it must stay *correct* at N. That is a test, not a benchmark.
- **Observed** — how fast it is today. That is a benchmark, and only the benchmark's name
  belongs here.

*(none)* is an honest entry. It makes an unmeasured claim visible instead of unknown.

## Designed, not built

Decided, and not yet true of the code. Each row is a claim with an ID from the same sequence,
tagged with the milestone that delivers it, so a reader cannot mistake it for current behaviour
and `/decompose` can find it. When the implementing PR lands, the loop moves the claim into
Behaviour or Refusals — same ID, same words — and adds its proof row.

| Claim | Statement | Milestone |
|---|---|---|
| XX-4 | <what will be true> | <milestone title> |

Status is `designed, not built, as of <date>` while this table has rows and `current as of
<date>` once it is empty. Omit the section entirely when there is nothing to say — an empty one
invites filling. Everything above this section describes today. Nothing in it does.

## Out of scope

What this capability deliberately does not do, and where that work lives instead. Be specific:
this is the section a reviewer checks a diff against, and the one that stops an issue from
quietly widening the capability.

## Accepted residual risk *(optional)*

Risks a human decided to carry rather than close, each with who accepted it, when, and the
compensating control. Cross-reference the row in `docs/security/threat-model.md` where one
exists. A risk nobody accepted on the record is not residual; it is an open question.

## Future work *(optional)*

Named, not decided: work agreed in principle with no milestone and no ADR. The difference from
*Designed, not built* is exactly that — a Designed claim has a milestone; a Future work item
has a sentence. When one is decided it moves up, gets an ID and a milestone, and leaves here.

## Open questions

Decisions not yet made, each with what would force the call. An open question named here is
tracked; one left in a closed issue is lost.

## History

Dated one-liners: what changed about this capability, and the issue that changed it. Newest
first. This is how a spec stays trustworthy — a reader can see when it was last true.

- `<YYYY-MM-DD>` — <what changed> (#NNN)
