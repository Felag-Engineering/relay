# Policy

**Status:** aspirational — worked through with the owner on `2026-09-13`, awaiting their review
of this draft. Describes intended behaviour, not the code (see the establishing phase in
`README.md`).

## Purpose

Policy is a Node's own answer to *"what will I ever execute, no matter who asks?"* It is the
single document that defines everything that can run on a Node: which Native Operations are
allowed and with what arguments, the Template Operations the Node offers, and whether Raw Exec
is permitted at all.

It is the last line of defence. The Relay can be fully compromised and the AI-agent fully
jailbroken, and a Node still refuses everything its Policy does not allow. Policy is written by
people, delivered by the customer's config management like any other host configuration, and
never reachable from the wire. Relay can read it and ask it hypothetical questions; widening
what a Node will do is always a deliberate human act done outside Relay.

Everything the Relay adds on its side — roles, the blast-radius cap, approval, Freeze — narrows
what Policy allows. A Task can be allowed by Policy and refused by the Relay; never the reverse.

## Surfaces

- **Daemon-local.** A predefined drop-in directory beside the relay-daemon's configuration,
  holding Policy **fragments**: files the daemon composes into one evaluated Policy. The package
  owns its shipped fragments; the operator owns every other file. `relay-daemon policy check`
  validates a directory with the same engine that enforces.
- **Reload.** An explicit reload, triggered by config management after writing fragments.
- **Relay, read-only.** The daemon reports the whole evaluated Policy, its fingerprint, and its
  validity to the Relay on connect and on every reload. MCP `describe_node`, the Control API's
  node read and the Console display it; the display side belongs to `query.md`.
- **Hypotheticals.** `PolicyQuery` asks the live engine what it *would* decide; that capability
  is `policy-preflight.md`.
- **Enforcement.** Every Task the daemon receives is evaluated before an executor runs.
- **No writing surface.** Nothing on any Relay surface writes, delivers or signs Policy, by
  design (invariant 2).

## Behaviour

### What a Policy contains

- A Policy has four kinds of entry, in any fragment:
  - **Native rules** — named allow and deny rules over the arguments of the four Native
    Operations.
  - **Template definitions** — a name, a risk class, a fixed command structure, and typed
    parameter slots. A slot's allowed values are declared inline on the definition.
    **Defining a Template is what permits it.**
  - **The Raw Exec gate** — allow and deny patterns. Absent from every fragment, Raw Exec is off.
  - **Deny rules** — vetoes over any Native Operation, Template or Raw Exec command.
- Every argument and slot is matched **by name**, never by position.
- A Template name means one command structure everywhere it is defined. The values it permits
  may differ between Nodes, by a differently constrained definition in that Node's fragments.

### Composition

- The daemon reads every fragment in the Policy directory and evaluates them as **one Policy
  with one fingerprint**. Which fragment a rule came from affects only error messages.
- A Template name defined in more than one fragment is a Policy error. There is no override and
  no precedence by file order: to replace a shipped Template, deny it and define your own under
  a different name.

### Evaluation

- **Deny-by-default.** A Native Operation, Template or Raw Exec command that no entry permits is
  denied.
- **Deny beats allow.** A matching deny rule from any fragment vetoes, whatever permitted it and
  wherever that was written.
- A call naming an argument or slot the Operation does not have, or carrying a value that is not
  well-formed for its type, is **malformed** — rejected before Policy is consulted, with its own
  outcome, and never reported as a Policy denial.
- A path-typed argument not in strict canonical form (absolute; no `.`, `..` or empty segment;
  no trailing slash) is denied before any rule is consulted. `file.read` re-evaluates Policy
  against the target it actually opened and reads only from the descriptor it checked.

### Path patterns

One glob dialect for every path-typed argument and slot, matched case-sensitively against the
canonical path:

| Syntax | Matches |
|---|---|
| `*` | Any characters within one segment; never `/` |
| `**` | Zero or more whole segments; valid only as a complete segment |
| `?` | Exactly one character within a segment |
| Dot-files | `*` and `**` match names beginning with `.`, for allows and denies alike |
| Braces, character classes, negation, escapes | Unsupported — a Policy error, never a literal match |

### Raw Exec

- Argv only, never a shell (invariant 1).
- An allow pattern must match the **whole** command line; the daemon enforces the full match
  rather than relying on the author to anchor.
- An argv element containing whitespace is denied outright, as is an empty `argv[0]`.
- Deny patterns veto on the joined command line or on any single element.
- Whether a Node's Policy enables Raw Exec is part of what the Node reports, so "which Nodes
  permit Raw Exec?" is one query at the Relay.

### Load, reload and validity

- Policy is loaded at daemon start and on every explicit reload. There is no filesystem watching.
- On reload the daemon reads and validates the whole directory, then swaps the evaluated Policy
  atomically. Tasks already running finish under the Policy that admitted them; every later
  Task is evaluated against the new one.
- **Any Policy error rejects the whole Policy** — a fragment that fails to parse, a duplicate
  Template name, a fragment with unacceptable ownership or permissions, an invalid slot type, an
  unsupported pattern. The Node then denies every Task, stays connected, and reports
  `invalid` with the error and the fragment at fault. This holds identically at start and on
  reload: there is no last-known-good fallback, no partial load, and no built-in allowance.
- A fragment that is a symlink, is not a regular file, or is group- or world-writable is a
  Policy error. A fragment must be owned by root or by the daemon's own uid.
- The new fingerprint or `invalid` state reaches the Relay on reload without a reconnect.

### What the Relay sees

- The whole evaluated Policy: every Native rule, every Template definition including its command
  body, every deny rule, and the Raw Exec gate — readable by any Account permitted to read that
  Node. The deny-list is not treated as a secret.

### The shipped default

- The package ships a read fragment: every first-party `read`-class Template (the shipped read
  catalog), `system.facts`, and `file.read` of any path outside a curated confidentiality
  deny-list. It permits no `mutate` Operation and does not enable Raw Exec.
- The package replaces its own fragments on upgrade and never touches an operator's. An
  operator narrows the shipped default with a deny fragment; widening a shipped Template means
  defining a new one under a different name.

## Refusals

- **Denied by Policy.** A Task Policy does not permit resolves `denied_by_policy`, distinct from
  `failure`, `unsupported` and a malformed call. The denial is a structured `/proto` contract
  carrying, in its first pass, only:
  - a reason: `no_allow` (nothing permitted it) or `denied` (a deny rule vetoed it);
  - human-readable text. Caller-supplied text quoted into it is truncated to a fixed budget.
- **Malformed.** An unknown argument or slot name, or a value not well-formed for its type, gets
  its own outcome for Native and Template Operations alike — so a typo never reads as a denial
  and never sends an AI-agent into a retry loop.
- **Invalid Policy.** Every Task on a Node whose Policy is `invalid` is denied, and the denial
  says the Policy is invalid rather than naming a rule.
- **From the wire.** No message can add, remove, edit, deliver or reload a rule.
- **Approval is not Policy's to check.** Policy never permits anything "with approval": a Node
  cannot verify an approval claim without trusting the Relay that sends it, so Policy stays the
  floor that holds even when an approval is forged. Gating is `approval.md`.

## Governing ADRs and invariants

- **Invariant 2 / ADR-0002** — locally rooted and remotely immutable. Binds as written: Policy
  reaches a Node only through the customer's config management, and nothing on the Relay can
  deliver or sign it.
- **Invariant 3 / ADR-0002** — deny-by-default, deny-beats-allow, argument-level granularity.
  Binds as written; arguments are now matched by name.
- **Invariant 1 / ADR-0001** — nothing on the wire can compose or escalate a command. A
  Template's structure is fixed in a root-owned local file; Raw Exec is argv-only and gated here.
- **Invariant 12 / ADR-0011** — only the daemon's live engine evaluates Policy, hypotheticals
  included.
- **ADR-0021 — needs amending.** Templates are no longer a separate tier of files beside Policy;
  they are definitions inside Policy fragments, and the separate template-set fingerprint
  collapses into the Policy fingerprint. Its rejection of a daemon-side deny floor stands.
- **ADR-0018 — needs amending.** The deferred path matcher is resolved as the glob dialect above.
  Case and Unicode folding on a folding mount remains a recorded residual risk.
- **ADR-0019 — needs amending.** Whitespace-bearing argv elements are now denied outright, and
  allow patterns are full-match.
- **ADR-0022** — the shipped read posture stands, now expressed as a package-owned fragment.
- **ADR-0025** — reads are audited and output is not retained; this is the present answer to
  secrets in read output.
- **GLOSSARY.md — needs updating** for Template Operation, template pack and the template-set
  fingerprint, and gains *Policy fragment*.

## Seams and proof

_Not yet written._ This spec's claims are the backlog of its testing issue.

## Out of scope

- **Hypothetical evaluation** (`PolicyQuery`, preflight): `policy-preflight.md`.
- **Displaying Policy** on the Relay: `query.md`.
- **The Native vocabulary and the Template language** — the four Natives' argument schemas, slot
  types and what makes a value well-formed, and how slot values are substituted and quoted:
  `operations-and-templates.md`.
- **Relay-side authorization, approval, the blast-radius cap and Freeze**: `accounts-and-access.md`,
  `approval.md`, `execution.md`, `freeze.md`. Policy never consults them.
- **Getting fragments onto a Node and triggering reload**: `daemon-installation.md`, through the
  customer's config management.
- **Central Policy authorship.** Out of realm (AGENTS.md). A Template an AI-agent drafts ends as
  a proposal a human ships through config management.

## Accepted residual risk

- **Self-modification is a deployment concern.** That nothing a Task runs can write the Policy
  directory or trigger a reload rests on the shipped unit's filesystem sandbox, documented as a
  deployment requirement. The self-reference lint is a warning, not an error. Named so they are
  not forgotten: the `pkg.install` profile relaxes that sandbox; the daemon-uid ownership
  exception stands; an agentless tier (ADR-0037) would have no unit; and explicit reload makes
  a writable Policy directory a live escalation rather than one that waits for a restart.
- **Secrets in read output.** The confidentiality deny-list cannot know every file that holds a
  credential; read auditing records that such a file was read, not what it said.

## Future work

Wanted, deliberately not in the first pass. Named so each is neither re-litigated nor lost;
none is a commitment to an order.

- **Richer denial detail** — the deciding fragment and rule, the argument that decided it, the
  pattern that matched.
- **Shared Template definitions with separate allow rules** — one definition serving a fleet,
  with per-Node allowed values held apart from it.
- **A daemon-verified guarantee against self-modification** — the daemon itself establishes that
  nothing a Task runs can write the Policy directory or trigger a reload.
- **Output rules** — what a result may contain, enforced on the Node, the only place that sees
  output before it leaves and so the only place such a rule holds against a compromised Relay.
- **Distributing Policy through the Relay** — only if it adds no path by which the Relay can widen
  what a Node permits.

## Open questions

1. **Who sets a Template's risk class, and does the Relay trust it?** A Template's risk class is
   written in a Node's Policy and reported by that Node; the Relay picks the read or mutate
   blast cap from it. A compromised Node could report `read` for a mutating Template. Belongs to
   `execution.md` and `operations-and-templates.md`; forced before Templates are dispatchable.
2. **Does `invalid` become a `state:` label?** Targeting "every Node whose Policy is invalid"
   wants one, which adds to the closed vocabulary. `selectors-and-labels.md`; forced when the
   invalid state is built.
3. **What remains of `operations-and-templates.md`?** With Template definitions inside Policy, it
   shrinks to the Native vocabulary and the Template language. Settle when that spec is worked
   through.

## History

- `2026-09-13` — worked through with the owner. Policy and Templates collapse into one concept in
  a drop-in directory of fragments; explicit reload; any error invalidates the whole Policy and
  is reported; config management is the only delivery path (superseding the 2026-07-07
  signed-bundle direction); named arguments with inline slot constraints; glob path patterns;
  stricter Raw Exec; full Policy visible to the Relay; bare structured denials; no
  approval-in-Policy; output rules deferred.
- `2026-09-13` — stub created to name the capability.
