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
  - **Template definitions** — a name, a description, a risk class, a fixed command
    structure, and typed parameter slots. A slot's allowed values are declared inline on the
    definition. The Template language itself is `operations-and-templates.md`.
    **Defining a Template is what permits it.**
  - **The Raw Exec gate** — allow and deny patterns. Absent from every fragment, Raw Exec is off.
  - **Deny rules** — vetoes over any Native Operation, Template or Raw Exec command.
- Every argument and slot is matched **by name**, never by position.
- A Template name means one command structure everywhere it is defined. The values it permits
  may differ between Nodes, by a differently constrained definition in that Node's fragments.

### Composition

> **Not yet reconciled (`2026-09-19`).** The v0.7.0 first cut of the Policy directory is
> `daemon-installation.md`'s, not this section's: a Policy file plus a directory of fragments,
> applied by restart, a bad-mode fragment refusing start like the Policy file, and no
> package-owned fragments (#648, `policy-catalog.md`). Explicit reload, Templates inside
> fragments, package-owned fragments and a reported `invalid` state remain this spec's intent,
> to be reconciled when it is migrated.

- The Policy directory is `/etc/relay-daemon/policy.d`, beside the Policy file
  `/etc/relay-daemon/policy.toml` (owner decision, 2026-10-16; `daemon-installation.md` DI-36).
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

> **Not yet reconciled (`2026-09-19`)** — see *Composition*.

- Policy is loaded at daemon start and on every explicit reload. There is no filesystem watching.
- On reload the daemon reads and validates the whole directory, then swaps the evaluated Policy
  atomically. Tasks already running finish under the Policy that admitted them; every later
  Task is evaluated against the new one.
- **Any Policy error rejects the whole Policy** — a fragment that fails to parse, a duplicate
  Template name, a fragment with unacceptable ownership or permissions, an invalid slot type, an
  unsupported pattern. A Template slot in a decidable code-running position makes the Template
  set unloadable instead, and Native Operations keep running (ADR-0021, amended 2026-10-15;
  `operations-and-templates.md`). The Node then denies every Task, stays connected, and reports
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

> **Not yet reconciled** — see *Composition*. Until then the shipped default stays one
> operator-owned Policy file (ADR-0022, ADR-0033 §4) and is not a catalog fragment. ADR-0033's
> 2026-10-15 amendment keeps it that way under packaging: the daemon package places the default
> only when no Policy file exists and never rewrites it, and the shipped read catalog arrives in
> its own optional package rather than with the daemon (`daemon-installation.md`).

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
  - human-readable text. Caller-supplied text quoted into it is truncated to a fixed budget, on
    the Raw Exec and Operation paths alike (#258 tracks the Operation path).
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
- **ADR-0019 — amended `2026-09-16`.** Whitespace-bearing argv elements are denied outright, and
  allow patterns are full-match. Its choice to quote caller text into a Raw Exec denial, bounded,
  stands; removing that quoting (Future work) would need a further amendment for the Raw Exec path.
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
  types and what makes a value well-formed, and how slot values reach the shell:
  `operations-and-templates.md`.
- **Relay-side authorization, approval, the blast-radius cap and Freeze**: `accounts-and-access.md`,
  `approval.md`, `execution.md`, `freeze.md`. Policy never consults them.
- **Getting fragments onto a Node and applying them**: `daemon-installation.md`, through the
  customer's config management.
- **Pre-made fragments and the screen that arranges them**: `policy-catalog.md`.
- **Central Policy authorship.** Out of realm (AGENTS.md). A Template an AI-agent drafts ends as
  a proposal a human ships through config management.

## Accepted residual risk

- **Self-modification is a deployment concern.** That nothing a Task runs can write the Policy
  directory or trigger a reload rests on the shipped unit's filesystem sandbox, documented as a
  deployment requirement. That is why no
  Alpine package ships yet (`daemon-installation.md`): without systemd there is no such sandbox.
  The self-reference lint is a warning, not an error. Named so they are
  not forgotten: the `pkg.install` profile relaxes that sandbox; the daemon-uid ownership
  exception stands; an agentless tier (ADR-0037) would have no unit; and explicit reload makes
  a writable Policy directory a live escalation rather than one that waits for a restart.
- **Secrets in read output.** The confidentiality deny-list cannot know every file that holds a
  credential; read auditing records that such a file was read, not what it said.
- **Secrets in denial text reach the daemon log.** A denial's human-readable text quotes
  caller-supplied text — a deny pattern's matched text and a refused `argv[0]` on the Raw Exec
  path, the arguments on the Operation path — and so copies a secret passed as an argument into
  the Task result and the daemon log, beyond the audit trail `execution.md` already accepts it
  reaching. Accepted by the owner on `2026-09-17`, so that execution works end to end before it is
  refined. Compensating control: `execution.md`'s contract that arguments are never secrets, and
  the fixed budget on quoted text, which bounds how much of one is copied (Raw Exec today; the
  Operation path is #258). Threat model R20; the
  fix is under Future work.

## Future work

Wanted, deliberately not in the first pass. Named so each is neither re-litigated nor lost;
none is a commitment to an order.

- **Richer denial detail** — the deciding fragment and rule, the argument that decided it, the
  pattern that matched.
- **No caller text in denials or the daemon log** — a denial names the form, the index and the
  rule that decided it and never quotes what the caller sent; the same holds for the daemon's
  log of a refused or failed Task. Pulls against *richer denial detail* above, and needs
  ADR-0019 amended for the Raw Exec path, where it chose quoting for diagnosability. Scoped, with the deny paths and log
  lines that quote today, in #619.
- **Shared Template definitions with separate allow rules** — one definition serving a fleet,
  with per-Node allowed values held apart from it.
- **A daemon-verified guarantee against self-modification** — the daemon itself establishes that
  nothing a Task runs can write the Policy directory or trigger a reload.
- **Output rules** — what a result may contain, enforced on the Node, the only place that sees
  output before it leaves and so the only place such a rule holds against a compromised Relay.
- **Distributing Policy through the Relay** — only if it adds no path by which the Relay can widen
  what a Node permits.

## Open questions

1. **Does `invalid` become a `state:` label?** Targeting "every Node whose Policy is invalid"
   wants one, which adds to the closed vocabulary. `selectors-and-labels.md`; forced when the
   invalid state is built.

Resolved elsewhere: how the Relay trusts a Template's risk class, and what remains of
`operations-and-templates.md`, were settled in that spec on `2026-09-13`.
