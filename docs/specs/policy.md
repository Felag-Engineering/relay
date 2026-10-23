# Policy

**Status:** aspirational — worked through with the owner on `2026-09-13`, brought in line with
the owner's MVP decisions on `2026-10-23`, awaiting their review of this draft. Describes
intended behaviour, not the code (see the establishing phase in `README.md`).

## Purpose

Policy is a Node's own answer to *"what will I ever execute, no matter who asks?"* It defines
everything that can run on a Node: which Native Operations are allowed and with what arguments,
which Template Operations are allowed and with what slot values, and whether Raw Exec is
permitted at all.

It is the last line of defence. With the Relay fully compromised and the AI-agent fully
jailbroken, a Node still refuses everything its Policy does not allow. Policy is written by
people, delivered by the customer's config management, and never reachable from the wire. Relay
can read it and ask it hypothetical questions; widening what a Node will do is always a human
act done outside Relay.

Everything the Relay adds — roles, the blast-radius cap, approval, Freeze — only narrows what
Policy allows. A Task can be allowed by Policy and refused by the Relay; never the reverse.

## Surfaces

- **Daemon-local.** The Policy file and, beside it, the Policy directory of Policy
  **fragments**: files the daemon composes with the Policy file into one evaluated Policy. Every
  file is the operator's; no package owns a fragment. `relay-daemon policy check` validates
  Policy with the same engine that enforces.
- **Restart.** A Policy change applies when the daemon restarts. Config management writes the
  change, runs `relay-daemon policy check`, and restarts the daemon.
- **Relay, read-only.** The daemon reports the whole evaluated Policy and its fingerprint to the
  Relay on connect. MCP `describe_node`, the Control API's node read and the Console display it;
  the display side belongs to `query.md`.
- **Hypotheticals.** `PolicyQuery` asks the live engine what it *would* decide; that capability
  is `policy-preflight.md`.
- **Enforcement.** Every Task the daemon receives is evaluated before an executor runs.
- **No writing surface.** No Relay surface writes, transmits or signs a Node's Policy, by
  design (invariant 2; see *Refusals*).

## Behaviour

### What a Policy contains

- A Policy has four kinds of entry, in the Policy file or any fragment:
  - **Native rules** — named allow and deny rules over the arguments of the four Native
    Operations.
  - **Template rules** — named allow and deny rules over Template Operations, by name and slot
    value. A Template is defined in a root-owned file in the Node's template root, not in
    Policy (ADR-0021); the Template language is `operations-and-templates.md`. A rule for a
    Template the Node has not loaded is inert, and dispatch reports `unsupported`.
  - **The Raw Exec gate** — allow and deny patterns. Absent from every file, Raw Exec is off.
  - **Deny rules** — vetoes over any Native Operation, Template or Raw Exec command.
- Every argument and slot is matched **by name**, never by position.
- The values a Template permits may differ between Nodes, by that Node's own Policy rules.

### Composition

Built today: one Policy file, applied when the daemon restarts. The MVP adds Policy fragments,
in this first cut (`daemon-installation.md` DI-36):

- The Policy directory is `/etc/relay-daemon/policy.d`, beside the Policy file
  `/etc/relay-daemon/policy.toml`.
- The daemon reads the Policy file and every fragment in the Policy directory and evaluates them
  as **one Policy with one fingerprint**. Which file a rule came from affects only error
  messages.
- Deny beats allow across all the files. There is no override and no precedence by file order:
  one file narrows another only by a deny rule.
- No package places or owns a fragment. Every fragment is the operator's.

### Evaluation

- **Deny-by-default.** A Native Operation, Template or Raw Exec command that no entry permits is
  denied.
- **Deny beats allow.** A matching deny rule from any file vetoes, whatever permitted it and
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

### Load and validity

- Policy is loaded once, at daemon start. A change applies when the daemon restarts. There is no
  explicit reload and no filesystem watching.
- **The change procedure:** write the fragment, run `relay-daemon policy check` against it, then
  restart the daemon. Config management does all three, for example with a handler that
  restarts the daemon when a fragment changes.
- A fragment that is a symlink, is not a regular file, or is group- or world-writable refuses
  start, as the Policy file does. A fragment must be owned by root or by the daemon's own uid.
- **A fragment that cannot be read or parsed leaves the whole Policy deny-all**, as does any
  other Policy error: an invalid rule or an unsupported pattern. The daemon keeps running and
  denies every Task. There is no last-known-good fallback, no partial load, and no built-in
  allowance. A Template slot in a decidable code-running position makes the template set
  unloadable instead, and Native Operations keep running (ADR-0021;
  `operations-and-templates.md`).
- The restart reconnects the Node, and the new fingerprint reaches the Relay on connect.

### What the Relay sees

- The whole evaluated Policy: every Native rule, every Template rule, every deny rule, and the
  Raw Exec gate — readable by any Account permitted to read that
  Node. The deny-list is not treated as a secret.

### The shipped default

- The shipped default is one Policy file, not a fragment. The daemon package places it only
  when no Policy file exists and never rewrites it; from then on it is the operator's file
  (ADR-0022, ADR-0033).
- It allows the whole shipped read catalog, all seven `read` Templates with `log.tail` included,
  which ships inside the `relay-daemon` package (ADR-0053). It also allows `system.facts`, and
  `file.read` of any path outside a curated confidentiality deny-list. It permits no `mutate`
  Operation and does not enable Raw Exec.
- The confidentiality deny-list still applies to the catalog: deny beats allow, and every path
  denied to `file.read` is denied to `file.checksum` too (ADR-0022).
- An operator narrows the shipped default with a deny fragment, for example one that denies
  `log.tail` for chosen units or outright, or by editing the Policy file, which is theirs
  (ADR-0053). Widening a shipped Template means defining a new one under a different name.

## Refusals

- **Denied by Policy.** A Task Policy does not permit resolves `denied_by_policy`, distinct from
  `failure`, `unsupported` and a malformed call. The denial is a structured `/proto` contract
  carrying, in its first pass, only:
  - a reason: `no_allow` (nothing permitted it) or `denied` (a deny rule vetoed it);
  - human-readable text. Caller-supplied text quoted into it is truncated to a fixed budget, on
    the Raw Exec and Operation paths alike.
- **Malformed.** An unknown argument or slot name, or a value not well-formed for its type, gets
  its own outcome for Native and Template Operations alike, so a typo never reads as a denial.
- **A Policy that failed to load.** Every Task on that Node is denied by the deny-all Policy.
- **No Relay surface writes Policy.** MCP, the Control API and the Console never write,
  transmit, sign or apply Policy content to a Node, and no message on the Node connection
  carries Policy content towards the daemon (invariant 2).
- **From the wire.** No message can add, remove, edit or deliver a rule, or make the daemon load
  one.
- **Approval is not Policy's to check.** Policy never permits anything "with approval": a Node
  cannot verify an approval claim without trusting the Relay, so Policy stays the floor that
  holds even against a forged approval. Gating is `approval.md`.

## Governing ADRs and invariants

- **Invariant 2 / ADR-0002** — locally rooted and remotely immutable, as written: Policy reaches
  a Node only through the customer's config management, and nothing on the Relay can deliver or
  sign it.
- **Invariant 3 / ADR-0002** — deny-by-default, deny-beats-allow, argument-level granularity, as
  written; arguments are matched by name.
- **Invariant 1 / ADR-0001** — nothing on the wire can compose or escalate a command. A
  Template's structure is fixed in a root-owned local file; Raw Exec is argv-only and gated here.
- **Invariant 12 / ADR-0011** — only the daemon's live engine evaluates Policy, hypotheticals
  included.
- **ADR-0021** — Templates load from the template root beside Policy, with their own
  template-set fingerprint, and Policy governs them by name. Its rejection of a daemon-side deny
  floor stands.
- **ADR-0053** — the read catalog ships inside the `relay-daemon` package and the shipped
  default allows all of it, `log.tail` included; supersedes in part ADR-0021 decision 11.
- **ADR-0018 — needs amending.** The deferred path matcher is resolved as the glob dialect above.
  Case and Unicode folding on a folding mount remains a recorded residual risk.
- **ADR-0019 — amended `2026-09-16`.** Whitespace-bearing argv elements are denied outright, and
  allow patterns are full-match. Its choice to quote caller text into a Raw Exec denial, bounded,
  stands; removing that quoting (Future work) would need a further amendment for the Raw Exec path.
- **ADR-0022** — the shipped read posture stands, as one Policy file placed only if absent
  (ADR-0033).
- **ADR-0025** — reads are audited and output is not retained; this is the present answer to
  secrets in read output.

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
- **Pre-made fragments and a screen that arranges them**: later work, roadmap:
  relay/policy-catalog-and-live-reload.
- **Central Policy authorship.** Out of realm (AGENTS.md). A Template an AI-agent drafts ends as
  a proposal a human ships through config management.

## Accepted residual risk

- **Self-modification is a deployment concern.** That nothing a Task runs can write the Policy
  file or the Policy directory rests on the shipped unit's filesystem sandbox, a documented
  deployment requirement — which is why no Alpine package ships yet (`daemon-installation.md`):
  without systemd there is no such sandbox. The self-reference lint is a warning, not an error.
  Also carried: the `pkg.install` profile relaxes that sandbox; the daemon-uid ownership
  exception stands; and an agentless tier (ADR-0037) would have no unit. A writable Policy
  directory waits for a restart to take effect; explicit reload, if built, would make it live.
- **Secrets in read output.** The confidentiality deny-list cannot know every file that holds a
  credential; read auditing records that such a file was read, not what it said.
- **Logs reach the model provider by default.** The shipped default allows `log.tail`, so
  whatever reaches a Node's journal, secrets included, can flow to the AI-agent and its model
  provider. Accepted by the owner on `2026-10-23` (ADR-0053); an operator narrows or denies
  `log.tail` with a fragment.
- **Secrets in denial text reach the daemon log.** A denial's human-readable text quotes
  caller-supplied text — a deny pattern's matched text and a refused `argv[0]` on the Raw Exec
  path, the arguments on the Operation path — and so copies a secret passed as an argument into
  the Task result and the daemon log, beyond the audit trail `execution.md` already accepts it
  reaching. Accepted by the owner on `2026-09-17`, so that execution works end to end before it is
  refined. Compensating control: `execution.md`'s contract that arguments are never secrets, and
  the fixed budget on quoted text, which bounds how much of one is copied. Threat model R20; the
  fix is under Future work.

## Future work

Wanted, deliberately not in the first pass, and in no committed order.

- **Richer denial detail** — the deciding fragment and rule, the argument that decided it, the
  pattern that matched.
- **No caller text in denials or the daemon log** — a denial names the form, the index and the
  rule that decided it and never quotes what the caller sent; the same holds for the daemon's
  log of a refused or failed Task. Pulls against *richer denial detail* above, and needs ADR-0019
  amended for the Raw Exec path, where it chose quoting for diagnosability. Scoped, with the deny
  paths and log lines that quote today, in #619.
- **Shared Template definitions with separate allow rules** — one definition serving a fleet,
  with per-Node allowed values held apart from it.
- **A daemon-verified guarantee against self-modification** — the daemon itself establishes that
  nothing a Task runs can write the Policy file or the Policy directory.
- **Beyond the first cut of fragments** — explicit reload without a restart, Template
  definitions inside fragments, package-owned fragments, and a reported `invalid` state:
  roadmap: relay/policy-catalog-and-live-reload.
- **Output rules** — what a result may contain, enforced on the Node, the only place that sees
  output before it leaves and so the only place such a rule holds against a compromised Relay.
- **Distributing Policy through the Relay** — only if it adds no path by which the Relay can widen
  what a Node permits.

## Open questions

None open. Resolved elsewhere: how the Relay trusts a Template's risk class is ADR-0042.
