# Operations and Templates

**Status:** aspirational — worked through with the owner on `2026-09-13`, Template language revised with the owner on `2026-10-14`, awaiting their review
of this draft. Describes intended behaviour, not the code (see the establishing phase in
`README.md`).

## Purpose

Operations are the typed vocabulary through which Relay acts on a Node: *restart this service*,
*read this file*, *show disk usage*. They let an AI-agent administer a fleet without composing
shell. Whoever authors an Operation fixes what runs; a caller only fills in values, and a value
can never change which command runs.

The vocabulary has two sources. **Native Operations** are built into the relay-daemon and frozen
at four. **Template Operations** are named commands an operator defines in a Node's Policy, with
typed slots a caller fills. Templates are how the vocabulary grows.

This spec owns what an Operation is, the risk-class contract, the Native vocabulary, the Template
language, and how callers see and call the vocabulary — including when targeted Nodes do not
share it. Where a Template is defined and which values a Node allows is `policy.md`.

## Surfaces

- **`/proto`.** One descriptor shape for every Operation, Native or Template: name, description,
  risk class, and named, typed arguments with their descriptions and allowed values.
- **Daemon.** The Native executors and their validators; the Template renderer, which is the one
  place a shell command is built; `relay-daemon policy check`, which validates Template
  definitions with the engine that runs them.
- **MCP.** `list_operations` describes the vocabulary reachable across a Selector;
  `run_operation` calls any Operation by name. Discovery's shape is `query.md`.
- **Control API and Console.** Dispatch any Operation, Native or Template, by name.

## Behaviour

### Every Operation

- An Operation has a name, a description, a risk class (`read` or `mutate`), and zero or more
  named, typed arguments. A Template's arguments are called slots.
- Arguments are matched by name. A call naming an argument the Operation does not have, omitting
  a required one, or carrying a value not well-formed for its type is **malformed**: rejected
  before Policy is consulted, with its own outcome, for Native and Template Operations alike.
- An Operation may declare a timeout; otherwise the daemon-wide default applies. A caller may ask
  for a shorter timeout and never a longer one.
- Output is bounded by the daemon-wide output cap.

### The Native vocabulary

Exactly four, frozen. A fifth needs an ADR; new vocabulary is Templates.

| Operation | Class | Arguments | Why it is Native |
|---|---|---|---|
| `system.facts` | `read` | none | Feeds the registry on connect |
| `file.read` | `read` | `path` (required) | Re-checks the resolved target and reads only from the descriptor it checked — beyond what a shell command can do safely |
| `service.restart` | `mutate` | `unit` (required; systemd unit charset, never a leading `-`) | Predates Templates; kept |
| `pkg.install` | `mutate` | `name` (required), `version` (optional) | A purpose-built executor spanning package managers, with its own sandbox profile — safer than per-manager Templates through a root shell |

A Native's argument values are validated by the daemon. The descriptor in `/proto` is generated
from those validators, so what a caller is told and what the daemon enforces cannot drift.

### The Template language

- A Template is defined in Policy with a name, a `description`, a risk class, a body, optional
  timeout, and slots, each with a type, a one-line description and an optional `allow` list. A
  Template without a description, or a slot without one, is a Policy error.
- A Template name may not shadow a Native Operation's name.
- **The body runs through a shell.** Authors may use the full shell — pipes, fallbacks,
  redirection, here-documents, substitutions — because the text the shell parses is theirs alone.
- **A slot value is never shell text** (ADR-0021, amended 2026-10-14; #974). Each placeholder must
  stand alone as a whitespace-delimited token outside any quotes (kept, so a value is never glued
  to the author's text) and becomes a quoted positional parameter (`"$1"`);
  the values are passed to the shell as separate arguments. The parsed text is identical for every
  call, so no value can add a word, an operator, a redirection or an expansion, in any POSIX shell. This
  is the single point invariant 1 rests on for the Template tier.
- **A slot fills only a data position.** A placeholder standing where its value would be executed,
  where that is decidable from the body, is a Template compile error (the Node's template set is
  `unloadable`; Native Operations keep running): the command-name position, including the operand
  of `exec`/`command`/`builtin`; the operand of `eval`/`.`/`source`; the argument after a shell's or
  interpreter's `-c`/`-e`; and `let` (ADR-0021, amended 2026-10-15). Arithmetic contexts
  (`(( ))`, `$(( ))`, `$[ ]`) cannot hold a slot at all, since a slot stands only at the top level. Code positions not reliably decidable (an `awk` or `sed` expression, `find -exec`,
  `xargs` into a shell, an option that takes a command to run) are a `policy check` warning that
  `--strict` fails. These two lists are the start of the Safe-Template hazard list (Future work)
  and grow with it.
- **No well-formed value is an option.** No daemon-owned slot type admits a value beginning with
  `-`; an `enum` value is a literal the author chose.
- **Slot types are a closed set owned by the daemon:**

  | Type | Well-formed | `allow` narrows by |
  |---|---|---|
  | `identifier` | Letters, digits and a small safe punctuation set, bounded length, never beginning with `-` | Exact values |
  | `integer` | Decimal, bounded digits | Exact values |
  | `path` | Strict canonical absolute path, no C0 control or DEL | Policy's glob dialect |
  | `enum` | Exactly one of the author's listed values | — (the list is the constraint) |

  A slot with no `allow` accepts any well-formed value. Adding a type is a daemon release, a
  change to this spec, and a red-team case.

### Risk class and the blast cap

- A Native's risk class is fixed in the daemon.
- A Template's risk class is declared in each Node's Policy and reported by that Node.
- **A Template dispatch takes the most restrictive class reported by the Nodes that report the
  Template:** `read` only if every one of them reports `read`; otherwise `mutate`. The blast cap
  follows that class (invariants 5 and 13).
- The Task carries the class the Relay used. A daemon whose own Policy declares that Template
  `mutate` refuses a Task dispatched as `read` — which also covers a reload between resolution
  and execution.

### Calling the vocabulary

- Callers reach every Operation through generic tools: `list_operations` to learn what is
  reachable across a Selector — descriptions, slots, types, allowed values, risk class and which
  Nodes report each Operation — and `run_operation` to call one by name. The MCP tool list is
  small and does not change when any Node's Policy changes.
- A Template is dispatchable through every surface exactly as a Native is.

### When targeted Nodes do not share a vocabulary

- The Relay refuses a Template name that no targeted Node reports.
- Otherwise, targeted Nodes that do not report the Template are **excluded before the risk class
  and blast cap are decided**, and appear in the result as `unsupported` without being
  dispatched. Class and cap are decided over the Nodes that remain. A Node the Relay holds no
  vocabulary report for — one that has not reconnected since the Relay started — is excluded the
  same way, with a reason that says so; the Relay never dispatches a Template blind (ADR-0042).
- A call's argument names must match the Template's slots on **every** remaining Node. If those
  Nodes disagree about the slot set, the call is refused as a vocabulary disagreement rather than
  sent to some of them (ADR-0042).
- The capability layer resolves a Template's class; an adapter never does (invariant 10).
- A Node whose report is stale — the Template removed on reload after it was reported — answers
  `unsupported` from its own daemon. `unsupported` is neither a failure nor a Policy denial.

### The shipped read catalog

- > **Not yet reconciled** — as in `policy.md`: until Templates move into Policy, the catalog is a
  > template pack (ADR-0021, ADR-0022), not a Policy fragment, and installing it permits nothing
  > a Node's Policy does not already allow.
- A package-owned Policy fragment (`policy.md`) of first-party `read` Templates: process list,
  service status, disk usage, listening ports, package inventory, a bounded log tail, and file
  checksum. Bounds such as the log tail's line count are fixed by the body, not by a slot.
- It grows through normal review. Every change is a Policy change and lands in front of a human.
- It ships as its own optional package beside the daemon package, so a Node offers it only where
  the operator chose to install it; its files are package-owned and replaced on upgrade
  (ADR-0033, amended 2026-10-15; `daemon-installation.md`).

## Refusals

- **Unknown Operation.** A name no targeted Node reports is refused at the surface, pointing the
  caller at `list_operations`.
- **Malformed call.** Unknown or missing argument names and ill-formed values get their own
  outcome, never `denied_by_policy`, so a typo never reads as a denial.
- **Class mismatch.** A daemon refuses a Task dispatched under a lower risk class than its own
  Policy declares.
- **Policy errors in a Template definition** — a missing description, a slot not standing alone,
  an unknown slot type, a name shadowing a Native — make the whole Policy `invalid` (`policy.md`).
  A slot in a decidable code-running position is a Template compile error: the Node's template set
  is `unloadable` and Native Operations keep running (ADR-0021, amended 2026-10-15).
- **From the wire.** Nothing adds, changes or removes an Operation on a Node. The Relay never
  renders or substitutes a Template body.

## Governing ADRs and invariants

- **Invariant 1 / ADR-0001** — nothing on the wire can compose or escalate a command. For
  Templates this rests on slot values never being shell text (ADR-0021, amended 2026-10-14);
  the code-position refusals are defence in depth beside it. For Natives, on argv.
- **Invariant 13 / ADR-0012** — every Operation declares a risk class, and it chooses the cap. *(Invariant 13 amended 2026-10-02, ADR-0042: a Template Operation's class is Node-reported, and a dispatch takes the most restrictive class the Nodes it reaches report.)*
  Binds through the most-restrictive rule and the daemon's class check.
- **Invariant 5 / ADR-0004** — the blast cap is enforced on the Relay before dispatch, over the
  Nodes remaining after exclusion.
- **Invariant 8 / ADR-0007** — `/proto` is the single source of truth for the vocabulary.
- **Invariant 7** — Node-reported facts are forgeable; a Template's reported class is treated as
  one.
- **ADR-0042** — the class rule, exclusion, slot agreement, and where each is decided. Amends
  ADR-0021 and ADR-0012.
- **ADR-0021 — needs amending.** Template definitions move into Policy; template packs and the
  template-set fingerprint are retired; the Native freeze stands.
- **ADR-0015 — needs amending.** Its trigger has fired: argument schemas move into `/proto` for
  every Operation, generated from the daemon's validators.
- **GLOSSARY.md — needs updating.** Template Operation, template pack (retired), template-set
  fingerprint (retired), slot types.

## Seams and proof

_Not yet written._ This spec's claims are the backlog of its testing issue.

## Out of scope

- **Where Templates are defined, allowed values, fragments, reload and `invalid`**: `policy.md`.
- **Dispatch, fan-out mechanics, cancellation, Raw Exec and the per-tier mechanism table**:
  `execution.md`.
- **The shape of `list_operations` and `describe_node`**: `query.md`.
- **How Template calls group for approval**: `approval.md`. The first pass treats each distinct
  Template call as its own shape.
- **Getting Policy onto a Node**: the customer's config management (`daemon-installation.md`).

## Accepted residual risk

- **A Template's risk class is Node-reported.** Most-restrictive-wins still trusts Nodes when
  every Node reporting a Template reports `read` — a dispatch to one compromised Node, or to a set
  of them.
- **An author can write an unsafe Template.** A slot handed to another interpreter, a value read
  as a flag, a path escaping its root, a command that reads too much. Positional parameters, the
  code-position refusals and slot types narrow this; an undecidable code position the author
  writes, and a command's own reading of a well-formed argument, remain.
- **Node output can steer the AI-agent.** A Template's result flows into the model's context and
  can carry instructions. To be decided as its own track (ADR-0021 amendment, decision 6; #980).
- **Deceptive characters in a value.** A `path` value may carry invisible or bidirectional
  characters that mislead a human reader; every surface showing it must render them visibly
  (ADR-0021 amendment, decision 4; #979).

## Future work

Wanted, deliberately not in the first pass. Named so each is neither re-litigated nor lost;
none is a commitment to an order.

- **A stronger answer for a Template's risk class.** Candidates, none chosen: a class the Relay
  pins per Template name, set by an operator; pinning at first observation and treating a
  downgrade as an alarm; a Relay-side floor for names matching no registered read Template.
- **Research: MCP with many tools and many targets.** How AI-agents and MCP clients behave with
  large or changing tool lists, schemas that differ per target, and fleets of thousands — to
  decide whether generic `run_operation` stays, or gives way to per-Template tools, a promoted
  short list, or something else.
- **Mixed-vocabulary dispatch.** Candidates: telling the caller before dispatch which Nodes will
  be skipped; a fleet view of vocabulary drift; whether excluded Nodes count toward a mutate cap.
- **Safe-Template authoring** (shape decided). A Safe-Template hazard list, kept in this spec —
  every known way a Template can exceed its author's intent, each tagged mechanical or judgement,
  extended by research into shell tricks, environment and `PATH`, locale, symlink-following,
  privilege-changing and writing commands, and check-to-use races. Every mechanical entry becomes
  a `policy check` rule that makes the Policy `invalid`, each with a red-team case; an authoring
  guide shows safe and unsafe forms side by side.
- **Per-Operation output bounds** tighter than the daemon-wide cap.
- **Shape and scale declarations on Template slots**, for finer approval grouping.

## Open questions

None open. Questions this spec raised for others: `query.md` owns how `list_operations` stays
legible across thousands of Nodes; `approval.md` owns Template-call grouping.
