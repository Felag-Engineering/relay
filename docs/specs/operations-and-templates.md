# Operations and Templates

**Status:** stub — aspirational, not yet worked through with the owner (`2026-09-13`).

## Purpose

Operations are the typed vocabulary through which Relay acts on a Node: *restart this service*,
*read this file*, *list listening ports*. They let an AI-agent administer a fleet without
composing shell. The author of an Operation fixes what runs, and the caller only fills in
validated values.

The vocabulary has two sources. **Native Operations** are compiled into the relay-daemon and
frozen at four. **Template Operations** are shell templates with typed slots, written by a
trusted operator in root-owned files on the Node. Relay ships a first-party read catalog of
them. Templates are how the vocabulary grows. A recurring Raw Exec pattern should be promoted
to a Template.

## Surfaces

- **Proto.** The vocabulary contract (`OperationDescriptor`: name and risk class;
  `TemplateSnapshot` and `TemplateDescriptor`: per-Node templates with typed slots and no body).
- **Daemon-local.** The Native registry and its validators. A template root beside the Policy
  file, holding loose template files plus *template packs* (one directory each), including the
  shipped `relay-read` catalog. `relay-daemon policy check` lints templates, and
  `dump-operation-schema` emits the Native schema.
- **Relay.** The Native vocabulary as model-facing descriptions (purpose, argument constraints,
  example, and a shape or scale class per argument). It is kept honest by a daemon-generated
  golden schema checked in CI.
- **MCP.** `list_operations` returns the Native Operations, plus a Node's reported Templates when
  given a Node ID. `run_operation` and `describe_node` also reach the vocabulary. Discovery
  itself is `query.md`.
- **Control API and Console.** They dispatch Native Operations by name. Uncertain: whether any
  surface can dispatch a Template Operation today (see Open questions).

## Behaviour

_To be established by interrogation._

Candidate claims, from the ADRs and the code — each to be confirmed, changed or dropped:

- Every Operation, Native or Template, declares a risk class of `read` or `mutate`. A Template
  without one fails to load.
- The Native vocabulary is exactly `system.facts`, `file.read`, `service.restart` and
  `pkg.install`. Adding a fifth needs a new ADR.
- Native argument values are validated by the daemon against per-argument charsets and anchoring
  rules. The Relay's published constraint text is proven equal to those validators by a golden
  schema.
- A caller's argument **names** are checked against the Operation's declared names on every
  surface, through one shared check. An unknown or missing required name is a validation error,
  never `denied_by_policy`. This is issue #345, and it is fixed.
- A Template slot value is validated against its slot type (`identifier`, `integer`, `path`,
  `enum`) and substituted as one single-quoted word. No value can add words, operators,
  redirections or expansions.
- Every template slot must be a standalone, whitespace-delimited token in the template body.
- Templates load only from root-owned, non-symlinked, non-writable-by-others files. Any failure
  (bad file, parse error, shadowing a Native name, duplicate name) fails the whole set. The Node
  then has no Templates and reports an `unloadable` template-set fingerprint.
- The daemon reports a template-set fingerprint beside its Policy fingerprint in `Hello` and in
  every snapshot.
- Dispatching an Operation that is not in a Node's vocabulary resolves `unsupported` on that
  Node. That is neither a failure nor a Policy denial.
- The shipped read catalog is exactly seven `read` Templates: process list, service status,
  disk usage, listening ports, package inventory, bounded log tail and file checksum. The line
  cap on the log tail is fixed by the template, not by a slot.

## Refusals

_To be established by interrogation._

Candidate claims, from the ADRs and the code — each to be confirmed, changed or dropped:

- An unknown Operation name is refused at the surface, naming the problem and pointing at
  `list_operations`.
- A Template body is never sent to the Relay, and the Relay never renders or substitutes one.
- Nothing on the wire can add, change or remove a Template on a Node.

## Governing ADRs and invariants

- **ADR-0001 / invariant 1**: three tiers ordered by trust. A caller's arguments can never change
  which command runs. New vocabulary is Templates.
- **ADR-0021**: the local Template tier, template packs, fingerprints, `unsupported`, the shipped
  catalog, the Native freeze, and data-egress governance ("read" does not mean "safe to see").
- **ADR-0012 / invariant 13**: every Operation's risk class is security-relevant contract and
  chooses its blast cap.
- **ADR-0015**: the daemon is the source of truth for what it enforces, and the golden schema
  guards the Relay's description of it.
- **ADR-0007 / invariant 8**: `/proto` is the single source of truth for the vocabulary contract.
  Generated code is never hand-edited.
- **ADR-0002 / invariant 2**: Templates share Policy's trust root. They are readable by the Relay
  and never writable over the wire.

## Seams and proof

_Not yet written._

## Out of scope

- **Dispatch, fan-out, blast caps, timeouts, cancellation, Raw Exec gating and the per-tier
  mechanism table**: `execution.md`.
- **Which argument values a Node allows**: `policy.md`. Validation decides whether a value is
  well-formed. Policy decides whether it is allowed.
- **Discovery reads** (`list_operations` shape, `describe_node` vocabulary view): `query.md`.
- **How an argument's shape or scale class groups approvals**: `approval.md`.
- **Distributing templates to Nodes**: the customer's config management (`daemon-installation.md`).
  Signed courier distribution is a future decision, not this spec.

## Open questions

1. **Can a Template Operation actually be dispatched?** From reading the code, MCP
   `run_operation` and the Control API both look an Operation up in the fleet-wide *Native*
   vocabulary only, and refuse any other name as `unknown operation`. The one Template dispatch
   found is in the cross-binary test harness, which bypasses the surfaces. If that reading is
   right, the shipped catalog is listed but cannot be run. Is closing that gap in scope now, and
   what should the Relay check before it forwards a Template name?
2. **Whose risk class does the Relay trust for a Template?** The class comes from the Node's own
   report. A compromised Node could label a `mutate` Template as `read` and get the generous read
   cap. Options include: accept it (Policy on that Node is the gate anyway), always use the
   mutate cap for Templates, or pin the class at the Relay. Invariant 7 treats Node-reported
   facts as forgeable.
3. **Name validation for Templates.** The argument-name check (#345) reads Native descriptors. Should
   Template slot names be checked at the surface against the Node's reported slots, and what
   happens when a Selector spans Nodes with different vocabularies?
4. **Mixed-vocabulary fan-out.** One Selector across Nodes with and without a Template yields
   partial `unsupported`. Is that the product behaviour, or should resolution narrow to Nodes
   that report the Template, or refuse up front?
5. **Is the freeze permanent?** `service.restart` and `pkg.install` are grandfathered Natives.
   Should they migrate to Templates eventually, or stay forever?
6. **Arguments in `/proto`.** ADR-0015 kept the argument schema out of `OperationDescriptor` until
   something must ship it over the wire. `TemplateDescriptor` now carries typed slots on the wire
   while Natives do not. Has the trigger already fired?
7. **Slot-type vocabulary.** Four types today. Who may add one, and does a new slot type need the
   Template red-team suite re-run as an acceptance gate?
8. **A shape or scale class for Template slots.** Natives declare shape or scale per argument for
   approval grouping. Templates carry no such declaration. Should template authors declare it, and
   what is the default?
9. **Third-party and operator packs.** Is a template pack a unit of versioning Relay understands
   (name and version in the registry), or only a directory convention on the Node?
10. **Output bounds.** Stdout and stderr are size-capped per Task. Should an Operation or Template
    be able to declare its own tighter output bound as part of its contract (data egress)?
11. **Per-Operation timeouts.** Natives declare a default timeout. Should Templates declare one,
    and may a caller override it?
12. **Catalog governance.** Is the shipped catalog a closed list that needs an ADR to add to, or
    can it grow with normal review?

## History

- `2026-09-13` — stub created to name the capability.
