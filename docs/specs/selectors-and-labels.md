# Selectors and Labels

**Status:** aspirational — worked through with the owner on `2026-09-13`, awaiting their review
of this draft. Describes intended behaviour, not the code (see the establishing phase in
`README.md`).

## Purpose

Labels are how a Node is described. A Selector is how a caller says which Nodes it means. Every
capability that acts on more than one Node takes a Selector, so this is the shared addressing
vocabulary of the whole control plane.

The model is four namespaces with one writer each. A Node describes itself in `node:`, and
nothing remote can change that. The Relay applies `relay:` labels as a consequence of its own
actions, and neither users nor Nodes edit them. Users organise the fleet with `tag:`. `state:`
tracks a Node's current condition and is written by nobody.

It is a security boundary, not a convenience. What a Selector resolves to determines the blast
radius of everything downstream, and **who is allowed to write a Label determines whether a
target can be forged.** A compromised Node that could label itself into the quarantine lane
would escape quarantine by describing itself out of it.

## Surfaces

A Selector is accepted wherever a capability acts on or lists Nodes: `list_nodes`,
`run_operation` and `raw_exec` over MCP; the Control API's execution and node routes; the
Console's fleet filter. One grammar, one parser, one resolver — no surface evaluates a Selector
itself.

Label **writes** are deliberately asymmetric:

- `node:` — the Node's own declared-labels file and its daemon; no Relay surface.
- `relay:` — no surface writes one directly. Each is written by the Relay action that defines
  it: enrollment, quarantine.
- `tag:` — add and remove, singly or in bulk by Selector, on every surface: MCP, the Control API
  and the Console.
- `state:` — no writer anywhere.

## Behaviour

### Four namespaces, one writer each

Every Label is namespaced, and a namespace is immutable from every side but its own author
(invariant 7).

| Namespace | Written by | Never written by | Purpose |
|---|---|---|---|
| `node:` | The Node: config management declares, the daemon fills in built-ins | The Relay, any user | Routine targeting; the Node's self-description |
| `relay:` | The Relay, only as the side effect of a defined action | The Node, any user directly | The security lane |
| `tag:` | An Account of `operator` or above, on any surface | The Node | Routine targeting; organising the fleet |
| `state:` | **Nobody** — derived from the registry at resolution time | Anyone | Routine targeting on live condition |

**Only `relay:` is a valid security-lane target — with one exception for engaging a
quarantine.** Remediation targets `relay:` and only `relay:`. Engaging a quarantine may target
`relay:` or `tag:`, because no Node can write either; lifting one targets `relay:` only; `node:`
and `state:` are never a quarantine target, because a Node controls them (`quarantine-node.md`).
This is invariant 7 as amended on 2026-09-16 (ADR-0006, ADR-0020). `node:` and `state:` remain routine targeting only.

The writers are structurally separated, not separated by permission: a report from a daemon
cannot reach the `relay:` or `tag:` labels on its Node record, and a daemon can never revoke or
un-revoke itself.

### `relay:` — written only by Relay actions

- **No user ever writes a `relay:` label directly.** Each `relay:` key is defined together with
  the action that sets and clears it; roles, step-up and audit apply to that action.
- The set of `relay:` keys is **closed, and grows only when an action is built.** Defined today:

  | Key | Written by | Value |
  |---|---|---|
  | `relay:enrollment-token` | Enrollment | The ID of the Enrollment Token the Node joined through |
  | `relay:node-id` | Enrollment | The Relay-assigned Node ID, bound to the Node's certificate |
  | `relay:quarantine` | Engaging a quarantine, by a `relay:` or `tag:` Selector resolved once to concrete Nodes; cleared only by lifting it (`quarantine-node.md`) | `on` while quarantined |

- `relay:node-id` is the way to address one specific Node without trusting it, and is a valid
  security-lane target; a value set addresses a handful.
- `relay:enrollment-token` keeps a leaked token's Nodes targetable by the security lane.
- An Enrollment Token may carry `tag:` labels, applied to each Node that enrolls with it. Token
  scope as a list of operator-chosen `relay:` labels is retired.

### `node:` — declared and built-in

- **Declared labels** (`node:env=prod`, `node:role=web`) come from a root-owned file written by
  the customer's config management. The daemon reads it at start and on the same explicit reload
  as Policy, and reports the result to the Relay without a reconnect.
- **Built-in labels** are filled in by the daemon from its Facts: `node:hostname`, `node:ip`,
  `node:os`, `node:arch`. Their keys are reserved; a declared label cannot set one.
- A multi-valued built-in (`node:ip`) matches when any of its values matches.
- A declared-labels file that is malformed or over the limits contributes **no** declared
  labels — never a partial load, which would silently drop the Node out of Selectors it should
  match. Built-in labels still apply, and the Node reports `state:labels-invalid`.
- Every `node:` label, declared or built-in, is forgeable by its own Node.

### `tag:` — organising the fleet

- An Account of `operator` or above adds and removes tags on every surface, MCP included, so an
  AI-agent can organise the fleet as it works. Standard authentication, no step-up.
- A tag is `key=value`, the same shape as every other Label.
- Bulk tagging takes a Selector and is audited as **one action naming every Node it touched.**
  Every single write is audited.
- A tag grants no reach its writer did not already have: every dispatch still passes the blast
  cap, Policy and approval. A tag is never a security-lane target, except that a quarantine may be
  engaged by `tag:` (`quarantine-node.md`); once engaged, only the resulting `relay:` label matters.

### Limits

- Per Node: at most 64 declared `node:` labels and at most 64 tags.
- A key is at most 63 characters and a value at most 255, both within the safe character set.

### What a compromised Node can and cannot forge

- It **can** forge its own `node:` labels, declared and built-in. Routine `node:` targeting
  trusts the Node exactly as much as the Node.
- It **can** influence `state:` terms derived from its own reports — including hiding
  `policy-invalid`, `raw-exec-enabled` and `labels-invalid`.
- It **cannot** touch `relay:` or `tag:`. That is what makes the security lane safe to target.

Because a Node's reported facts feed `node:` built-ins and `state:`, values are gated at ingress
against a well-formedness allowlist so a hostile value cannot inject a second Selector term. A
value that cannot be rendered as a single Selector term is **refused at ingress, never
sanitised** — sanitising would let the Relay itself manufacture a value matching a Selector
nobody wrote.

### `state:` — derived, never stored

`state:` labels are evaluated at Selector-resolution time from the registry. **No Node record has
a `state:` field**, and nothing writes one. The vocabulary is closed; adding a term is a change to
this spec.

| Kind | Terms |
|---|---|
| Markers (boolean) | `offline`, `outdated`, `cert-expiring`, `policy-invalid`, `raw-exec-enabled`, `labels-invalid` |
| Facts (key=value) | `daemon-version`, `policy-fingerprint` |

- `outdated` means below the ADR-0014 dispatch minimum and nothing else.
- `cert-expiring` fires within a configurable fraction of the certificate's lifetime, and stays
  quiet when the provenance needed to compute it is unknown.
- `policy-invalid` means the Node reports its Policy `invalid` (`policy.md`); `raw-exec-enabled`
  means the Node's Policy enables Raw Exec; `labels-invalid` means its declared-labels file
  contributed nothing.
- `policy-fingerprint` covers the whole evaluated Policy, Template definitions included.
- **Terms derived from a Node's own report find Nodes; they guarantee nothing.** A compromised
  Node can hide any of them.
- A marker written with a value, or a fact written bare, is a parse error rather than a silently
  empty match.

Deriving at resolution time rather than storing a denormalised copy is why a second code path
exists in resolution. The alternative was a stored copy with recompute triggers on several
separate events.

### The grammar

A Selector is **an AND of terms**. There is no OR across keys and no parentheses, so a Selector's
blast radius stays legible at a glance.

- **Every term carries a namespace prefix.** An unprefixed term is a parse error, never a guess —
  the parser is fail-closed, because a term silently interpreted in the wrong namespace is a
  targeting error with a blast radius.
- `node:key=value`, `relay:key=value`, `tag:key=value` — key and value both required.
- `state:marker` or `state:fact=value` — from the closed vocabulary above.
- **A value set** matches any listed value for one key: `node:role=web|api`.
- **A value glob** matches within a value: `*` any run of characters, `?` exactly one
  (`node:hostname=web-*`). Globs are allowed in every namespace, `relay:` included — there a glob
  can only range over labels the Relay itself wrote.
- **Negation** excludes: `!tag:canary=true`, `!state:offline`, `!node:env=dev`. It is valid for
  `node:`, `tag:` and `state:` only.
- **A negated `relay:` term is a parse error.** With negation, a `relay:` label the store declined
  to serve would otherwise make a quarantined Node match `!relay:quarantine=on`, and be targeted
  as though it were not quarantined.
- **An empty Selector** matches every Node for reads and listing, and is **refused for
  dispatch**. Targeting the whole fleet must be written deliberately (for example
  `node:hostname=*`), so an AI-agent that forgets a Selector gets an error, not the fleet.

### Resolution

Resolution walks the registry and returns the Nodes matching every term. The resolved **count**
is what the blast-radius cap is checked against (invariant 5), so resolution is what makes the cap
meaningful.

A Selector's resolved set is the same for every surface and every caller; authorization decides
who may *ask*, never what matches.

### Labels the store declines to serve

The stored-Label allowlist is deliberately **narrower than the parser**, because the hazard is a
term concatenated back together by a Console href or an AI-agent — so rendering must be gated
more tightly than parsing. A stored Label outside the allowlist is declined at read-back rather
than deleted or rewritten: *decline to serve, never write*.

A declined label is invisible to resolution. For a positive term that can only remove a Node from
a match. For a negated term it can **add** one (see *Accepted residual risk*) — which is why
negation is refused on `relay:`, and why quarantine cannot be escaped through a declined label:
its key and value are both inside the allowlist, and `relay:` cannot be negated. For `node:` the
condition self-heals on the Node's next report; for `relay:` there is **no self-heal**, which is a
disclosed residual (threat-model register R13) with operator-facing remediation.

## Refusals

| Refusal | Cause |
|---|---|
| Unprefixed term | A term with no `node:`/`relay:`/`tag:`/`state:` prefix — a parse error, never a guess |
| Negated `relay:` term | Negation is valid only for `node:`, `tag:` and `state:` |
| Empty Selector on dispatch | The whole fleet must be targeted explicitly |
| Unknown `state:` term | Outside the closed vocabulary |
| Marker with a value, fact without one | The two `state:` shapes are not interchangeable |
| Malformed label at ingress | A key or value that cannot render as one Selector term — refused, never sanitised |
| Declared label on a reserved built-in key | `node:hostname`, `node:ip`, `node:os`, `node:arch` are the daemon's |
| Over-limit or malformed declared-labels file | None of its labels apply; the Node reports `state:labels-invalid` |
| Direct write of a `relay:` label | No surface offers one; `relay:` labels are written only by their defining action |
| Tag write by a `viewer`, or by a Node | `tag:` is written by an Account of `operator` or above |
| Tag over the per-Node limit | At most 64 tags per Node |

## Governing ADRs and invariants

- **Invariant 7** (ADR-0006, ADR-0020, ADR-0034) — the whole of it. Binds as written: its
  `tag:` clause (an operator through the control plane) is consistent with every surface,
  MCP included, being a control-plane adapter. This spec is where the invariant's per-namespace
  mechanism lives.
- **Invariant 5** (ADR-0004) — the cap is checked against the *resolved* count.
- **Invariant 10** — one parser and one resolver in the capability layer; no surface evaluates a
  Selector itself.
- **ADR-0006 — needs amending.** Enrollment no longer stamps operator-chosen token scope as
  `relay:` labels; it writes `relay:enrollment-token` and `relay:node-id`, and a token carries
  `tag:` labels instead.
- **ADR-0020 — amended 2026-09-16.** Its direct post-enrollment `relay:` label management (`admin` +
  step-up) is superseded: `relay:` labels are written only by defined actions. Its `tag:` design
  stands, extended to MCP.
- **ADR-0034 — needs amending.** The `state:` vocabulary gains `policy-invalid`,
  `raw-exec-enabled` and `labels-invalid`, and retires `template-unloadable` and
  `template-fingerprint`.
- **ADR-0017** — unchanged: `node:` labels are trusted exactly as much as the Node.
- **GLOSSARY.md — needs updating** for Label (the `relay:` writing rule, `node:` built-ins) and
  the `state:` vocabulary.

## Seams and proof

Parsing and resolution live in the capability layer; label authority lives in the registry; the
`state:` vocabulary lives in its own package with no database import. Tested at those seams rather
than through a surface.

### What proves each claim

| Behaviour | Proven by | Seam |
|---|---|---|
| All four namespaces are recognised, and namespace naming is total and distinct | `TestNamespaceNames_ReportsAllFourNamespaces`, `TestNamespaceName_TotalAndDistinct` | capability |
| The grammar parses, and an unprefixed term is an error | `TestParseSelector` | capability |
| A Relay-set label survives a Node's report, and vice versa | `TestImmutabilityBoundary_RelaySurvivesNodeReport`, `TestImmutabilityBoundary_NodeSurvivesRelaySet` | registry |
| No Node record carries a `state:` field | `TestNode_HasNoStateLabelField` | nodestate |
| The `state:` vocabulary is closed, and its key kinds match | `TestKeyKind_Closure`, `TestMarkerKeysAndFactKeys_MatchKeyKind` | nodestate |
| A hostile daemon version cannot inject a Selector term | `TestFacts_HostileDaemonVersionCannotInjectASelectorTerm` | nodestate |
| No whitespace rune, including Unicode, reaches a Selector term | `TestFacts_NoWhiteSpaceRuneReachesASelectorTerm`, `TestFacts_UnicodeWhitespaceCannotInjectASelectorTerm` | nodestate |
| Hostile value shapes are omitted rather than rendered | `TestFacts_OmitsHostileValueShapes` | nodestate |
| `outdated` comes only from the version gate | `TestMarkers_OutdatedComesOnlyFromNodeOutdated`, `TestOutdated_WithMinimumConfigured`, `TestOutdated_NoMinimumConfigured` | nodestate |
| `cert-expiring` fires inside the window and is quiet outside it or when provenance is unknown | `TestMarkers_CertExpiringFiresUnderTheWindow`, `TestMarkers_CertExpiringQuietAboveTheWindow`, `TestMarkers_CertExpiringQuietWhenProvenanceUnknown` | nodestate |
| A `relay:`-namespace Selector narrows as expected; `state:` too | `TestSelectorNamespaceNarrows`, `TestSelectorNamespaceState` | approval |
| Labels are independent across Nodes, and reads return copies | `TestLabels_AreIndependentOfOtherNodes`, `TestGetReturnsCopy` | registry |
| `state:` derivation imports no database | `TestNoDatabaseSQLImport` | compile-time |

Claims above with **no row**, and so nothing checking them:

- **Everything decided on `2026-09-13`** has no test yet: `relay:` labels written only by their
  defining action, the `relay:enrollment-token` and `relay:node-id` stamps, tags carried on a
  token, declared versus built-in `node:` labels and reserved keys, the declared-labels file's
  all-or-nothing load and `labels-invalid`, `tag:` writes on every surface and bulk tagging
  audited as one action, the per-Node limits, the new `state:` markers, value sets, value globs,
  negation and the negated-`relay:` refusal, and the empty-Selector refusal on dispatch.
- That a zero-width space in a reported fact is accepted. It is —
  `TestFacts_ZeroWidthSpaceIsAcceptedKnownGap` documents it as a **known gap** rather than proving
  it safe, which is the honest state and not the same as coverage.
- That `relay:` labels can only be written through the Relay's own actions. The immutability
  boundary is tested from both directions, but no test asserts the *absence* of any other write
  path the way `no_dispatch` asserts the absence of a parallel dispatch path.

### Performance

| Characteristic | Contract | Measured by |
|---|---|---|
| Resolution | Walks the registry once per dispatch; the resolved count feeds the blast cap | *(none)* |
| `state:` evaluation | At resolution time, not stored — so it costs per resolution rather than per state change | *(none)* |
| Value globs and negation | Evaluated per Node per term during the same walk | *(none)* |
| Declined labels | Reported once at startup (capped sample per namespace) and counted on `/metrics`; the counter is traffic-driven | *(none)* |

There are no benchmarks in this repository. Resolution cost scales with fleet size and is on the
path of every dispatch, including a read at the 10,000-Node cap; nothing measures it.

## Out of scope

- **The blast-radius cap itself** — `execution.md`. This spec produces the count; that one
  enforces the limit.
- **Enrollment mechanics** — `enrollment.md`, which must follow this spec: tokens carry `tag:`
  labels, enrollment writes `relay:enrollment-token` and `relay:node-id`, and token scope as
  `relay:` labels is retired.
- **What quarantine does, and who may quarantine** — `quarantine-node.md`. This spec defines only
  that the action writes `relay:quarantine`.
- **The incident ladder** (quarantine, revoke, Freeze) — `quarantine-node.md`, `freeze.md` and
  `enrollment.md`.
- **Policy** — a Node's Policy governs what may run on it, not which Nodes are addressed.
- **Getting the declared-labels file onto a Node** — the customer's config management
  (`daemon-installation.md`).
- **Services and Dependencies** — the System Model (`system-model.md`).

## Accepted residual risk

- **Negation can over-include through a declined label.** A Node whose `node:`, `tag:` or `state:`
  label the store declines to serve is invisible to a positive term and *matched* by a negated
  one: `!tag:canary=true` would include a canary whose tag was declined. Routine targeting only;
  every dispatch still passes the blast cap, Policy and approval, and `relay:` cannot be negated,
  so quarantine cannot be escaped this way.
- **Node-derived terms can lie.** `node:` labels and the `state:` terms derived from a Node's own
  report — `policy-invalid`, `raw-exec-enabled`, `labels-invalid`, `daemon-version`,
  `policy-fingerprint` — describe what the Node claims.
- **A zero-width space is accepted in a reported fact.** It cannot inject a term, but it can make
  two visually identical values distinct.

## Future work

Wanted, deliberately not in the first pass.

- **A structural guard for `relay:` writes** — an absence test asserting that no path other than a
  defining action writes a `relay:` label, the analogue of `no_dispatch`.

## Open questions

- **Where do a Node's declared Labels live?** This spec puts them in a root-owned declared-labels
  file; `daemon-installation.md` currently puts them in the daemon's environment file beside the
  join string. One home is chosen in both specs (raised 2026-10-15).

No other question is open. Who may take the actions that write `relay:` labels is settled in `enrollment.md` and
`quarantine-node.md`; a re-enrolled Node is a new record whose tags do not follow it
(`enrollment.md`).
