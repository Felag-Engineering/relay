# `state:` labels — a Relay-derived namespace nobody can set

Fleet maintenance targets operational state. "Run this on the Nodes still carrying the old
Policy", "quarantine anything that cannot take work" — these are the everyday Selectors an
operator reaches for, and today none of them can be written.

Labels target; **Facts explicitly do not** (CONTEXT.md: "never used for targeting — that is the
role of Labels"). But the things an operator wants to target here are *neither*. `Hello` carries
`daemon_version` and `Facts` as **separate fields**, and the Policy and template-set fingerprints
have their own CONTEXT.md entries as values "the daemon reports and the Relay records in the
registry". They are a third category — the Relay's own record of its relationship with a Node —
and that category has no targeting mechanism.

ADR-0020 added a third namespace because operator grouping fitted neither existing one. This adds a
fourth, for the same reason and with the opposite write model: `tag:` is set by operators and by
nobody else; `state:` is set by **nobody at all**.

## Decisions

- **A fourth label namespace, `state:…`** — derived by the Relay from the registry, immutable to
  the Node *and* to every Account including `admin`, and valid in Selectors for routine targeting
  exactly like `node:` and `tag:`. There is no write path, no endpoint, and no role that can create
  one; this is enforced structurally, not by permission check. The prefix is mandatory, per
  ADR-0020, so a label's authority stays legible from its name.

- **Every `state:` label is Node-local and objective** — computable from one Node's registry record
  with **no reference to any other Node**. This is the load-bearing rule and it excludes the
  obvious first draft. "Policy fingerprint behind the fleet's mode" is fleet-relative: roll a
  Policy to 51% of the fleet and the mode flips, so the remaining 49% become "drifted" without
  anything about them changing, and a Selector targeting it **silently inverts mid-rollout**.
  It also smuggles desired-state past invariant #9 — computing "behind" requires a notion of what
  the fleet *should* be on, and CONTEXT.md deliberately frames fingerprints as an observation
  ("confirm a rollout landed by string comparison"), never a target.

- **The vocabulary is closed and lives in the contract.** Two shapes, both Node-local:

  | Boolean marker | True when |
  |---|---|
  | `state:offline` | not currently connected |
  | `state:outdated` | daemon below the configured dispatch minimum (ADR-0014) |
  | `state:template-unloadable` | the Node's template set failed to load; vocabulary empty, fail closed |
  | `state:cert-expiring` | identity certificate inside the configured warning window and not yet renewed |

  | Key=value fact | Value |
  |---|---|
  | `state:daemon-version=` | as reported in `Hello` |
  | `state:policy-fingerprint=` | as reported in `Hello` / `PolicySnapshot` |
  | `state:template-fingerprint=` | the template-set fingerprint, or the literal `unloadable` |

  Free-form state labels would become a second `tag:` with none of the guarantees, and a Selector
  written against an operator-invented state term would silently stop matching the day someone
  changed what it meant.

- **Drift is not a label, deliberately.** It stays what CONTEXT.md always said it was: an
  observation, read off the fingerprint distribution. Targeting "the ones that are behind" is
  `state:policy-fingerprint=4b18…c02` — Node-local, objective, and stable under rollout.

- **`state:` is never a security-lane target.** Quarantine, remediation and secret-distribution
  Selectors target `relay:` and only `relay:`, exactly as before. `state:` is computed partly from
  what the Node itself reports, so a compromised Node can influence it; ADR-0017's trust reasoning
  applies unchanged.

- **`state:` terms are evaluated at Selector-resolution time**, as predicates over the registry —
  never materialised as stored labels. Every surviving term is Node-local, so this is cheap and
  cannot go stale. Materialising would mean recomputing on every `Hello`, every `PolicySnapshot`,
  every disconnect and every min-version config change, and maintaining a denormalised copy, for
  no correctness gain.

- **`state:` labels appear wherever labels appear** — `list_nodes`, `describe_node`, the Control
  API, the Console. The AI-agent targets them identically to a human. A Console-only concept would
  be a second vocabulary and the first to drift.

## Considered Options

- **Fold derived state into `relay:`.** Smallest change and needs no new namespace. Rejected: it
  mixes machine-derived values into the one namespace reserved for the security lane, so a
  quarantine Selector could be written against a term whose definition shifts underneath it —
  precisely the erosion ADR-0020 created `tag:` to prevent.

- **Extend Selector grammar to state predicates** (`daemon.version < 1.4.2`). Most expressive, and
  it supports comparisons that equality cannot. Rejected: Selector stops being "a label-based
  query", which is a larger change to the ubiquitous language than adding a namespace, and every
  surface that renders a Selector — Plans, approval objects, audit rows — has to learn a second
  grammar. Once fingerprints are targetable, the comparison cases that remain are not worth it.

- **Materialise into `tag:` and target the tag.** No architecture change at all: filter, apply a
  `tag:`, target it. Rejected as the general answer: it is a snapshot that goes stale the moment a
  Node changes, so "the ones that are behind" means "the ones that were behind when someone last
  pressed the button". It remains a perfectly good *manual* workflow.

- **Make Facts targetable.** Superficially simpler — one fewer category. Rejected: it makes the
  Relay a config-management query engine, which the ROADMAP's scope rule puts out of realm ("if
  Ansible could check it in check-mode, it is out of realm"), and it creates fragile Selectors over
  high-cardinality, Node-asserted values. An operator who wants to target on OS has their config
  management stamp `node:os=ubuntu`; that is what `node:` labels are for.

## Consequences

- **Amends CONTEXT.md's `Selector` definition** — no longer purely "a label-based query" — and
  ADR-0006's and ADR-0020's namespace count, and **CLAUDE.md invariant #7**, which states that
  Labels use three namespaces. Human-merge lane, as ADR-0020 was.

- **Selector resolution gains a second code path** alongside label matching. That is the cost of
  evaluation-at-resolution and it is accepted; the alternative was a denormalised copy with
  recompute triggers on four separate events.

- **`outdated` is pinned to ADR-0014's meaning** — below the dispatch minimum — which is what the
  MCP wire already ships (`tools_execution.go`, asserted by `mcp_plan_test.go`). CONTEXT.md gains
  the entry; `docs/design/ui-advisory.md` uses the word for Policy-fingerprint drift and must be
  corrected in the same change.

- **A compromised Node can influence its own `state:` labels** by lying in `Hello` — the same trust
  posture as `node:` labels, and the reason `state:` is excluded from the security lane. The
  failure mode is a Node evading routine work, not attracting a secret or shedding a quarantine.

- **`state:cert-expiring` requires a warning-window threshold**, which is Relay configuration
  (file-only, invariant #11). No value is proposed here; it should be a fraction of `LeafValidity`
  rather than an absolute, so it tracks any future change to certificate lifetime.

- **The registry must first carry what the markers read** (#440). Liveness is decided today in
  the dispatcher's stream set and the registry exposes only `LastSeen`; certificate validity
  exists only at issuance (`ca.go`) and is not persisted. `state:offline` needs a
  connected/disconnected seam fed by the transport, and `state:cert-expiring` needs
  `cert_not_after` — with `enrolled_at`, `renewal_count` and `last_renewed_at`, which Node detail
  also renders — on the Node record. That lands first, as its own change.

- **The `state:cert-expiring` window is 25% of `LeafValidity` remaining** (84h at 336h). The
  daemon renews at a jittered 50–75% of the lifetime (`daemon/src/renew.rs`), so a Node with under
  a quarter left has missed its entire renewal window: the marker is an alarm that automation
  failed, never a heads-up, and it is quiet on a healthy fleet by construction. Expressed as a
  fraction so it tracks any change to the lifetime; file-only configuration (invariant #11).

- **The Selector change carries `tag:` parsing too.** `capability/selector.go` parses only
  `node:` and `relay:` today; the namespace enum grows to four in one pass (the `tag:` *write*
  path stays with ADR-0020's label management, #430). `NamespaceNames()` reports `state`, so
  approval-gate rules stay honest about what a Selector touched.

- **Approvals bound to `state:` Selectors re-park more often.** `HashPlan` binds the resolved Node
  set; `state:offline` and `state:policy-fingerprint=` flip as Nodes reconnect and roll, so a
  parked Plan over them is likelier to drift before it is answered. Expected and correct — the
  alternative is a signature over a set that changed.

- **Where the security-lane assertion lives: on the `relay:` write path (#430), not here.** A
  `relay:` label write accepts explicit Node IDs or a Selector containing only `relay:`
  predicates; any `node:`, `tag:` or `state:` term is refused, with a structural test. A Console
  "quarantine these" from a filtered fleet view therefore sends the resolved Node IDs, never the
  filter. For this ADR the assertion reduces to the compile-time fact that `registry.Node` and
  `Report` have no state-label field.

- Console surfaces are specified in `docs/design/console/` (01, 02, 05) and depend on this ADR
  landing first.
