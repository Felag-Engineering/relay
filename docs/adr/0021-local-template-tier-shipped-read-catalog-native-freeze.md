# A local Template tier, a shipped read catalog, and a frozen native vocabulary

Template **execution** is separable from template **distribution** (owner decision
2026-08-03, issue #266). ADR-0001 defined tier 2 — **Template Operations**, operator-authored
shell templates with typed parameters — but sequenced it behind operator-signed distribution
(v0.8.0). That coupling was unnecessary: a template loaded from a local, root-owned file
beside `policy.toml` shares Policy's trust root (ADR-0002 unchanged — locally-rooted,
remotely-immutable), and a catalog shipped **inside the daemon package** is trusted the way
the binary is: you installed it. This ADR realizes tier 2 without signing; v0.8.0 shrinks to
signing + courier distribution of the same objects. The default read Policy posture that
makes the shipped catalog usable out of the box is a **companion decision** (#294, its own
short ADR), referenced but not specified here.

## Decisions

- **Template tier semantics (realizes ADR-0001 tier 2).** A Template Operation is an
  operator-authored shell template with **named, typed-validated parameter slots**. The
  trusted author fixes the command structure; the caller supplies only parameter values.
  **Substitution can never alter command structure**: each parameter is validated against
  its slot's declared type/constraints and then substituted such that it fills exactly the
  lexical position the author wrote — a value can never add words, operators, redirections,
  or expansions. A **`risk_class` (`read` | `mutate`) is mandatory** on every template
  (ADR-0012); a template without one fails to load. **Policy governs templates exactly like
  Native Operations**: deny-by-default, deny-beats-allow, argument-level constraints on
  parameters — the template's name enters the same Policy vocabulary, and a Policy rule for
  it is written no differently. **The shell boundary is treated as hostile**: per-parameter
  validation and quoting are the mitigation for the tier's residual risk (parameter
  injection, per ADR-0001), and a **red-team suite** — adversarial parameter-injection
  attempts against the substitution boundary, in the tradition of the v0.0.8 Raw Exec
  red-team — is an **acceptance criterion of the milestone, not a follow-up**. Findings
  become regression tests.
- **Local loading, same trust root.** Templates load from root-owned files beside
  `policy.toml`; changing them requires local or out-of-band access (config management,
  SSH), never the wire — ADR-0002's model applies verbatim, and the Relay can query but
  never modify a Node's template set. A directory of templates installed and versioned as a
  unit is a **template pack** (the convention the shipped catalog and future first- or
  third-party packs follow).
- **Fingerprint and discovery.** The daemon reports a **template-set fingerprint** beside
  the Policy fingerprint (in `Hello` and every snapshot); the registry records it —
  fleet-wide template drift visibility without the templates traveling, the exact
  Policy-fingerprint mechanism reused. Because the vocabulary is now **per-Node**,
  `list_operations`/`describe_node` expose each Node's effective vocabulary, and dispatching
  a template a Node has not loaded yields a **distinct `unsupported` per-Node outcome** —
  not a failure, not a Policy deny: the Node was never asked to decide.
- **Shipped read catalog.** A first-party template pack installed with the daemon package:
  **process list, service status, disk/mount usage, listening ports, package inventory,
  bounded log tail, file checksum** — all `read` class. This absorbs the old v0.7.0 native
  read-Op batch: the catalog is the tier's own first customer, so its safety machinery is
  proven on templates we ship before operators author their own.
- **Native-vocabulary freeze.** The Native Operation vocabulary is **frozen at the current
  four**. `system.facts` and `file.read` stay native as platform intrinsics (facts feeds
  the registry; `file.read` carries the ADR-0018 canonical-path matching and
  resolved-target re-check, which needs executor-level descriptor access no template has).
  `service.restart` and `pkg.install` are grandfathered. **New vocabulary = templates.**
- **Prerequisite: one registry lookup (#289, in flight in parallel).** The vocabulary goes
  behind a single **name → (handler, arg-shape, risk-class)** lookup (architecture review
  2026-07-07, candidate 3), so the template tier **registers** Operations instead of adding
  dispatch match arms, and validation, Policy evaluation, and discovery read one source of
  truth. The ADR-0015 golden schema continues to pin the (frozen) native vocabulary;
  per-Node template vocabularies are discovered live, not golden-pinned.
- **Data-egress governance (owner review 2026-08-04).** `read` means "cannot change Node
  state" — it does **not** mean "safe for the AI to see". A read result flows to the model
  provider: reading is exfiltration by construction (PII in logs, secrets in configs). The
  shipped catalog is therefore governed by what it makes **reachable**, not by an
  `/etc/shadow` deny-list alone: the bounded log tail reads whatever secrets land in logs,
  and the file checksum is a content oracle over any path Policy lets it touch. The shipped
  default Policy (#294) must scope these accordingly (paths/units/journals reachable by
  default), and **output classification in Policy** — rules about what results may contain,
  not only what may run — is named as the long-term direction, deferred beyond v0.2.0.
- **Default read Policy posture is #294's companion ADR.** Read pre-allowed out of the box
  with a confidentiality deny-list; `mutate` + Raw Exec stay opt-in whitelist; engine
  semantics unchanged. Recorded and specified there, not here.

## Considered Options

- **Keep the tier coupled to signing (status quo sequencing, old v0.8.0).** Rejected: the
  trust argument for a local root-owned file is ADR-0002's, already made — signing adds
  distribution reach, not execution trust. Waiting keeps Raw Exec as the only extensibility
  valve for another two milestones, against ADR-0001's own intent.
- **Keep growing the native vocabulary instead.** Rejected: every addition is Rust in the
  privileged exec path plus a daemon release for the whole fleet (ADR-0014: IaC-only
  upgrades), so the vocabulary would grow at release cadence, centrally chosen, while the
  fleet-specific long tail stays on Raw Exec — the most dangerous path absorbing the demand
  the typed path exists to serve.
- **Templates as centrally-expanded Raw Exec** (Relay substitutes parameters, sends the
  result as Raw Exec). Rejected: the daemon would see only a command string — no typed
  parameter validation at the enforcement boundary, no argument-level Policy, and the
  trusted-author property enforced by the untrusted side. Collapses tier 2 into tier 3.
- **Argv-only templates (no shell).** Safest boundary, but the vocabulary gap templates
  exist to close *is* shell composition (pipes, filters, redirection) — argv-only is just a
  native Operation authored in TOML. Rejected in favor of a hostile-shell posture:
  validation + quoting + red-team, per ADR-0001's stated residual risk.

## Consequences

- ADR-0001's tier 2 gets its promised ADR (this one); tiers 1 and 3 are unchanged, and the
  tier ordering by trust still holds — a template is safer than Raw Exec *because* a
  trusted local author fixed the structure. ADR-0002 is unchanged; its v0.8.0 rewrite
  ("operator-rooted") will cover Policy and template bundles alike.
- The template loader and substitution engine are exec-path security surface: human-merge
  lane, always, and the red-team suite gates the milestone.
- The Operation vocabulary stops being fleet-uniform. Surfaces and the AI-agent must treat
  vocabulary as per-Node (`list_operations`/`describe_node`), and the Job engine gains the
  `unsupported` outcome (`/proto` change — contract-first, both sides regenerated).
- The registry, `describe_node`, and the Console (v0.6.0 views) carry the template-set
  fingerprint beside the Policy fingerprint; a template rollout is confirmed the same way a
  Policy rollout is (ADR-0002).
- `policy check` grows template linting, and the self-reference lint (#287) warns when an
  allow rule's reach includes the daemon's own config, binary, or unit — which now includes
  the template files themselves (a template or Policy rule that can rewrite templates is
  self-modifying Policy).
- The AI-agent may *draft* templates, but nothing loads until a root-owned file lands on
  the Node out-of-band — and, after v0.8.0, until an operator signs the bundle. The
  widening act stays human, exactly as for Policy.
- #288 (read auditing / output-retention) must be decided before the catalog makes reads
  ubiquitous; the data-egress section above is its motivation.
- CONTEXT.md gains **Template Operation** and **template pack** in the same change.
