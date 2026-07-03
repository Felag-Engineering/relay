# Daemon lifecycle: IaC-owned upgrades, a dispatch-level version gate, additive proto discipline

The relay-daemon is upgraded only by the customer's config management; the Relay
enforces a minimum daemon version by refusing to dispatch (not to connect); and the
`/proto` contract evolves additively within a package version, with breaking changes
served as a parallel package for a deprecation window.

## Decisions

- **The daemon never self-upgrades, and the Relay never pushes binaries.** A
  self-upgrade channel is RCE-on-the-executor: the most privileged binary in the
  system accepting new code over the very connection it is designed to distrust would
  undo ADR-0002's premise in one feature. The daemon binary is a root-owned artifact
  updated exactly like the Policy file: via the customer's reviewed IaC pipeline,
  consuming the release artifacts CD publishes on tag.
- **Minimum daemon version, enforced at dispatch.** `Hello` already reports
  `daemon_version`. A below-minimum Node still connects, heartbeats, and appears in
  the registry — flagged `outdated` — but the Job engine refuses to send it Tasks
  (reported per-Task, like a per-Node freeze). Refusing the *connection* instead
  would make stale daemons invisible mid-upgrade; the registry is the upgrade
  dashboard. The minimum version is Relay config: file-only, like the blast caps —
  the API cannot lower it.
- **Proto discipline: additive-only within `gleipnir.v1`.** New fields and messages
  only; no renumbering, no semantic changes to existing fields. A breaking change
  means a `gleipnir.v2` package served alongside `v1` for a deprecation window.
  Ordering rule: **the Relay upgrades first**; daemons lag behind within the
  min-version window.

## Considered Options

- **Self-updating daemon.** Operationally seductive (no IaC round-trip), rejected as
  a supply-chain and trust-inversion hazard; it also duplicates what customers'
  existing IaC does natively.
- **Relay-pushed binaries via an Operation.** Same inversion with extra steps, and it
  would make the update channel subject to Policy debates it can never win.
- **Hard connection rejection below min-version.** Simpler, but hides exactly the
  Nodes the operator is trying to find during a rolling upgrade. Rejected for the
  dispatch-level gate.

## Consequences

- The registry gains an `outdated` flag; `list_nodes` and the Console can surface
  upgrade progress with no extra machinery.
- Version-gate refusals are per-Task outcomes, so a Job against a mixed fleet reports
  honestly per Node rather than failing wholesale.
- CD (issue #44) is the artifact source this workflow consumes; the beta docs must
  include the Ansible upgrade example.
- CI should enforce proto additivity (e.g. buf breaking-change checks) so the
  discipline is a gate, not a convention.
