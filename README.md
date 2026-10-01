# Relay

A fleet-administration control plane. A lightweight, non-AI daemon (the **relay-daemon**)
runs on every managed Linux server, dials home to a central **Relay**, and holds a
persistent connection open. Through that connection the Relay runs typed administrative
**Operations** on the fleet, and an **AI-agent** drives the whole thing by using the Relay
as a tool — while per-Node **Policy** restricts what may actually run. Defense in depth.

**Relay lets you hand your fleet to an AI without handing it trust.** Other tools answer
"what if the operator goes rogue?" with procedure; Relay answers with architecture.

> **Naming:** the product is **Relay**. **Gleipnir** is the first-party AI-agent system
> that will drive Relay — a separate project and a consumer of Relay's MCP/API surfaces,
> with no special privileges. The repo name `gleipnir-relay` is historical.

```
┌─────────────┐   MCP    ┌──────────────────┐  gRPC/mTLS   ┌────────────────────┐
│  AI-agent   │ ───────▶ │      Relay       │ ◀─ dial home ─│   relay-daemon ×N  │
│ (MCP client)│  tools   │  (Go server)     │  persistent   │   (Rust, per Node) │
└─────────────┘          └──────────────────┘   bidi stream └────────────────────┘
                                                                  │ enforce local Policy
                                                                  ▼ execute Operation / Raw Exec
```

## The two programs

Relay is two programs, and everything else in the system is one of them or a thin adapter
over one.

The **Relay** is a central server, written in Go. It holds the registry of known Nodes,
resolves which of them a request targets, authorizes the caller, caps how far a single
action may reach, dispatches the work, and records what happened. It is also the private
CA that mints each Node's identity at enrollment. It is the only thing that talks to the
fleet, and the only thing an operator or an AI-agent talks to.

The **relay-daemon** is a small daemon, written in Rust, installed on every managed
server. It dials out to the Relay and holds one persistent connection open, so no managed
server needs an inbound port. It receives Tasks, evaluates each against a Policy file that
lives on its own disk and is owned by root, executes only what that Policy permits, and
reports results. It is not an AI, does not reason, and never becomes either.

Three surfaces reach the Relay: the MCP surface an AI-agent drives, the Control API that
tooling calls, and the Admin Console a human uses. All three are adapters over one
capability layer, so what may be done, who may do it, and how it is recorded are decided
once rather than three times.

## Philosophy

Relay's purpose is to make a dangerous capability **bounded, attributed, previewable and
survivable**, so that granting it is a rational decision rather than an act of faith.

The phrasing matters. Relay does not try to avoid remote code execution — it *is* remote
code execution, offered deliberately, and a design that pretended otherwise would be a
worse one.

Fleet tools like Ansible, Salt, and Chef were designed around a **trusted human
operator**: the control plane faithfully amplifies whatever the operator says, and safety
is procedure layered on top. That holds exactly as long as the operator is careful,
honest, and human. Relay assumes none of those three.

The answer here rests on one move: **the enforcement that matters lives on the machine
being protected, not in the thing asking.** Every managed Node holds its own root-owned
Policy that nothing on the wire can widen. A control that lives only in the control plane
is advisory, because it evaporates the moment the control plane is owned. A control rooted
on the Node does not.

Procedure is still kept — approval, step-up re-authentication, an emergency Freeze. What
is rejected is procedure *standing alone*: every procedural control has a structural floor
beneath it that holds when the person fails.

That sets the design bar. The question is never "how hard is this to break into" but
**"what is still true after it has been broken into."** A fully compromised Relay must
still be unable to exceed what each Node already permits locally.

The AI framing is not a separate concern. A jailbroken AI-agent is simply the most
demanding instance of the general problem — untiring, fast, plausible, and wrong. A design
that holds against it holds against a compromised human operator with stolen credentials,
because the architecture never asked who was asking in the first place. Designing for the
hostile AI-agent is what makes the ordinary case safe.

## Who Relay defends against

The design must hold when each of these is true, individually or together:

- The AI-agent is jailbroken or hallucinating, and is issuing instructions in earnest.
- The Relay itself is fully compromised — an attacker holds the control plane.
- A Node is compromised and is lying to the Relay about what it is.
- The human operator is malicious or mistaken, and is using legitimate credentials.

Each has a structural answer beneath whatever procedural one it also has. That is what the
architecture invariants in [AGENTS.md](AGENTS.md) encode, and what
[docs/security/threat-model.md](docs/security/threat-model.md) maps boundary by boundary.

## Core ideas

- **Typed Operations, not shell strings.** A fixed vocabulary of structured Operations is the
  primary execution primitive; a regex-gated **Raw Exec** escape hatch covers the long tail.
  Between them sit **Template Operations**: operator-authored, with the command structure
  fixed in a root-owned local file and every parameter slot single-quoted, so an argument can
  never change which command runs — new vocabulary is Templates, never new Natives.
  ([ADR-0001](docs/adr/0001-structured-operations-with-regex-gated-raw-exec.md),
  [ADR-0021](docs/adr/0021-local-template-tier-shipped-read-catalog-native-freeze.md))
- **The Node distrusts the Relay.** Policy is locally-rooted and remotely-immutable, so a
  compromised Relay or jailbroken AI-agent still cannot exceed a Node's local limits.
  ([ADR-0002](docs/adr/0002-node-side-policy-is-locally-rooted-and-remotely-immutable.md))
- **Selector fan-out.** The AI-agent targets Nodes by label Selector; one call fans out across
  the fleet with a hard blast-radius cap.
  ([ADR-0003](docs/adr/0003-mcp-meta-tool-surface-with-selector-fan-out.md),
  [ADR-0004](docs/adr/0004-async-job-execution-model.md))
- **Outbound-only, mutually authenticated.** Daemons need no inbound ports; identity is an
  mTLS client cert issued at enrollment.
  ([ADR-0005](docs/adr/0005-grpc-bidi-over-mtls-transport.md),
  [ADR-0006](docs/adr/0006-node-enrollment-identity-and-label-authority.md))
- **A System Model the AI maintains.** The Relay holds a git-backed semantic graph that links
  Labels into Services and Dependencies, so the AI-agent understands the fleet as a connected
  system — not isolated Nodes. Advisory only; auditable and human-correctable via git.
  ([ADR-0008](docs/adr/0008-system-model-git-backed-semantic-graph.md))

## Configuration

The Relay's blast-radius caps (above) are startup-only: `-read-blast-cap` /
`RELAY_READ_BLAST_CAP` (default 10000, generous) and `-mutate-blast-cap` /
`RELAY_MUTATE_BLAST_CAP` (default 100, small — Raw Exec always takes this one).
The minimum-daemon-version gate is the same shape: `-min-daemon-version` /
`RELAY_MIN_DAEMON_VERSION` (semver, empty = off) flags any connected Node whose
reported daemon version is below it as `outdated` in the registry.
([ADR-0014](docs/adr/0014-daemon-lifecycle-iac-upgrades-version-gate.md))
Like the rest of the Relay's config today, these are resolved once from flags/env
at process start; nothing sets or raises them via an API.

## Repository layout

The annotated layout lives in one place: [AGENTS.md § Repository layout](AGENTS.md#repository-layout).

## Status

Pre-release, and **not yet licensed for use** — publishing a `LICENSE` (source-available under
the BSL) is still open (#123) and its parameters are undecided.

**The GitHub milestones are the authority on what is in progress**, and the GitHub releases on
what has shipped; read them with `gh` rather than inferring either from any file. Milestones
were deliberately built out of order — the Template engine and shipped catalog, Accounts and
access, the Control API, approval callout, and the MCP Tasks extension shipped ahead of a
real-hardware proof.

## Documentation

- **[AGENTS.md](AGENTS.md)** — how to work in this repo, and the fourteen architecture invariants that constrain every change.
- **[GLOSSARY.md](GLOSSARY.md)** — the ubiquitous language. Every term here is canonical.
- **[docs/specs/](docs/specs/)** — capability specifications: what each capability does today, across MCP, the Control API, and the Admin Console.
- **[docs/adr/](docs/adr/)** — why the architecture is the way it is.
- **[docs/security/threat-model.md](docs/security/threat-model.md)** — the trust boundaries, and which invariant defends each.
- **[docs/api/](docs/api/)** — Control API reference and OpenAPI surface.
- **[docs/operations/beta-hardware-validation.md](docs/operations/beta-hardware-validation.md)** — the one validation that cannot be automated: proving the vertical slice on real machines.
- **[docs/dev-fleet.md](docs/dev-fleet.md)** — local dev fleet: `make dev-fleet-up` for one Relay + N relay-daemons, drivable over MCP (dev-only).
- **[docs/operations/relay-install.md](docs/operations/relay-install.md)** — installing and running the Relay from a released artifact: verify-then-install, flags/env, the packaged `systemd` unit.
- **[docs/operations/relay-daemon-install.md](docs/operations/relay-daemon-install.md)** — installing and running the relay-daemon on a Node: artifact, env config, Policy, the shipped unit.
- **[docs/operations/enrollment.md](docs/operations/enrollment.md)** — joining Nodes to the fleet: scoped Enrollment Tokens, single-Node and bulk (Ansible) enrollment.
- **[docs/operations/policy-as-code.md](docs/operations/policy-as-code.md)** — Policy files in the IaC repo: `policy check` in CI, config-management distribution, fingerprint-verified rollout.
- **[docs/operations/template-packs.md](docs/operations/template-packs.md)** — Template Operations: authoring typed parameter slots, the template-pack convention, fingerprint-verified rollout, and the `unsupported` outcome.
- **[docs/operations/iac-upgrades.md](docs/operations/iac-upgrades.md)** — daemon upgrades through config management, consuming the CD artifacts, observed by the `min-daemon-version` gate (ADR-0014).
- **[docs/operations/ca-disaster-recovery.md](docs/operations/ca-disaster-recovery.md)** — CA key custody, backups, and the "burn it down" compromise runbook.
- **[docs/operations/daemon-privilege-posture.md](docs/operations/daemon-privilege-posture.md)** — the hardened `systemd` unit and per-Operation privilege map for running relay-daemon in production.
- **[docs/operations/version-stamping.md](docs/operations/version-stamping.md)** — what a build reports for `--version`, and how the daemon's version feeds the ADR-0014 `min-daemon-version` gate.
- **[docs/operations/release-artifacts.md](docs/operations/release-artifacts.md)** — release artifact naming, pinning, and verify-then-install.
- **[docs/operations/control-plane-credential.md](docs/operations/control-plane-credential.md)** — the API Token a control-plane caller presents, and why Relay's config can grant none.
- **[docs/operations/approval-gates.md](docs/operations/approval-gates.md)** — which dispatches wait for a human before they run, and where that is configured (ADR-0027).
- **[docs/operations/audit-output-retention.md](docs/operations/audit-output-retention.md)** — what the audit trail keeps of a Task's output: full for `mutate`, metadata-only for `read`.
- **[docs/operations/demo-fleet.md](docs/operations/demo-fleet.md)** — the nine-Node `demo` profile of the dev fleet as a runbook: roster, beats, fault injection.
- **[docs/deferred.md](docs/deferred.md)** — work agreed in principle and not yet specified. Each gets an ADR when picked up.
