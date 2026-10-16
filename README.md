# Relay

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/relay-wordmark-dark.svg">
    <img src="docs/brand/relay-wordmark-light.svg" alt="Relay" width="360">
  </picture>
</p>

**Relay lets you hand your fleet to an AI without handing it trust.**

Relay is a fleet-administration control plane for Linux servers. An AI-agent drives it as an
MCP tool. Each managed server still decides for itself what may run.

- **Node-rooted Policy.** Every Node holds its own root-owned Policy that nothing on the wire
  can widen. A compromised Relay still cannot exceed it.
- **Typed Operations.** The AI-agent calls structured Operations, not shell strings. Raw Exec is
  a regex-gated escape hatch for the long tail.
- **Blast cap and approval.** A hard cap limits how many Nodes one call can reach. Approval
  gates make chosen dispatches wait for a human.

## Quickstart

You need Docker Engine with the Compose v2.18+ plugin. The first run compiles both programs
inside Docker images, which takes a few minutes. After that, bringing the fleet up takes
seconds.

Start one Relay and three relay-daemons. The command returns once every daemon is healthy:

```console
$ make dev-fleet-up
…
 Container relay-demo-daemon-2-1 Healthy
 Container relay-demo-relay-1 Healthy
 Container relay-demo-daemon-3-1 Healthy
 Container relay-demo-daemon-1-1 Healthy
```

Export the fleet's CA certificate and control-plane credentials to `./.dev-fleet/`:

```console
$ make dev-fleet-creds
env -u STATE_DIR -u BASE bash scripts/dev-fleet-mcp.sh init
 relay-demo-relay-1 Copying relay-demo-relay-1:/var/lib/relay/ca/ca-cert.pem to .dev-fleet/ca-cert.pem
 relay-demo-relay-1 Copied relay-demo-relay-1:/var/lib/relay/ca/ca-cert.pem to .dev-fleet/ca-cert.pem
dev-fleet-mcp: CA cert and both credentials are in .dev-fleet/
dev-fleet-mcp: copy-paste launch commands: .dev-fleet/start-claude.txt
```

Call the MCP `run_operation` tool. This reads `/etc/os-release` on every dev Node:

```console
$ scripts/dev-fleet-mcp.sh call run_operation '{"selector":"relay:env=dev","operation":"file.read","args":{"path":"/etc/os-release"},"wait_seconds":30}'
…
    "structuredContent": {
      "job_id": "job-bc14009ea5e0173ea03ad28a675e8943",
      "job_status": "complete",
      "results": [
        {
          "duration_ms": 8,
          "exit_code": 0,
          "node_id": "node-9e4282abbacea4743b94100403020240",
          "outcome": "success",
          "stderr": "",
          "stderr_truncated": false,
          "stdout": "PRETTY_NAME=\"Relay dev-fleet (busybox)\"\nNAME=\"Relay dev-fleet\"\nID=relay-dev-fleet\n",
          "stdout_truncated": false
        },
…
```

Now ask for `/etc/shadow`. The fixture Policy on each Node denies it, so nothing executes:

```console
$ scripts/dev-fleet-mcp.sh call run_operation '{"selector":"relay:env=dev","operation":"file.read","args":{"path":"/etc/shadow"},"wait_seconds":30}'
…
    "structuredContent": {
      "job_id": "job-c700bdb3f855924418508ce6e486645e",
      "job_status": "complete",
      "results": [
        {
          "duration_ms": 7,
          "node_id": "node-9e4282abbacea4743b94100403020240",
          "outcome": "denied_by_policy",
          "refusal_explanation": "Refused by the Node, not by this control plane \u2014 a refusal, not a failure: nothing executed. Policy is local to the Node: the relay-daemon loads it from that Node's own disk, and the Relay has no code path to add, change or relax a rule over the wire (ADR-0002). The Node is never told which Account or role asked \u2014 the wire contract carries no caller identity \u2014 so the same request reaching the Node gets the same answer whoever asks, and no credential this control plane can issue changes it. Where the answer is a Policy rule, widening it is a deliberate human change on the Node itself, delivered by your own config management, and never something this control plane can do.",
          "stderr": "denied by explicit rule for operation 'file.read'",
          "stderr_truncated": false,
          "stdout": "",
          "stdout_truncated": false
        },
…
```

The verdict is the daemon's, not the Relay's. The Relay never evaluates Policy.

The same refusal in the Console, at `https://127.0.0.1:9443/console/` (sign in as `admin` /
`admin1234567`):

<p align="center">
  <img src="docs/images/console-policy-refusal.gif" alt="The Console's Activity feed gains a file.read of /etc/shadow refused on three Nodes; its Job page shows denied_by_policy and the Node's refusal explanation." width="720">
</p>

<p align="center">
  <img src="docs/images/console-fleet.png" alt="The Console's Fleet screen: three Nodes grouped by node:role, with their labels, Policy fingerprint and last-seen time." width="720">
</p>

This fleet is dev-only: committed credentials, a fixture Policy, one host.
[docs/dev-fleet.md](docs/dev-fleet.md) covers Claude Code, the approval gate and the Console
in depth. A real deployment starts at
[docs/operations/relay-install.md](docs/operations/relay-install.md). `make dev-fleet-down`
stops the fleet.

## How it works

```
┌─────────────┐   MCP    ┌──────────────────┐  gRPC/mTLS   ┌────────────────────┐
│  AI-agent   │ ───────▶ │      Relay       │ ◀─ dial home ─│   relay-daemon ×N  │
│ (MCP client)│  tools   │  (Go server)     │  persistent   │   (Rust, per Node) │
└─────────────┘          └──────────────────┘   bidi stream └────────────────────┘
                                                                  │ enforce local Policy
                                                                  ▼ execute Operation / Raw Exec
```

Relay is two programs, and everything else in the system is one of them or a thin adapter
over one.

The **Relay** is a central server, written in Go. It holds the registry of known Nodes,
resolves which of them a request targets, authorizes the caller, and caps how far a single
action may reach. It dispatches the work and records what happened. It is also the private CA
that mints each Node's identity at enrollment. It is the only thing that talks to the fleet,
and the only thing an operator or an AI-agent talks to.

The **relay-daemon** is a small daemon, written in Rust, installed on every managed server. It
dials out to the Relay and holds one persistent connection open, so no managed server needs an
inbound port. It evaluates each Task against a Policy file on its own disk, owned by root, and
executes only what that Policy permits. It is not an AI, does not reason, and never becomes
either. Per-Node Policy restricting what may actually run, beneath a Relay that already
authorizes and caps, is defense in depth.

Three surfaces reach the Relay: the MCP surface an AI-agent drives, the Control API that
tooling calls, and the Admin Console a human uses. All three are adapters over one capability
layer, so what may be done, who may do it, and how it is recorded are decided once rather than
three times.

- **Typed Operations, not shell strings.** A fixed vocabulary of structured Operations is the
  primary execution primitive; a regex-gated **Raw Exec** escape hatch covers the long tail.
  Between them sit **Template Operations**: operator-authored, with the command structure
  fixed in a root-owned local file and every parameter value passed to the shell as data,
  never as shell text, so an argument can never change which command runs. New vocabulary is
  Templates, never new Natives.
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
  system rather than isolated Nodes. Advisory only; auditable and human-correctable via git.
  ([ADR-0008](docs/adr/0008-system-model-git-backed-semantic-graph.md))

## MCP tools

The MCP surface registers eight tools. Each line is taken from the tool's own description.

| Tool | What it does |
|---|---|
| `list_nodes` | List Nodes in the fleet registry, optionally filtered by a Selector. |
| `describe_node` | Describe one Node in full, including its effective Policy as last reported by the daemon. |
| `list_operations` | List the Operation vocabulary: each Operation's purpose, risk class, argument names, types and constraints, and a usage example. |
| `run_operation` | The default way to act on Nodes: run a structured Operation against a Selector's matched Nodes. |
| `raw_exec` | The escape hatch, for when no structured Operation expresses the task: run an argv that each Node's Policy regex allows or refuses. |
| `get_job` | Re-read a Job's per-Node results by id. |
| `cancel_job` | Cancel a Job's Tasks. |
| `approve_request` | Answer a parked approval request: the in-band decision path, relaying a decision a human actually made. |

The Control API exposes the same capability layer to tooling; its reference is
[docs/api/](docs/api/).

## Who Relay defends against

The design must hold when each of these is true, individually or together:

- The AI-agent is jailbroken or hallucinating, and is issuing instructions in earnest.
- The Relay itself is fully compromised — an attacker holds the control plane.
- A Node is compromised and is lying to the Relay about what it is.
- The human operator is malicious or mistaken, and is using legitimate credentials.

Each has a structural answer beneath whatever procedural one it also has. That is what the
architecture invariants in [AGENTS.md](AGENTS.md) encode, and what
[docs/security/threat-model.md](docs/security/threat-model.md) maps boundary by boundary.

### Why it is built this way

Other tools answer "what if the operator goes rogue?" with procedure; Relay answers with
architecture.

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

## Status

Pre-release. Relay is source-available under the [Business Source License 1.1](LICENSE). It
is free for personal, non-commercial use by individuals. Use by or for an organization needs a
commercial license. Each version converts to Apache-2.0 three years after its release, its
Change Date. Relay is source-available, not open source: issues are welcome, code
contributions from outside Felag Engineering are not accepted (see
[CONTRIBUTING.md](CONTRIBUTING.md)). The repository was renamed from `gleipnir-relay`; GitHub
redirects the old URL.

**The GitHub milestones are the authority on what is in progress**, and the GitHub releases on
what has shipped; read them with `gh` rather than inferring either from any file. Milestones
were deliberately built out of order. The Template engine and shipped catalog, Accounts and
access, the Control API, approval callout, and the MCP Tasks extension shipped ahead of a
real-hardware proof. For what the code on `main` does today, capability by capability, see
[docs/STATUS.md](docs/STATUS.md). Work agreed in principle but not yet specified is in
[docs/deferred.md](docs/deferred.md).

Gleipnir is the separate first-party AI-agent system that will drive Relay, as a consumer of its
MCP and Control API surfaces with no special privileges; the repository is now
`Felag-Engineering/relay`.

## Security

Relay is remote code execution as a service, by design. Report a vulnerability privately, never
in a public issue: [SECURITY.md](SECURITY.md) has the channel and the supported versions.

## Documentation

- **[docs/dev-fleet.md](docs/dev-fleet.md)**: the local dev fleet in depth, drivable over MCP from Claude Code or any other MCP client.
- **[docs/operations/](docs/operations/)**: operator runbooks for installing, enrolling, upgrading, auditing and recovering a fleet.
- **[docs/specs/](docs/specs/)**: capability specifications, saying what each capability does today across MCP, the Control API, and the Admin Console.
- **[docs/adr/](docs/adr/)**: why the architecture is the way it is.
- **[GLOSSARY.md](GLOSSARY.md)**: the ubiquitous language. Every term here is canonical.
- **[AGENTS.md](AGENTS.md)**: how to work in this repo, the [repository layout](AGENTS.md#repository-layout), and the fourteen architecture invariants that constrain every change.
