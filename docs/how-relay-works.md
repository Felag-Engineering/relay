# How Relay works

Relay is a safe way to let an AI-agent run commands on your servers. The question it exists to
answer is always the same: **who did what, on which machine, and which human stands behind
it.** Everything below is in service of controlling, restricting and auditing that.

This page is the outside view in plain words. What each capability does today is in
[`docs/specs/`](specs/); what is built on `main` is in [`STATUS.md`](STATUS.md); why the
system is shaped this way is in [`docs/adr/`](adr/); the fourteen rules that must always hold
are in [`AGENTS.md`](../AGENTS.md).

## The parts

- **A Node** is one of your Linux servers. On it runs the **relay-daemon**, a small program
  with no intelligence of its own. It dials out to the Relay, so nothing has to be opened
  inbound on the Node.
- **The Relay** is the control plane every daemon connects to, and every request to do
  anything on the fleet goes through it. It is loaded into an AI-agent's harness as an MCP
  server, so to the AI-agent the whole fleet is a set of tools.
- **The AI-agent** is the orchestrator that decides what to ask for. It is a client of Relay
  and never part of it. Relay treats it as capable, useful and untrusted.
- **A human** reaches the same Relay through the Admin Console or the Control API, to watch,
  to approve, and to administer. The Console offers a human nothing the API does not; both
  are views onto one capability layer.
- **Policy** is a root-owned file on each Node that says what that Node will and will not
  run. The Relay can read it and can never change it. Only whoever administers the Node can.

## What happens when the AI-agent asks for something

1. **The AI-agent calls a tool.** It names an Operation from a fixed vocabulary, such as reading
   a file or restarting a service, with typed arguments, and a Selector that says which Nodes.
   It cannot send a shell string. The one exception, Raw Exec, is conspicuous, separately
   gated, and always treated as the riskiest class of action.
2. **Relay knows who is asking.** The call arrives on an Account. A machine Account is how an
   AI-agent authenticates, and the record of the call carries that Account and the human the
   AI-agent acts for, so the audit trail always ends in a person. A human Account signs in with
   its own credentials, and sensitive actions ask the human to prove it again.
3. **Relay works out the reach.** The Selector resolves to a set of Nodes using Labels. Labels
   have namespaces with exactly one writer each, so a Node cannot promote itself into a
   group the security lane targets, and the AI-agent cannot relabel the fleet.
4. **Relay bounds the blast radius.** A hard cap on how many Nodes one call may reach is
   enforced before anything is sent. Mutating Operations have a tighter cap than reads.
5. **A human may have to say yes.** Approval rules make chosen dispatches wait for a human.
   Relay writes the question, the AI-agent's harness puts it to a person rather than to the
   model, and the answer binds to exactly what that person was shown. The AI-agent cannot send
   an approval itself. Routing the question honestly is the harness's job, and the record says
   which approvals Relay verified and which a client asserted.
6. **Each Node decides for itself.** The daemon receives a Task for exactly this Operation and
   these arguments, checks its own Policy, and refuses or runs. Policy is deny by default, a
   deny always beats an allow, and it can be as specific as a single argument value.
7. **It runs once, and the result comes back.** A Task has a unique ID and the daemon
   remembers what it has already run, so a dropped connection never runs something twice.
   The output, the exit code, and every refusal along the way are recorded against the Job.
8. **Everything is on the record.** Who asked, for whom, what resolved, what was capped, who
   approved, what each Node decided, and what happened. That record is what an operator reads
   afterwards and what an auditor reads later.

## What cannot happen

Each of these is a rule the code is held to, not a setting someone can turn off.

- Nothing on the wire can turn one command into another or add a second one.
- The Relay can never modify a Node's Policy. A compromised Relay cannot exceed what each Node
  already allows.
- Nothing is at-least-once. A Task runs at most once, however the network behaves.
- The AI-agent cannot widen its own reach: not the blast cap, not the Labels, not the approval
  rules. Changing those is a human's act, re-authenticated and audited.
- The daemon never updates itself and the Relay never pushes binaries. Software reaches a
  Node only through the customer's own configuration management.
- No credential, and not the Relay process itself, can change the terms on which credentials
  are accepted. That configuration is set on the host, outside Relay.

## Where Relay stops

Relay is for response and fleet administration. It is not configuration management, it does
not converge a fleet toward a desired state, it does not distribute software, it does not
author Policy centrally, and it is not a remote shell. Each of those has been asked for and
each is a deliberate no, recorded in `AGENTS.md`.

## Where to read next

- A capability, today, on every surface: the spec in [`docs/specs/`](specs/).
- The adversaries and the boundaries that hold against them:
  [`docs/security/threat-model.md`](security/threat-model.md).
- A decision and its reasons: the ADR in [`docs/adr/`](adr/), and the proposal it came from
  in [`docs/proposals/`](proposals/).
- Running it: [`docs/operations/`](operations/) for a real deployment,
  [`dev-fleet.md`](dev-fleet.md) for a local one.
