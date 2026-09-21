# Agentless SSH execution as an explicitly low-assurance tier (control-plane-side enforcement, no Node veto)

**Status:** Proposed.

**Status: Proposed — a potential new avenue, not an accepted decision.** Records the
option and the guardrails it would require. Ratification is a human call; this ADR
touches the security surface and the founding thesis (ADR-0002) and must not be adopted
without review.

An optional execution mode in which the **Relay** initiates SSH *into* Nodes and runs a
curated, parameter-validated command through a **Relay-side executor**, with **no
relay-daemon on the Node**. It is the agentless (Ansible-shaped) model: nothing is
installed on the target; the control plane holds SSH access and runs vetted commands.
Its defining property — and its defining cost — is that **enforcement is entirely
control-plane-side; the Node retains no veto.**

## Why consider it

The relay-daemon carries a real adoption tax: landing a net-new privileged component on
every Node (binary + root-owned Policy, provisioned via config management) is the single
likeliest thing to stall adoption, independent of architecture quality. Agentless
execution removes the per-Node footprint entirely — the reason the config-management
market largely runs this way. It offers a fast, zero-footprint on-ramp and a
land-and-expand path: adopt agentless, upsell the daemon to security-serious accounts.

## The crux — what it keeps and what it surrenders

This mode preserves the **agent-client-facing** safety and surrenders the
**Relay-distrust** safety. Precisely:

- **Kept (gates 1–3):** authentication to a machine **Account**, **Grant**
  authorization, the blast-radius cap, and a curated command vocabulary. The AI-agent
  still cannot run arbitrary commands — only vetted, parameter-checked templates. The
  SSH executor is *just another dispatch adapter behind the one capability layer*
  (ADR-0009/0010), never a parallel control path.
- **Surrendered (gate 4 / ADR-0002):** the Node no longer enforces local **Policy**; it
  executes whatever arrives over SSH. A misbehaving or jailbroken AI-agent is contained
  by the Relay; **a compromised Relay is not contained by anything.** Relay holding SSH
  to the fleet *and* being the sole enforcement point equals fleet-wide root from one
  box — the exact inversion ADR-0002 exists to prevent.

So: this tier defends against a *misbehaving AI-agent*, not against a *compromised
Relay*. The relay-daemon defends against both. That gap is the whole difference, and it
is not recoverable within this mode — there is no SSH path to a Node-side veto, because a
Node-side veto requires Node-side code.

## Considered Options

- **relay-daemon only (status quo; ADR-0002, ADR-0005).** Strongest — survives a fully
  compromised Relay, argv-never-shell execution, outbound-only. Pays the per-Node
  install cost. The reference architecture and the only tier that realizes the founding
  thesis.
- **Agentless SSH executor (this ADR).** No per-Node install; fastest adoption.
  Surrenders the Node veto and the outbound-only posture. A legitimate *reduced-assurance*
  tier, never a replacement.
- **SSH + a Node-side forced-command enforcer.** Preserves the veto (the enforcer still
  gates locally) but reintroduces the per-Node install — so it is *not* agentless and
  does not solve the adoption tax this ADR targets. Belongs to the daemon-tier family.

## Non-negotiable guardrails if adopted

1. **Explicitly low-assurance; never the default, never mismarketed.** It must never be
   documented or sold as delivering Relay-compromise resistance or the "Node distrusts
   the Relay" property. Misrepresenting the customer's threat model is the one move the
   product cannot make — the entire brand is honesty about trust boundaries. Every
   surface that offers this tier states, in the customer's face, that it trusts the
   control plane.
2. **Gates 1–3 are identical to the daemon path.** Same capability layer, Accounts,
   Grants, blast cap, Freeze, per-Account audit. No bespoke control path.
3. **Curated templates only; the remote shell is hostile.** Commands are operator-defined
   templates with per-parameter validation and quoting — never AI-supplied raw strings.
   Because SSH exec runs the command string through the Node's login shell, parameter
   expansion is a shell-injection surface; this executor inherits the Template Operation
   parameter-safety discipline (ADR-0001 tier 2) and treats the shell boundary as an
   attacker. **Raw Exec over this transport is forbidden** (there is no veto behind it).
4. **Least-privilege SSH principal.** Relay logs in as a dedicated, non-root, tightly
   scoped account; the SSH key is a fleet-wide secret and gets rotation, scoping, and
   monitoring commensurate with root-on-the-fleet.
5. **Composes with the stop controls.** Freeze halts it; the blast cap applies; every
   action is attributed to its Account (ADR-0013, ADR-0004).

## Consequences

- Enables a two-tier product: **agentless = adoption, daemon = the moat.** The tiers must
  carry ruthlessly clear guarantee labels — a published matrix with "survives a
  compromised Relay: daemon = yes, agentless = **no**" as a first-class row.
- **Loses the outbound-only / no-inbound-ports property (ADR-0005):** Relay dials in;
  Nodes need reachable SSH. Acceptable on flat internal networks (the on-prem case that
  motivates it), but a genuine change to the transport posture, not a footnote.
- **The Node-side Policy story does not apply on agentless Nodes.** The local
  `policy.toml` and the operator-signed distribution model (ADR-0002; v0.8.0) are
  meaningless where there is no local enforcer — enforcement is 100% the Relay-side
  curated vocabulary plus Grants. Documentation must not imply otherwise.
- Does **not** change the daemon tier. The relay-daemon remains the reference
  architecture and the only configuration that realizes "hand your fleet to an AI without
  handing it trust."
- If accepted: GLOSSARY.md gains a term for this execution mode, and the threat-model
  doc (v0.0.8) must cover it as an explicit reduced-assurance configuration with its own
  boundary diagram.

## Note (2026-09-20): numbering

This proposal was filed as a second `ADR-0015` on 2026-08-27, colliding with the golden-schema
ADR; #570 renumbered it to **ADR-0037** on 2026-09-12. Any citation of "ADR-0015" that means
the agentless tier is stale (#281 was retitled). Still **Proposed**; a spec's *Governing ADRs*
section must not lean on it.
