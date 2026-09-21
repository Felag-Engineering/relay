# Account suspension — fencing one actor without freezing the fleet

**Status:** Deferred — not adopted (2026-08-24).

> **Status: Deferred — not adopted (2026-08-24).** Withdrawn in the review that followed its
> drafting, before any code. Kept at its number so the reasoning, and the defects found in it, are
> not re-derived. Nothing below is in force: the incident ladder remains ADR-0020's three rungs
> (quarantine < revoke < Freeze), and stopping one actor is done by revoking its API Tokens or by
> Freeze. Revival is tracked as #443.
>
> **Why it was withdrawn.** (1) Plumbing for a control nothing yet needs. (2) As written it can lock
> every admin out: `operator`+ may suspend any Account including admins, lifting is an admin *call*,
> and a suspended Account's every call is refused — a hijacked operator session that suspends every
> admin leaves nobody able to lift. Freeze has no such hole because it never refuses its own
> release. (3) It omits the Account model's existing `Enabled` off-switch from its Considered
> Options, and the code comment on that field already used the word "suspended" for it. (4) Its
> Disconnect clause has no object: the MCP transport is stateless (ADR-0028; `Stateless: true`, no
> `Mcp-Session-Id`), so there is no connection to drop.
>
> **Constraints any revival must satisfy:** a role ceiling (an Account may suspend only Accounts at
> or below its own role; only `admin` suspends `admin`); no self-suspension; the last active
> (enabled and unsuspended) admin cannot be suspended; the lift call is *not* exempt from refusal;
> engage is human-principal only; suspension and `Enabled` are independent states (re-enabling does
> not lift); storage as columns on the Account with history in audit.

The incident ladder ADR-0020 records is quarantine (`relay:`) < revoke < Freeze. Every rung fences
a **Node** or the whole fleet. None of them fences an **actor**.

That gap has a specific shape now that an AI-agent drives the control plane. An operator watching
the agent surface (`docs/design/console/03-agent-sessions.md`) sees a machine Account doing
something alarming and has two options: revoke its API Token — heavyweight, not cheaply reversible,
and really credential management rather than incident response — or Freeze the entire fleet,
stopping every other actor's legitimate work to stop one. Neither is what the situation calls for.

The obvious reach, "end the session", is not a control at all. An MCP session is authenticated by a
bearer token; dropping the connection buys the seconds it takes the client to reconnect with the
same credential.

## Decisions

- **Suspension is a reversible state on the Account** (ADR-0010), not on a session or a
  credential. A suspended Account may still authenticate and connect; **every call it makes is
  refused**. This is what makes the control durable where a connection kill is not.

- **Everything is refused, not merely dispatch.** An Account is suspended because it is not
  trusted, and reading is exfiltration by construction (ADR-0021) — a read result flows onward to
  the model provider. A dispatch-only brake would leave the exfiltration path open, which is the
  wrong half to keep. Refused calls are **audited**, so a suspended agent remains observable
  through what it attempts.

- **In-flight Tasks keep running.** Suspension halts new calls; it does not reach into work already
  dispatched. This is Freeze's semantics exactly (ADR-0013), and `TaskCancel` remains the only
  instrument for in-flight work. Two controls, one consistent meaning of "stop".

- **Fire-alarm asymmetry, as ADR-0013 established for Freeze:** `operator`+ to suspend, with no
  step-up — anyone who can see the problem may pull the cord. `admin` **plus step-up**, with an
  audited reason, to lift. Lifting is marginally stricter than releasing a Freeze because it
  restores privilege to one named actor, which ADR-0009 puts in the step-up class.

- **Suspension is not revocation.** API Tokens, Enrollment Token scope and role assignment all
  survive it. Conflating the two would cost the cheap reversibility that is the entire reason the
  rung exists — an operator who hesitates because undoing it is expensive will reach for Freeze
  instead, or for nothing.

- **Disconnect is a separate, non-security convenience.** Dropping an agent's connection so a stuck
  loop restarts with fresh context is a real and benign need, and it is **not a rung on the
  ladder**. Any surface offering it must say the Account may reconnect immediately.

## Considered Options

- **Terminate the session.** The first design, and the intuitive one. Rejected: bearer-token
  authentication means the client reconnects immediately, so the control is theatre — it looks like
  a brake and stops nothing. It survives here only as Disconnect, honestly labelled.

- **Revoke the Account's API Token.** Genuinely stops the actor. Rejected as the incident
  instrument: re-issuing is an `admin` ceremony that yields a *new* credential to distribute, so
  the action is not reversible in the sense an operator needs at 3am, and a token may be shared
  across sessions the operator did not mean to stop. It remains the right move for a credential
  believed compromised.

- **Temporarily demote the Account to `viewer`.** Cheap and uses existing machinery. Rejected
  twice over: it mutates a durable authorization field to encode a transient condition, so the
  original role is lost unless something else remembers it; and a `viewer` can still read, which
  means the exfiltration path stays open.

- **A per-Account Freeze — dispatch refused, reads allowed.** Symmetric with Freeze and keeps a
  legitimate orchestrator observable and able to report on work it already did. Rejected on
  ADR-0021: if the reason for suspension is that the actor may be compromised, continuing to serve
  it reads is continuing to hand it the fleet's contents.

- **Do nothing; use Freeze.** The status quo. Rejected on collateral damage: stopping every actor
  to stop one is a cost operators will decline to pay, which means in practice they will do nothing
  at all.

## Consequences

- **Amends ADR-0020's incident ladder** to four rungs: quarantine (one Node) < **suspend** (one
  actor) < revoke (one Node, irreversible) < Freeze (everything). Quarantine fences a machine;
  suspend fences an actor. The symmetry is the teachable part.

- **The Account model gains a suspension state**, its audit events (engage, lift, and every refused
  call while suspended), and enforcement at the capability layer's authorization chokepoint — never
  in a surface. A Console or MCP-specific check would be a second control path.

- **A hijacked `operator` session can suspend Accounts**, which is a denial of service against the
  customer's own automation. Bounded and noisy: suspension changes no credential and destroys no
  state, every engage is audited, and lifting requires `admin` + step-up, so the attack makes noise
  rather than progress. This is the same trade ADR-0013 accepted for Freeze.

- **A suspended agent stays observable.** Because refusals are audited, the operator can watch what
  a suspended actor tries to do next — which is often exactly the evidence needed to decide whether
  to lift the suspension or revoke the credential.

- Console surfaces are specified in `docs/design/console/` (03, 15, 16) and depend on this ADR
  landing first.
