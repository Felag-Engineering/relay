# 16 — Incident

**No artboard.** The three rungs on one surface, in ascending order of consequence.
**Milestone v0.7.0.**

**Governing:** ADR-0013, ADR-0020, ADR-0006, invariants #7.
**Backend:** Freeze engage/release; `relay:` label writes; Node revocation —
all through the capability layer.

> **Blocked by [#397](https://github.com/Felag-Engineering/gleipnir-relay/issues/397).** Two of the
> three rungs on this screen have **no role gate on the API today**: `POST /api/v1/nodes/{id}/revoke`
> and `POST /api/v1/freeze/engage|release` authenticate the caller and never check their role, so a
> `viewer` can do both. Shipping a screen whose buttons state a role requirement the API does not
> enforce documents a protection that is not there. Fix #397 first.

## What this screen is for

During an incident nobody reads a nav. The four controls that stop things are currently scattered
across Node detail, the agent stream and a global banner, and the **relationship between them** —
which is the actual knowledge an operator needs at 3am — exists only in documentation.

This screen puts them in one place, ordered, with their blast radius stated.

## The ladder

| Rung | Fences | Engage | Lift | Reversible |
|---|---|---|---|---|
| **Quarantine** Nodes | the resolved Nodes, within the `mutate` blast cap | `operator`+, machine Accounts allowed, reason | human `admin` + step-up, reason | yes |
| **Revoke** a Node | one Node | `admin` + step-up | — | **no** |
| **Freeze** the fleet | everything | `operator`+ | `admin` + reason | yes |

Rendered top to bottom in that order, with blast radius stated on each in plain words. The ordering
is the teaching: reach for the narrowest thing that works.

**Cancel is not on the ladder.** It stops one in-flight Task and nothing future. Every rung above
leaves in-flight Tasks running, and Cancel is the only instrument for those — say so on this
screen, because it is the most common misunderstanding.

## Current state comes first

Before the controls: what is engaged **right now**. Frozen or not, and since when and by whom;
which Nodes carry `relay:quarantine`; recently revoked Nodes.

An incident screen that opens on a set of buttons rather than a situation is a screen nobody trusts
under pressure.

## Freeze

Cheap to engage, deliberate to release (ADR-0013). Engaging states what it does and what it does
**not**: halts all new Task dispatch across every risk class, leaves in-flight Tasks running, leaves
Preflights available. Persisted across Relay restarts.

**Engage is human-principal only** — a machine Account, whatever its role, cannot freeze the
fleet (#397). Releasing requires `admin` and an audited reason. An emergency stop that looks like a total outage
gets released in a panic — the release path is where that panic is slowed deliberately.

## Quarantine

Setting `relay:quarantine=on` on a Node.

> **The value is pinned, and pinned deliberately.** The fence is
> `relay:quarantine=`**`on`** — key *and* value — not the bare presence of the key.
> A reader that tests only for the key treats `relay:quarantine=off` as fenced,
> while a Selector tests both (`capability.Predicate`), so the set the Console
> draws and the set an operator can target would differ. On the security lane,
> "fence these Nodes" resolving to a different set than the one on screen is the
> failure that matters. Decided **2026-08-26**, before any writer exists — which is
> the cheap moment, since after one ships this becomes a fleet-wide migration of a
> security-lane label. The constants are `registry.QuarantineKey` /
> `registry.QuarantineOn`; the quarantine capability must write through
> them, and no surface may spell the string itself.

**Revised 2026-09-16** to match invariant 7 as amended (ADR-0006, ADR-0020) and
`docs/specs/quarantine-node.md`. The earlier text here — `admin` + step-up for both acts, through a
generic `relay:` label write, `relay:`-only targets — is superseded. No Account writes a `relay:`
label directly; `relay:quarantine=on` is written only by engaging a quarantine and cleared only by
lifting one.

- **Engage:** `operator` or above, machine Accounts included, with a required reason. Targets a
  Selector of only `relay:` and `tag:` terms — explicit Node IDs, `relay:enrollment-token=…`, or
  `tag:incident=4412`. A `node:` or `state:` term is refused. From a filtered Fleet view the
  Console sends the resolved Node IDs, never the filter. The Selector resolves once; the confirm
  step shows the exact Nodes before anything is written, and the result shows them again. One
  engage counts against the `mutate` blast cap, so the confirm step says how many Nodes that is and
  refuses above the cap — a fleet-wide fence is a Freeze. Also from Node detail (spec 02) for one
  Node.
- **Lift:** a **human** `admin` with step-up and a required reason. Targets `relay:` terms only —
  in the Console, the quarantined Nodes selected on this screen's current-state list. A `tag:`
  can never release a Node.
- **Nothing is sent to a quarantined Node, reads included**, and the Node is not told. Tasks
  already running keep running; say so beside the control, and point at Cancel.

Because `relay:quarantine` is Node-immutable, a compromised Node can never remove it — which is the
entire reason quarantine works at all.

## Revoke

The only irreversible rung, and it must read that way. Revoking a Node's certificate ends its
identity; rejoining means enrollment with a fresh Enrollment Token. Confirm with the Node named,
not a count.

## Stopping one actor

Not a rung. Account suspension (ADR-0035) is **deferred, not adopted** (#443); the instruments are
revoking the Account's API Tokens (spec 15) or Freeze. Say so on this screen, because it is the
question an operator asks here.

## Must not appear

- Any Relay configuration, including the Freeze persistence path or gate rules.
- A "panic button" that engages several rungs at once. The ladder exists to make people choose the
  narrowest instrument; a combined control defeats it.
- Revocation without the Node named in the confirmation.

## Acceptance

- [ ] Current state renders before any control.
- [ ] Rungs render in ascending blast-radius order with their radius stated.
- [ ] Freeze engages with `operator`+ and releases only with `admin` and a recorded reason.
- [ ] Revoke is visually distinct as irreversible and names the Node in its confirmation.
- [ ] The screen states that no rung stops in-flight Tasks, and points at Cancel.
- [ ] Every action here is audited with actor, target and reason.
- [ ] Freeze engage is refused to a machine Account of any role.
- [ ] Quarantine by Selector refuses any term outside `relay:`.
