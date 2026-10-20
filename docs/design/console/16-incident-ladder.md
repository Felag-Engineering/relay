# 16 — Incident

**No artboard.** The three rungs on one surface, in ascending order of consequence.
**Milestone v0.7.0.**

**Governing:** ADR-0013, ADR-0020, ADR-0006, invariants #7.
**Backend:** Freeze engage/release; `relay:` label writes; Node revocation —
all through the capability layer.

## What this screen is for

During an incident nobody reads a nav. The controls that stop things are otherwise scattered
across Node detail, Activity and a global banner, and the **relationship between them** — what an
operator needs at 3am — lives only in documentation. This screen puts them in one place, ordered,
with their blast radius stated.

## The ladder

| Rung | Fences | Engage | Lift | Reversible |
|---|---|---|---|---|
| **Quarantine** Nodes | the resolved Nodes, within the `mutate` blast cap | `operator`+, machine Accounts allowed, reason | human `admin` + step-up, reason | yes |
| **Revoke** a Node | one Node | `admin` + step-up | — | **no** |
| **Freeze** the fleet | everything | `operator`+ | `admin` + reason | yes |

Rendered top to bottom in that order, with blast radius stated on each in plain words. The ordering
is the teaching: reach for the narrowest thing that works.

**Cancel is not on the ladder.** It stops one in-flight Task and nothing future. Every rung above
leaves in-flight Tasks running, and Cancel is the only instrument for those. Say so on this screen:
it is the most common misunderstanding.

## Current state comes first

Before the controls: what is engaged **right now**. Frozen or not, since when and by whom; which
Nodes carry `relay:quarantine`; recently revoked Nodes. A screen that opens on buttons rather than
a situation is one nobody trusts under pressure.

## Freeze

Cheap to engage, deliberate to release (ADR-0013). Engaging states what it does and what it does
**not**: halts all new Task dispatch across every risk class, leaves in-flight Tasks running, leaves
Preflights available. Persisted across Relay restarts.

**Engage is human-principal only** — a machine Account, whatever its role, cannot freeze the
fleet. Releasing requires `admin` and an audited reason. An emergency stop that looks like a total
outage gets released in a panic; the release path slows that panic deliberately.

## Quarantine

Setting `relay:quarantine=on` on a Node.

> **The value is pinned, deliberately** (decided 2026-08-26, before any writer exists). The
> fence is `relay:quarantine=`**`on`** — key *and* value — not the bare presence of the key. A
> reader that tests only the key treats `relay:quarantine=off` as fenced, while a Selector tests
> both (`capability.Predicate`), so the set the Console draws and the set an operator can target
> would differ — the failure that matters on the security lane. The constants are
> `registry.QuarantineKey` / `registry.QuarantineOn`; the quarantine capability writes through
> them, and no surface spells the string itself.

The rules follow invariant 7 (ADR-0006, ADR-0020) and `docs/specs/quarantine-node.md`. No Account
writes a `relay:` label directly; `relay:quarantine=on` is written only by engaging a quarantine
and cleared only by lifting one.

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

Because `relay:quarantine` is Node-immutable, a compromised Node can never remove it — which is why
quarantine works at all.

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
