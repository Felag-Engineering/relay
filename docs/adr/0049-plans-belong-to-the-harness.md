# Plans belong to Gleipnir and the harness, not Relay

**Status:** Accepted (owner decision 2026-10-22).

This ADR supersedes ADR-0038 in full. ADR-0038's amendments of ADR-0011, ADR-0013 and ADR-0027
stand as renames only: the no-execution check is Policy preflight, it answers while frozen, and a
plan hash addresses one dispatch. Behaviour: `docs/specs/policy-preflight.md` and
`docs/specs/execution.md`. ADR-0038's design, as the harness's starting point, waits in the
private roadmap (`roadmap: runtime/plans-in-the-harness`).

## Decision

Relay runs one dispatch at a time and has no plan of its own. A **Plan** is Gleipnir's: a series
of tool calls, with branches, that Gleipnir determines and submits to the harness, which carries
it out one call at a time. Every call that reaches Relay is an ordinary dispatch, meeting the
Selector, authorization, the blast cap, the gate and each Node's Policy on its own. Relay's
**Policy preflight** is something else: the check that one tool call would be permitted, made
before it runs. ADR-0038's Relay-held Plan, never built, is withdrawn, and Relay stops using the
word for its own check.

## The decisions

1. **No Plan, no step cursor, no route on the Relay.** Relay stores no ordered list of steps and
   offers no tool, route or screen to propose, approve or advance one. A Job stays one dispatch of
   one Operation or Raw Exec, and `Stage` keeps its reserved meaning for batches within one Job.
2. **Gleipnir plans; the harness carries the plan out.** Relay cannot tell that two dispatches
   belong to one Plan, and enforces nothing about their order: each is decided alone. Whether the
   route a person saw is the route run is the harness's integrity, the same trust threat-model
   R21 records for approvals.
3. **Policy preflight keeps its name, and the wire follows it.** ADR-0011's decisions stand. The
   option the MCP tools and the Control API spell `plan` is renamed `preflight`
   (`policy-preflight.md` PF-19), because "plan" is Gleipnir's word for something else.
4. **The plan hash keeps its wire name and addresses one dispatch.** `plan_hash` is the content
   address ADR-0027 decision 8 defines for one gated dispatch; it has no multi-step reading.

## Why

A route held by Relay, with a payload-free cursor, was the strongest way to make an approved
sequence the sequence that runs. It was also a second execution model inside Relay, with its own
storage, lifecycle, half-finished state and Console screens, for work Gleipnir plans better: it
sees the whole task, including the parts Relay never touches, and it can branch. Relay's job is to
make each action safe; Gleipnir's is to choose the actions.

## What changes

- `docs/specs/plan.md` is removed. `execution.md`, `policy-preflight.md`, `approval.md`,
  `freeze.md` and `quarantine-node.md` stop describing a Relay Plan; the spec index and `STATUS`
  lose its rows.
- `GLOSSARY.md`: *Plan* is Gleipnir's; *Harness* is new; *Policy preflight*, *Plan hash*,
  *Stage*, *Freeze*, *Shape key*, *Approval* and *Approval grant* stop describing a Relay Plan.
- The threat model: R14 describes Gleipnir's Plans; the jailbroken-AI-agent narrative, *Kept
  current* and the invariant map cite this ADR.
- ADR-0006, ADR-0011, ADR-0013 and ADR-0042 lose their Relay-Plan wording; ADR-0038 carries a note
  pointing here. The OpenAPI description, the operations runbooks, the Console open-decisions page
  and the glossary allowlist follow.

## Alternatives

- **Build ADR-0038's Plan.** Strongest enforcement of an approved route, at the cost of a second
  execution model in Relay for work Gleipnir plans better.
- **Keep the `plan` wire option.** No breaking change, but Relay's check would share a name with
  Gleipnir's Plan, a confusion this decision exists to end.
