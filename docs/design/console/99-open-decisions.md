# 99 — Open decisions

**Read this before writing Console code.** Several things the screen specs describe are **not
decided**. They are drawn in the wireframes because a wireframe is the cheap place to see an idea,
not because anyone has ruled on them.

Per CLAUDE.md, an implementing agent has **no merge authority** and must **stop and flag a human
rather than guess on a hard call**. Every item in the first two sections is a hard call. Building
past one turns a sketch into an accidental architecture, which is precisely the failure this file
exists to prevent.

---

## Blocking — needs an ADR before the code lands

### D1. The `state:` Label namespace

**What:** a fourth namespace of Relay-derived labels — `state:offline`, `state:version-gated`,
`state:policy-drift`, `state:template-drift` — targetable by Selectors, set by nobody.

**Why it exists:** operational state (daemon version, Policy fingerprint, liveness) is what fleet
maintenance actually targets — "run this on the ones that are behind" — and today it is not
expressible. Labels target; Facts explicitly do not; and daemon version and the fingerprints are
*neither*, as `Hello` shows by carrying `daemon_version` and `Facts` as separate fields.

**Why it needs an ADR:** it changes CONTEXT.md's definition of **Selector** ("a label-based
query") and adds a namespace alongside ADR-0006's and ADR-0020's three. Both files are
escalate-to-a-human.

**What the ADR must settle:**
- The vocabulary is **closed** and lives in the contract. Free-form state labels become a second
  `tag:` with none of the guarantees, and Selectors written against them silently stop matching
  when a definition changes.
- `state:` is **never** a valid security-lane target (invariant #7 stands: quarantine, remediation
  and secret distribution target `relay:` and only `relay:`). Rationale: it is computed partly from
  what the Node itself reports.
- Who computes it, when, and what a Selector resolves against — live evaluation or a materialised
  label. This has real consequences for plan-hash stability.

**Alternatives considered and rejected in session:** folding into `relay:` (mixes derived state
into the security lane); extending Selector grammar to comparisons like `daemon.version < 1.4.2`
(bigger change to the domain language); the `tag:` bridge (a snapshot that goes stale).

**Blocks:** specs 01, 02, 05. Until it is ruled on, the fleet view can render these states as
presentational chips but must not offer them as Selector terms.

### D2. Ending an agent session

**What:** a control that drops one MCP session and refuses its next call, on spec 03.

**Why it exists:** the incident ladder is quarantine < revoke Node < Freeze, and **none of those
stop one misbehaving agent** without collateral damage. Today the options are disabling its
Account or freezing the entire fleet.

**What needs settling:** whether this is a new capability-layer verb or an Account-level action;
what happens to in-flight Jobs it started (the spec assumes they continue and Cancel handles
them); whether it requires step-up; whether the session can reconnect immediately with the same
credential, and if so what the control actually bought.

**Blocks:** the v0.7.0 half of spec 03. The read-only stream does not depend on it.

---

## Needs a ruling — smaller, but not an implementer's call

### D3. The word "outdated" is overloaded

ADR-0014 uses `outdated` for **a daemon below the dispatch minimum** ("a below-minimum Node …
appears in the registry — flagged `outdated`"). `ui-advisory.md` uses it for **a Policy
fingerprint behind the fleet**. Two different states, one word, in two governing documents.

These specs retire the word in favour of `state:version-gated` and `state:policy-drift`.
**CONTEXT.md needs the ruling** on which meaning owns the term, or whether it is retired outright.

### D4. `state:cert-expiring`

Leaf validity is 336h with jittered renewal. A Node that stops renewing falls off the fleet inside
two weeks with **nothing on screen saying so**. It is a question-1 truth ("can I reach it?") and it
is the only one of the four questions with no state label.

Raised in session; **not ruled on**. If accepted it is a fifth entry in D1's closed vocabulary.

### D5. Two deviations from `console-wireframe-brief.md`

Both are argued on the shared-grammar artboard and neither is settled:

1. **Amber is split.** The brief reserved amber for the Freeze banner and quarantine, then used
   amber for the odd Node out in the pixel wall. These specs use amber for *attention* (Freeze,
   offline, version-gated, over-cap) and indigo for *the security lane* (`relay:`), which keeps
   quarantine visually attached to `relay:` everywhere it appears.
2. **One muted red exists**, on `failure` and `timeout` only. The brief says "red for nothing
   routine"; a Task that ran and failed is not routine.

### D6. Does `Jobs` survive as a nav destination?

Activity (spec 04) renders Job rows and filters to them. A separate Jobs destination is currently
both a duplicate and a convenience. Pick one.

### D7. Policy as its own nav item

The nav carries ten destinations in three groups. Policy could fold under Add Nodes as "Node
setup". These specs give it its own slot on the argument that Policy authoring recurs while
enrollment is mostly a one-off.

---

## Prerequisites that already exist as issues

### D8. #397 — enrollment mint has no role gate

`POST /api/v1/enrollment-tokens` authenticates the caller and never checks their role, so a
`viewer` can mint a token that stamps `relay:` labels. **Spec 09 must not ship before this is
fixed** — rendering on top of an ungated mint wraps a privilege escalation in a convenience.

### D9. The SSE seam must cover MCP tool calls

`console-backend-coverage.md` scopes the v0.6.0 event seam to "registry and Job state
transitions". Spec 03 needs tool-call events, which is a **different source**. Either widen the
seam's scope or sequence spec 03 after it.

### D10. The approval-record schema must store the diff basis

Spec 08's anti-fatigue diff ("same as Tuesday, except the fan-out grew 1,180 → 2,214") requires
the approval record to hold enough to compare against a prior approval of the same shape.
`ui-advisory.md` already flags this as a v0.5.0 schema concern. It cannot be retrofitted cheaply.

---

## Proposed, not specified

### D11. A read-egress view

**The largest known gap.** ADR-0021 says reading is exfiltration by construction; ADR-0022 builds
a 25-path confidentiality deny-list around it; ADR-0025 makes every read auditable and fail-closed.
All that machinery exists and **nothing in the Console surfaces it**. Nobody can answer "what has
this agent read this week, and from where?" — a question the architecture itself says is the
important one.

The data is already recorded (who, which tool, what, when — never the contents). It needs a screen.
No spec, no wireframe yet.

### D12. A capability preview — "what could this Account actually do?"

Given a role and the fleet's live Policy, render the reachable envelope before someone is handed
the keys. Turns an abstract role grant into a concrete blast radius. More speculative; raised, not
pursued.

---

## Known gaps with no spec yet

Job detail (grouped outcomes at 10k), the approval queue as a list, Accounts and API tokens, the
incident ladder as one surface, login.

Plus two dimensions that cut across every screen and are not drawn anywhere: a `viewer` sees a
**structurally smaller** Console rather than a greyed-out one, and `console_execution = off`
removes Run **entirely** rather than disabling it. ADR-0026's insight is that *absent* beats
*forbidden*; an implementation that ships a disabled composer has given the property away.
