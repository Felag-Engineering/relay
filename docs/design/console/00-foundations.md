# 00 — Foundations

The design language and the shared components. Every screen spec assumes this document.
Artboard 11 ("Shared grammar") on the canvas renders all of it.

## The one sentence

The Console's job is to **make the security boundary legible**. A skeptical operator watches the
fleet, probes what is allowed, reads *why* something was denied, and only then trusts the system
enough to hand the same keys to an AI-agent. Every rule below serves that.

## Rules that override normal dashboard instincts

1. **A deny is not an error.** It is the product working correctly. Denies render calm and
   informative — the rule that fired, verbatim, with its file and line — never as a red failure.
   If a deny ever renders red, the product is arguing against itself.
2. **The UI computes what is interesting; the human reads only exceptions.** Fleets run
   100–10,000 Nodes. A list is a bug. Render the *mode* as one compressed line and spend the
   pixels on deviations.
3. **One decision per screen.** Decision surfaces (approval, apply) carry exactly one primary
   action with nothing competing.
4. **Plan before apply, everywhere.** Compose → see the truth → confirm identity → run. The
   mutating path is deliberately slower than the reading path.
5. **The customer's taxonomy is the organising axis.** Their label values (`prod`, `payments`,
   `web`) are the headline structure. Relay's own bookkeeping is "group by nothing".
6. **Live but stable.** Counters and lists may update live. Anything a human is reading in order
   to decide — an open approval card, a rendered Plan — is pinned and never reflows. New events
   queue behind an explicit click rather than pushing in.
7. **No settings pages, ever.** Relay configuration (blast caps, listeners, gate rules,
   `console_execution`) appears only as *effects in context* — a cap inside a plan line — never as
   an inventory of editable values. Invariant #11.

## The four questions

Relay can honestly answer exactly four questions about any Node:

1. **Can I reach it?** — connected now, last seen, for how long.
2. **Will it take work?** — daemon version against the dispatch minimum, template vocabulary,
   whether Freeze is engaged.
3. **What will it permit?** — Policy fingerprint, drift against the fleet's mode, and the
   effective Policy on demand.
4. **Who is it, and who vouched?** — certificate identity, enrollment provenance, labels.

**If a proposed field does not answer one of those four, it does not belong on a fleet surface.**
CPU, memory, load, latency and application health fail all four. This is not a monitoring product
and must not imitate one.

The data is not unavailable — `disk.usage`, `proc.list`, `net.listening`, `service.status` and
`log.tail` are read-class Operations. The distinction is **pulled, not collected**: a read is a
Job with a Plan, a blast cap and an audit record, and its output is not retained (ADR-0025). There
is no series to chart even if someone wanted one.

## Label namespaces — four, visually distinct

| Namespace | Set by | Immutable to | Targetable | Security lane |
|---|---|---|---|---|
| `node:` | the machine, via config management | the Relay | yes | no |
| `tag:` | operators, through the control plane | the Node | yes | no |
| `relay:` | the Relay (enrollment stamp, or `admin` + step-up) | the Node | yes | **yes — only this** |
| `state:` | **derived by the Relay; nobody sets it** | everyone | yes | no |

`state:` is new and **needs an ADR and a CONTEXT.md entry** — see `99-open-decisions.md`. Its
vocabulary must be **closed** and defined in the contract. Free-form state labels would become a
second `tag:` namespace with none of the guarantees, and Selectors written against them would
silently stop matching when a definition changed.

Closed vocabulary as drawn: `state:offline`, `state:version-gated`, `state:policy-drift`,
`state:template-drift`.

Security-lane Selectors (quarantine, remediation, secret distribution) target `relay:` and only
`relay:` — invariant #7, unchanged. `state:` is excluded because it is computed partly from what
the Node itself reports.

## Two chip grammars that must not collide

The Console carries two independent chip systems and they appear within 200px of each other on the
approval card. They must occupy **different visual channels**:

- **Trust lane owns fill versus outline.** A solid chip is an identity the Relay authenticated. A
  dashed chip is caller-asserted and nothing checked it. These must never read as equally
  authoritative — a jailbroken agent can assert anything it likes, but it cannot forge the filled
  one.
- **Namespace owns hue, glyph and the mono prefix.** `node:` and `tag:` are quiet and subtly
  differentiated; `relay:` is filled, distinct in hue, and carries a lock; `state:` carries the
  tint of its severity behind its mono prefix.

## Colour budget — the entire allowance

| Colour | Means | Used on |
|---|---|---|
| Amber | needs attention now | Freeze banner, offline, version-gated, over-cap notes |
| Indigo | the security lane | `relay:` labels and the acts that set them |
| Slate | a Policy decision was made | denies, and nothing else |
| Grey | drift | `state:policy-drift`, `state:template-drift` |
| Blue | interactive | links, primary buttons, the live indicator — never semantic |
| Muted red | failure and timeout | nothing else, ever |

Everything else is a near-white or near-black neutral. Two deviations from
`console-wireframe-brief.md` are recorded in `99-open-decisions.md`.

## Outcome vocabulary — all eight

From `proto/relay/v1/relay.proto`. The brief names six; there are eight, and three of them are
different kinds of "it did not run" that must not be collapsed.

| Outcome | Treatment | Why |
|---|---|---|
| `success` | quiet filled | it ran, it worked |
| `denied_by_policy` | **slate, filled** | a decision was made — the product working |
| `unsupported` | outlined, solid border | not in this Node's vocabulary; Policy was never asked |
| `unreachable` | outlined, **dashed** | offline at dispatch; the Task never left the Relay |
| `version_refused` | outlined, **dashed** | below the dispatch minimum; never sent |
| `cancelled` | quiet filled | killed in flight, honestly reported |
| `failure` | muted red | something ran and failed |
| `timeout` | muted red | ran past its limit |

Vocabulary is per-Node once templates exist (ADR-0021): `list_operations` / `describe_node` report
what a given Node actually has.

## Shared components

Build these once. They appear on three or more screens each.

**Plan renderer** (composer, approval object, Job detail). Fan-out summary with the cap arithmetic
visible, risk-class badge, grouped per-Node verdicts with expansion, and the plan hash in mono —
the hash is what an approval commits to. Pinned once rendered.

**Segmented outcome bar** (Job detail, composer, Activity). Minority segments carry a **floor
width**. At 10,000 Nodes, 14 denies are 0.14% and would vanish — and they are the entire reason
anyone is looking.

**The deny block** (composer, approval, Job detail, Policy fix). The showpiece. The rule verbatim,
in mono, with file and line, plus two links: the Node's effective Policy, and drafting the rule
that would allow it. An operator must get from *denied* to *I know exactly which file to change*
without leaving the Console — and the Console must be visibly unable to change it for them.

**Verified / asserted chips** (everywhere). See the trust lane above.

**Label chips** (everywhere). Four namespaces, per the table above.

**Step-up modal** (approval, apply, every privilege-granting act). A session proves a human
authorised the *session*; step-up proves a human intended *this action*. It carries a credential
no agent session holds, and it is the reason ADR-0026 could give a browser an execution surface at
all.

**Freeze banner** (every screen, whenever engaged). Amber, unmissable, in a slot above content. It
states what is still true — in-flight Tasks keep running, Plans still resolve — because an
emergency stop that looks like a total outage gets released in a panic.

## Navigation

Ten destinations in three groups. The grouping is load-bearing: it makes the model legible and
makes the absence of a settings section visible.

```
Observe      Fleet · Agents · Activity · Jobs
Act          Run · Policy · Approvals
Administer   Add Nodes · Accounts · Incident
```

Role and configuration change the nav **structurally, not cosmetically**. A `viewer` sees a
smaller Console; with `console_execution = off`, Run is absent, not disabled. ADR-0026's insight
is that *absent* beats *forbidden* — do not ship a greyed-out execution surface.

## Technical frame

Server-rendered Go + HTMX, internal-only, SSE for liveness. No SPA, no client build pipeline.
Strict CSP (no inline script), CSRF tokens on every mutating route, SameSite session cookies.
ADR-0009, unchanged — and per ADR-0026 these are now controls on a fleet-RCE path rather than
hygiene, so the review bar is correspondingly high.

The Console is a **thin adapter over the one capability layer**. It renders and requests; it never
decides. The `no_dispatch` structural guard extends to the Console package: a Console file that
holds a `*capability.Service`, calls `capability.New`, or reaches capability's internal dispatch
must fail to compile the test suite.
