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
4. **Preflight before apply, everywhere.** Compose → see the truth → confirm identity → run.
   The mutating path is deliberately slower than the reading path.
5. **The customer's taxonomy is the organising axis.** Their label values (`prod`, `payments`,
   `web`) are the headline structure. Relay's own bookkeeping is "group by nothing".
6. **Live but stable.** Counters and lists may update live. Anything a human is reading in order
   to decide — an open approval card, a rendered Preflight — is pinned and never reflows. New
   events queue behind an explicit click rather than pushing in.
7. **No settings pages, ever.** Relay configuration (blast caps, listeners, gate rules,
   `console_execution`) appears only as *effects in context* — a cap inside a preflight line —
   never as an inventory of editable values. Invariant #11.

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

`state:` is new and **needs an ADR and a GLOSSARY.md entry** — see `99-open-decisions.md` D1,
where its content is settled. Its vocabulary is **closed** and defined in the contract.

**Every `state:` label is Node-local and objective** — computable from one Node's record with no
reference to any other Node. A fleet-relative label (the first draft's "fingerprint behind the
fleet's mode") silently inverts its meaning mid-rollout and smuggles desired-state past invariant
#9.

Boolean markers: `state:offline`, `state:outdated`, `state:template-unloadable`,
`state:cert-expiring`.
Key=value facts: `state:daemon-version=`, `state:policy-fingerprint=`, `state:template-fingerprint=`.

**Drift is not a label.** It is an observation read off the fingerprint facet. "The ones that are
behind" is targeted as `state:policy-fingerprint=4b18…c02`.

`state:` terms are evaluated at Selector-resolution time, not materialised. Nobody can write one —
enforced structurally, not by permission check.

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
| Amber | needs attention now | Freeze banner, offline, outdated, over-cap notes |
| Indigo | the security lane | `relay:` labels and the acts that set them |
| Slate | a Policy decision was made | denies, and nothing else |
| Grey | drift and inertness | `state:template-unloadable`, fingerprint distributions in facets |
| Green | reachable, and it worked | liveness dot, `success` outcome, the pixel wall's `normal` bucket |
| Blue | interactive | links, primary buttons, the live indicator — never semantic |
| Muted red | failure and timeout | nothing else, ever |

**Green was added on 2026-08-27 (owner decision).** It had been in the product
without being in this table — the liveness dot and the `success` outcome chip
have always been green — while the pixel wall drew `normal` as a neutral, on the
argument in rule 2 above: a 10,000-cell field of saturated green leaves the seven
amber cells competing with it instead of standing out. That argument is real and
is the reason this entry is narrow.

What overruled it is that the fleet view already taught the opposite two hundred
pixels lower down. The deviation table shows a green liveness dot for the very
Node the wall drew as a grey square, so the page contradicted itself, and a
reader who had learned green-means-reachable read the wall as broken rather than
as calm.

**Green never means "healthy" in general** — Relay does not know whether a
machine is healthy, only whether it answered (see "The four questions"). It means
reachable, or it worked. Nothing else may take it.

### Luminance is a second channel, not decoration

Hue carries the meaning; **luminance carries the separation**. The pixel wall's
four buckets sit in four distinct luminance bands, and that is a requirement
rather than a preference: when `normal` first became green it landed 1.09:1 from
`attention`'s amber, differing almost purely on the red-green axis — precisely
the axis a deuteranope or protanope does not have. "Everything is fine" and
"needs attention now" were one colour for roughly one man in twelve.

Any new categorical colour must clear **3:1 against the surface it sits on**
(WCAG 1.4.11 — a swatch that carries meaning is non-text content) and **1.2:1
against every sibling under simulated deuteranopia and protanopia**.
`TestFleet_WallBucketsSurviveColourBlindness` enforces both.

The weakest surviving pair is grey against indigo in the dark theme, at 1.22:1.
Four recognisable hues above a 3:1 floor cannot all be separated on luminance;
closing that one needs a non-colour channel — a border, or a distinct cell shape
for `fenced` — and is open.

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
the hash is what an approval commits to. In the composer it renders the Preflight verdict; on the
approval object and Job detail it renders the Plan an approval commits to. Pinned once rendered.

**Segmented outcome bar** (Job detail, composer, Activity). Minority segments carry a **floor
width**. At 10,000 Nodes, 14 denies are 0.14% and would vanish — and they are the entire reason
anyone is looking.

**The deny block** (composer, approval, Job detail, Policy fix). The showpiece. The rule verbatim,
in mono, with file and line, plus two links: the Node's effective Policy, and drafting the rule
that would allow it. An operator must get from *denied* to *I know exactly which file to change*
without leaving the Console — and the Console must be visibly unable to change it for them. The
footer that says so is the capability layer's shared refusal text — the same bytes MCP and the
Control API return in `refusal_explanation` — not Console copy, and it is never re-authored per
screen.

**Verified / asserted chips** (everywhere). See the trust lane above.

**Kind label** (Job detail, Activity, approval object, Accounts). The word `human` or `machine`,
set immediately after a trust chip and never inside it. **It is not a chip**: no pill, no border,
no fill — small upper-case lettering with wide tracking in the secondary text colour, so it cannot
be read as a verified (filled) or an asserted (dashed) identity beside either one. The word carries
the meaning and nothing about it is encoded in colour; `human` and `machine` share one treatment,
in the dark theme and the light theme alike, and there is one treatment for every screen that draws
one. It qualifies the verified lane only — the Account the Relay authenticated — and never an
asserted `on_behalf_of`: **where a kind label is drawn, it is drawn only beside a verified (filled)
chip**, and an actor rendered as a dashed chip gets no kind label whatever its record says. It is
not a trust signal: `machine` beside a filled chip is still an
identity the Relay authenticated.

**Where a kind label is drawn beside the actor of a record, it is read from that record as it was
written, and never looked up from the Account registry's current kind.** Where the record carries
no kind, no label is drawn and nothing is inferred in its place. This is the owner decision of
2026-09-08 (#540) recorded in [04](04-activity.md) under "Kind is never read from the registry": a registry read reports the Account's kind today, so an Account converted later would
retroactively relabel its own history. The Accounts screen ([15](15-accounts-and-tokens.md)) is
the one surface that describes Accounts as they are now; it reads the registry's current kind
because that is its subject, and draws it in the same treatment because it is the same fact.

**Label chips** (everywhere). Four namespaces, per the table above.

**Step-up modal** (approval, apply, every privilege-granting act). A session proves a human
authorised the *session*; step-up proves a human intended *this action*. It carries a credential
no agent session holds, and it is the reason ADR-0026 could give a browser an execution surface at
all.

**Control-plane banner** (every screen, whenever a condition holds). Amber, unmissable, in a slot
above content. It is the Console's only surface for conditions about **the control plane itself**
rather than about Nodes — everything else on every screen answers the four questions, which are
questions about machines.

Three conditions, in descending urgency:

| Condition | Says |
|---|---|
| **Freeze engaged** | all new Task dispatch halted; in-flight Tasks keep running and Preflights still resolve; who engaged it and when |
| **Relay certificate near expiry** | automatic rotation has failed; the whole fleet fail-closes when it lapses |
| **CA near expiry** | the trust root every Node pins is running out; there is no rotation path today (D14) |

Freeze states what is *still true* on purpose: an emergency stop that looks like a total outage
gets released in a panic.

The two certificate conditions fire only when automation has already failed, so they are rare and
mean something. They are operational alarms, not configuration — invariant #11 is untouched, and
nothing here is editable. Note the limit honestly: both listeners share one certificate
(ADR-0031), so once the Relay's leaf actually lapses the Console is unreachable too. The banner is
a warning ahead of the event and can never be the only alarm.

## Standing notes and situational messages

Screens carry prose that says what they cannot do. Two kinds, told apart by one rule:

- A note rendered **unconditionally on every view of the screen** — what the screen cannot show
  yet, how it pages, why a filter it was asked for is absent — is a **standing note**.
- A note rendered **because of this request, this caller or this record's state** — a part of the
  URL that could not be read, a read that failed, "you already signed this", "your role cannot
  decide this" — is a **situational message**.

Where a screen has standing notes, they are drawn together in **one disclosure at the foot of the
screen, closed by default**, labelled in plain words ("About this screen"), and built from a native
`<details>`/`<summary>` so it needs no script under the strict CSP. A standing note is moved there,
never deleted: it keeps its substance and stays one click away, and only words that pointed at its
old position ("below", "above") change with it. Situational messages are never
collapsed or hidden; they render where they always have, because the operator needs them for the
thing in front of them. **When a note's class is in doubt, it is situational and stays visible.**
A note that states a property the Console must be visibly bound by is never collapsed. One is
named: Node detail's "there is no path from this screen to this Node's Policy" (invariant 2).
(Read egress's ADR-0025 statement was the second; that screen was retired on 2026-10-01, see
[17](17-read-egress.md).) A note that qualifies a claim the screen
visibly makes — "every figure is exact", "this is the feed" — is situational too, because hiding
it makes the visible claim stronger than the truth.

**Visible does not mean boxed.** A note that must stay visible is kept to one plain sentence and
drawn as part of the control or figure it qualifies, in the quiet note style, not as a dashed
block; its longer explanation may stay in the disclosure. The dashed `gap` box is for a message
about this request, this caller or this record that the operator must stop and read.

## Refreshing a screen

A screen that lists things which arrive on their own — calls, approval requests, Jobs — may offer
a **Refresh** control, so that what is new is one click away without the browser's reload button.

- **Where a screen offers a Refresh control, it reloads the page with the current query
  preserved.** It is a plain link to the same screen; it never splices rows into the page someone
  is reading (rule 6).
- **A Refresh makes exactly the reads a page load makes.** Of the screens that offer a Refresh
  control, every one's reads are audited except the Approvals queue's, which write no read record:
  a known gap, tracked in #779, and not a rule for any other screen to follow. The queue says so
  in one plain sentence beside its Refresh control; every screen that offers the control says in
  its "About this screen" disclosure whether a Refresh is recorded, and none claims a record the
  trail does not hold.
- **A Refresh is a deliberate act by the operator.** The Console never reloads a screen on a
  timer: [README](README.md) records the owner decision "No scheduled or repeated reads. Every read
  is a deliberate, audited act."

## Form controls — one treatment

Every text input, password input and select in the Console takes **one treatment**, the one the
sign-in page and the filter bar already carry: the canvas background, a subtle 1px border, the
control radius, the body font at the size around it, and the one focus ring (2px,
the interactive colour). Its label is always visible — small upper-case lettering in the muted text
colour, above or beside the control — and never replaced by a placeholder. Nothing suppresses a
focus ring, and no control shrinks below the target size it had. There is no second input style for
a screen that wants one; a form that renders browser defaults is a defect.

Buttons carry **the weight of what they do to authority**, not how dangerous they feel:

| The act | Weight | Treatment |
|---|---|---|
| **Grants** authority — create an Account, raise a role, re-enable an Account, mint a credential | primary | filled in the interactive colour, and always beside the password field it spends |
| **Reduces** authority — disable an Account, lower a role, revoke a credential, cancel | quiet | outlined, no fill, primary text colour |
| Reads or navigates — apply a filter, sign in | primary | as today |

The two weights are told apart by **fill against outline** — a channel that survives greyscale and
every colour-vision deficiency — and by the password field that only a granting form carries,
never by hue alone. A reducing act is **never red** (red is failure and timeout, and nothing else)
and never the most prominent control in its row: an emergency brake that looks like an alarm is
one people hesitate over, and one that outweighs the act beside it teaches the wrong reflex. A form
that can both grant and reduce — setting a role, which raises or lowers (the Accounts screen
splits it into Raise and Lower instead, spec 15) — takes the granting
weight, because it carries the password field and may spend it. Where two answers to one question
must not be weighted (Approve and Deny, spec 08), both take one neutral treatment and this table
does not apply.

## The incident ladder

Three rungs, in ascending order of blast radius. Every screen that offers one must make its
position on the ladder legible.

| Rung | Fences | Who | Reversible |
|---|---|---|---|
| `relay:quarantine` on a Node | one Node | `admin` + step-up | yes |
| Revoke a Node | one Node | `admin` + step-up | no |
| Freeze | the whole fleet | `operator`+ to engage, `admin` + reason to lift | yes |

Cancel is not on the ladder — it stops one in-flight Task and stops nothing future. Every rung
leaves in-flight Tasks running; Cancel is the only instrument for those.

There is no actor-scoped rung. Account suspension (ADR-0035) was drafted and **deferred, not
adopted** (#443); stopping one actor is revoking its API Tokens (spec 15) or Freeze. Freeze engage
is **human-principal only** — a machine Account, whatever its role, cannot pull the cord (#397).

## Navigation

Nine destinations in three groups. The grouping is load-bearing: it makes the model legible and
makes the absence of a settings section visible.

```
Observe      Fleet · Activity
Act          Run · Policy · Approvals
Administer   Add Nodes · Accounts · Access · Incident
```

There is no `Jobs` destination (D6): Activity renders Job rows and filters to them. **Job detail is
still its own page**, reached from any dispatch row in Activity and from a Node's recent Tasks. The
Agents screen was folded into Activity on 2026-09-29 ([04](04-activity.md)), and Access
([20](20-access.md)) took the destination it left.

Role and configuration change the nav **structurally, not cosmetically**. A `viewer` sees a
smaller Console; with `console_execution = off`, Run is absent, not disabled. ADR-0026's insight
is that *absent* beats *forbidden* — do not ship a greyed-out execution surface.

## Hard prerequisite: E2a

The Relay's server certificate is minted once at process start and never rotates
(`99-open-decisions.md` D13). Both listeners share one certificate (ADR-0031), so **the Console's
own TLS rides on it**: a Console shipped against a Relay with this defect breaks for every user
fourteen days after the process starts. Treat E2a as done-before-done for all Console work.

## Technical frame

Server-rendered Go + HTMX, internal-only, SSE for liveness. No SPA, no client build pipeline.
Strict CSP (no inline script), CSRF tokens on every mutating route, SameSite session cookies.
ADR-0009, unchanged — and per ADR-0026 these are now controls on a fleet-RCE path rather than
hygiene, so the review bar is correspondingly high.

The Console is a **thin adapter over the one capability layer**. It renders and requests; it never
decides. The `no_dispatch` structural guard extends to the Console package: a Console file that
holds a `*capability.Service`, calls `capability.New`, or reaches capability's internal dispatch
must fail to compile the test suite.
