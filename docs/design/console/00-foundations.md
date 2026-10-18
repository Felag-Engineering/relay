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
3. **One decision per screen.** Decision surfaces (apply, and every privilege-granting act) carry
   exactly one primary action with nothing competing.
4. **Preflight before apply, everywhere.** Compose → see the truth → confirm identity → run.
   The mutating path is deliberately slower than the reading path.
5. **The customer's taxonomy is the organising axis.** Their label values (`prod`, `payments`,
   `web`) are the headline structure. Relay's own bookkeeping is "group by nothing".
6. **Live but stable.** Counters and lists may update live. Anything a human is reading in order
   to decide — a rendered Preflight, a confirm step — is pinned and never reflows. New
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

The Console carries two independent chip systems and they appear within 200px of each other on Job
detail and in Activity. They must occupy **different visual channels**:

- **Trust lane owns fill versus outline.** A solid chip is an identity the Relay authenticated. A
  dashed chip is caller-asserted and nothing checked it. These must never read as equally
  authoritative — a jailbroken agent can assert anything it likes, but it cannot forge the filled
  one.
- **Namespace owns hue and the mono prefix.** `node:` and `tag:` are quiet and subtly
  differentiated; `relay:` is filled, distinct in hue, and carries its mono prefix, with no lock or
  other icon; `state:` carries the tint of its severity behind its mono prefix. A fenced chip
  carries no icon either. (Owner decision, 2026-10-18, D24: the lock this line once required was
  removed from the code on 2026-08-27, and the owner dropped the idea rather than restore it.)

**Self-reported names.** Wherever a Node is shown to a human — a Fleet row, the Node detail
heading, Compare's column headings, a pin chip, and any other place a Node is named — its
self-reported hostname is the **primary label**, and the verified Node ID is drawn **secondary**
beside or beneath it: smaller, in mono, in the muted text colour, and always in full, never
truncated. The hostname takes the trust lane's outline treatment (a dashed underline, never a
fill, never a trust chip), and the word "self-reported" is visible where it is read: the heading
itself, the Fleet table's Node column header (below 600px, where the header is hidden, the Node
cell's own label), Compare's column headings, and every row's accessible name. Because the
verified identifier is always drawn beside it, two Nodes claiming one hostname stay
distinguishable. Only RFC 1123 hostname characters qualify; anything else, a value shaped like a
Node ID (`node-` then only hex), or nothing, falls back to the Node ID as the primary label, which
is then not repeated beside itself. Selectors, links, pins and `?account=` always **use** verified
IDs; only the display order changes. Owner decision, 2026-10-18 (D21), which widened D20
(2026-10-01, #835): D20 made the hostname primary on Fleet rows and the Node detail heading only,
and Compare's column headings and the pin chips led with the verified Node ID.

## Colour budget — the entire allowance

| Colour | Means | Used on |
|---|---|---|
| Amber | needs attention now | Freeze banner, offline, outdated, over-cap notes |
| Indigo | the security lane | `relay:` labels and the acts that set them |
| Slate | a Policy decision was made | denies, and nothing else |
| Grey | drift and inertness | `state:template-unloadable`, fingerprint distributions in facets |
| Green | reachable, and it worked | liveness dot, `success` outcome, the pixel wall's `normal` bucket |
| Teal (the Relay brand teal) | interactive | links, primary buttons, focus rings, the live indicator — never semantic |
| Muted red | failure and timeout, and destructive acts | the `failure` and `timeout` outcomes; the buttons of acts that revoke, disable or lower authority ("Form controls" below) — nothing else |

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

**Interactive is the brand teal, by owner decision on 2026-10-01.** This table
said Blue while the stylesheet drew Gleipnir's terracotta hearth, which sat beside
the attention amber and failed AA: white on the dark primary button at 2.63:1,
white on the light primary button at 3.78:1, light link text on the surface at
3.56:1. The accent is now the Relay mark's teal (`#0a8276` light, `#4fb3a8` dark),
the one deliberate departure from the Gleipnir palette. Every text and fill
pairing it takes must clear 4.5:1 in both themes, so light link text uses a
darker step of the teal and the dark primary button carries dark text. It stays
distinct from green by role and shape rather than by colour: green is a state
fill (the liveness dot, the `success` chip, the wall's cells), while the accent
is text, outlines, buttons and the one live dot, which sits on a screen with no
liveness dot. `TestConsole_AccentPairsClearAA` enforces the contrast rule.

**Red was widened on 2026-10-18 (owner decision, D23).** It had meant failure and timeout and
nothing else, and the acts that reduce authority were drawn quiet so that an emergency brake would
not look like an alarm. In use, a Revoke that looked like every other outlined button was the
problem: an act that cannot be undone did not look it. Red now also marks the button of an act
that revokes, disables or lowers authority, and only the button — never a row, a chip or a deny.
A deny is still slate (rule 1), and a failed Task is still the only *outcome* drawn red.

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

**Policy fingerprint** (Fleet, Node detail, Compare). The full fingerprint hash, in mono, is always
drawn; nothing replaces it. Beside it sits a **Policy alias** — a human-readable name a human
`admin` gave that fingerprint (`docs/specs/query.md`) — or, where none is set, a neutral
**per-render letter** (A, B, C…) assigned in order of first appearance on that page, so that "the
Nodes on B" can be said aloud. A letter is not stored, is not stable across pages, carries no colour,
and is never called "majority", "outlier", "normal" or anything else that ranks one fingerprint
against another: the fleet's most common Policy is not its desired one (invariant 9, D1). An alias
is display only. It is never a Selector term, a filter value or an input to anything — the
`state:policy-fingerprint=` filter and every link that targets a fingerprint carry the hash — and
it is never shown without the full fingerprint, so a misleading name cannot hide which Policy it is. Where an
`admin` sees a fingerprint, an **Edit alias** control sits beside it; it is absent for every other
role (owner decision, 2026-10-18, D22).

**Step-up modal** (apply, every privilege-granting act). A session proves a human
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

### Identifiers render verbatim

Node ids, token ids, fingerprints, label keys and values, Account and token names and Operation
names are case-sensitive and are never case-transformed, wherever they sit. An upper-cased eyebrow,
caption, heading or table header resets case on the identifier (`<code>`, or the font-neutral
`.ident` wrapper inside prose); the identifier never gives way. In a table or feed a long
identifier scrolls with its container and is never broken; in a card it may soft-wrap, because a
card's value is read rather than compared column against column.

## Standing notes and situational messages

Screens carry prose that says what they cannot do. Two kinds, told apart by one rule:

- A note rendered **unconditionally on every view of the screen** — what the screen cannot show
  yet, how it pages, why a filter it was asked for is absent — is a **standing note**.
- A note rendered **because of this request, this caller or this record's state** — a part of the
  URL that could not be read, a read that failed, "you already signed this", "your role cannot
  decide this" — is a **situational message**.

**No screen carries an "About this screen" disclosure** (owner decision, 2026-10-18, D30). It
replaced a rule that gathered every standing note into one closed disclosure at the foot of the
screen; in use, a closed box of caveats was read by nobody and made every screen look unfinished.
A standing note is therefore either **visible**, as one sentence of at most ~15 words drawn beside
what it qualifies, or **deleted**, which it may be only when its substance is already in the docs
or is implied by the data it sits next to. The docs pointer the disclosure carried goes with it.
Situational messages are never collapsed or hidden; they render where they always have, because
the operator needs them for the thing in front of them. **When a note's class is in doubt, it is
situational and stays visible.** A note that states a property the Console must be visibly bound by
is never collapsed. One is named: Node detail's "there is no path from this screen to this Node's
Policy" (invariant 2). (Read egress's ADR-0025 statement was the second; that screen was retired on
2026-10-01, see [17](17-read-egress.md).) A note that qualifies a claim the screen visibly makes —
"every figure is exact", "this is the feed" — is situational too, because hiding it makes the
visible claim stronger than the truth.

**Visible does not mean boxed.** A note that must stay visible is kept to one plain sentence and
drawn as part of the control or figure it qualifies, in the quiet note style, not as a dashed
block; its longer explanation lives in the docs. The dashed `gap` box is for a message about this
request, this caller or this record that the operator must stop and read.

## Refreshing a screen

A screen that lists things which arrive on their own — calls, Jobs, Nodes and their
state — may offer a **Refresh** control, so that what is new is one click away without the
browser's reload button.

- **Where a screen offers a Refresh control, it reloads the page with the current query
  preserved.** It is a plain link to the same screen; it never splices rows into the page someone
  is reading (rule 6).
- **A Refresh makes exactly the reads a page load makes**, and those reads are audited. Every
  screen that offers the control says whether a Refresh is recorded in one visible sentence beside
  it, and none claims a record the trail does not hold. (The built Approvals queue is the one
  exception, writing no read record, #779; it is retired with the Console's approval surface,
  ADR-0044.)
- **A Refresh is a deliberate act by the operator.** The Console never reloads a screen on a
  timer: [README](README.md) records the owner decision "No scheduled or repeated reads. Every read
  is a deliberate, audited act."

### How old a page is

A server-rendered page is a snapshot, so a screen that shows one says how old it is (owner
decision, 2026-10-18, D29). Where a screen states when it was rendered, it states it **relatively**
— "rendered 40s ago" — inside a `<time>` element whose `datetime` carries the absolute UTC instant
and whose `title` shows it, so the exact time is one hover or one screen-reader query away. The
relative text is computed by the server at render. An external script from the Console's own origin
(`11-console-shell.md`, CSP) may advance that text while the page is open; it reads no data, makes
no request and never reloads the page, and with scripts off the page still reads correctly as at
render. A page that has grown old says so **in words and weight** — "rendered 12 min ago, Refresh
to re-read" in a heavier weight — and never in amber: amber means a machine needs attention now,
and an old page is the operator's to refresh, not an alarm.

## Form controls — one treatment

Every text input, password input and select in the Console takes **one treatment**, the one the
sign-in page and the filter bar already carry: the canvas background, a subtle 1px border, the
control radius, the body font at the size around it, and the one focus ring (2px,
the interactive colour). Its label is always visible — small upper-case lettering in the muted text
colour, above or beside the control — and never replaced by a placeholder. Nothing suppresses a
focus ring, and no control shrinks below the target size it had. There is no second input style for
a screen that wants one; a form that renders browser defaults is a defect.

A label and its control are **one unit**: they sit in a single wrapper, label above control, so
wrapping a filter bar at any width moves them together and a label is never left beside a different
field.

Buttons carry **the weight of what they do to authority**:

| The act | Weight | Treatment |
|---|---|---|
| **Grants** authority — create an Account, raise a role, re-enable an Account, mint a credential | primary | filled in the interactive colour, and always beside the password field it spends |
| **Destroys or reduces** authority — revoke a credential, disable an Account, lower a role, revoke a Node, and any later revoke or disable | danger | outlined in the muted red: red border and red text, no fill — and it asks a named confirmation first |
| Stops work in flight — cancel | quiet | outlined, no fill, primary text colour |
| Reads or navigates — apply a filter, sign in | primary | as today |

Granting and destroying are told apart by **fill against outline** — a channel that survives
greyscale and every colour-vision deficiency — by hue, and by the password field that only a
granting form carries. Owner decision, 2026-10-18 (D23), which replaced the rule that a reducing
act is "never red" and never the most prominent control in its row: a revocation that looked like
any quiet button did not look like what it is, an act that takes effect at once and cannot be
undone. A form that can both grant and reduce — setting a role, which raises or lowers (the
Accounts screen splits it into Raise and Lower instead, spec 15) — takes the granting weight,
because it carries the password field and may spend it. Where two answers to one question must not
be weighted, both take one neutral treatment and this table does not
apply.

**A destructive act asks a named confirmation.** Pressing its button performs nothing: it opens a
server-rendered confirmation step, reached by GET, that names the target and the consequence in one
sentence — "Revoke token `dev-fleet-approver`? Anything using it fails immediately; this cannot be
undone." — and holds the one POST form, with its CSRF token, that performs the act, beside a plain
link back that performs nothing. It is a page, not a browser `confirm()` dialog and not a script:
it works with scripts off and under the strict CSP. The confirmation is a presentation step, not a
control — the capability layer decides the act exactly as it would without it, and no act gains or
loses step-up by having one (spec 15's matrix is unchanged; revocation still takes no password,
because an emergency brake that costs one is routed around).

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

Eight destinations in three groups. The grouping is load-bearing: it makes the model legible and
makes the absence of a settings section visible.

```
Observe      Fleet · Activity
Act          Run · Policy
Administer   Add Nodes · Accounts · Access · Incident
```

There is no `Approvals` destination: the Console has no approval surface (ADR-0044, D21). A
parked request is answered in-band through the requesting client, or on the Control API.

There is no `Jobs` destination (D6): Activity renders Job rows and filters to them. **Job detail is
still its own page**, reached from any dispatch row in Activity and from a Node's recent Tasks. The
Agents screen was folded into Activity on 2026-09-29 ([04](04-activity.md)), and Access
([20](20-access.md)) took the destination it left.

Role and configuration change the nav **structurally, not cosmetically**. A `viewer` sees a
smaller Console; with `console_execution = off`, Run is absent, not disabled. ADR-0026's insight
is that *absent* beats *forbidden* — do not ship a greyed-out execution surface.

## Narrow width

At 800px and below the shell stacks: the nav sits above the content and, with the signed-in block,
folds behind a **Menu** control (a label tied to a hidden checkbox, so it needs no script; a
keyboard user toggles it with Space). Below 600px the Fleet deviation table and the Accounts table
reflow to cards, each cell carrying its own column name, and Compare stacks its Nodes, each value
labelled by the Node's name (its hostname, with the Node ID beside it). No page scrolls sideways; a
wide table that remains scrolls inside its own container.

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
holds any concrete capability service (`*capability.Execution`, `Approvals`, `ReadLane`,
`AccountAdmin`, `Control`, `Recorder` — or the retired `capability.Service`), calls any of their
constructors (or the retired `capability.New`), or reaches capability's internal dispatch
must fail to compile the test suite.
