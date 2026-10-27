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
3. **One decision per screen.** Decision surfaces (every privilege-granting act, and every
   change to the fleet such as a bulk tag edit) carry exactly one primary action with nothing
   competing.
4. **See the change before you make it.** The Console watches; it does not execute
   (ADR-0052). Its mutating acts (tags, Accounts, tokens, Enrollment Tokens) show what they will
   change before they change it, then confirm identity where the act needs it. The mutating
   path is deliberately slower than the reading path.
5. **The customer's taxonomy is the organising axis.** Their label values (`prod`, `payments`,
   `web`) are the headline structure. Relay's own bookkeeping is "group by nothing".
6. **Live but stable.** Counters and lists may update live. Anything a human is reading in order
   to decide — a rendered Plan, a confirm step — is pinned and never reflows. New
   events queue behind an explicit click rather than pushing in.
7. **No settings pages in the MVP.** The configuration file is the one source of Relay
   configuration (blast caps, listeners, gate rules). The Console shows it only as *effects in
   context*, a cap beside a fan-out count, never as an inventory of editable values. The
   security floor never becomes an editable value (invariant #11). Settings in the Console are
   later work: roadmap: relay/settings-in-the-console.

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

The data exists — `disk.usage`, `proc.list`, `net.listening`, `service.status` and `log.tail`
are read-class Operations — but it is **pulled, not collected**: a read is a Job with a Plan, a
blast cap and an audit record, and its output is not retained (ADR-0025). There is no series to
chart.

## Label namespaces — four, visually distinct

| Namespace | Set by | Immutable to | Targetable | Security lane |
|---|---|---|---|---|
| `node:` | the machine, via config management | the Relay | yes | no |
| `tag:` | a human Account at `operator` or above: Node detail, bulk from the Fleet view, the Control API (ADR-0050) | the Node | yes | no |
| `relay:` | the Relay, only as the side effect of a Relay action (`relay:node-id` at enrollment) | the Node | yes | **yes — only this** |
| `state:` | **derived by the Relay; nobody sets it** | everyone | yes | no |

`state:` is settled in `99-open-decisions.md` D1. Its vocabulary is **closed** and defined in the
contract.

**Every `state:` label is Node-local and objective** — computable from one Node's record alone. A
fleet-relative label ("fingerprint behind the fleet's mode") inverts its meaning mid-rollout and
smuggles desired-state past invariant #9.

Boolean markers: `state:offline`, `state:outdated`, `state:template-unloadable`,
`state:cert-expiring`.
Key=value facts: `state:daemon-version=`, `state:policy-fingerprint=`, `state:template-fingerprint=`.

**Drift is not a label.** It is an observation read off the fingerprint facet. "The ones that are
behind" is targeted as `state:policy-fingerprint=4b18…c02`.

`state:` terms are evaluated at Selector-resolution time, not materialised. Nobody can write one —
enforced structurally, not by permission check. `state:` is never a security-lane target
(invariant #7), because it is computed partly from what the Node itself reports.

## Two chip grammars that must not collide

Two independent chip systems appear side by side on Job detail and in Activity. They must occupy
**different visual channels**:

- **Trust lane owns fill versus outline.** A solid chip is an identity the Relay authenticated. A
  dashed chip is caller-asserted and unchecked. They must never read as equally authoritative — a
  jailbroken AI-agent can assert anything, but it cannot forge the filled one.
- **Namespace owns hue and the mono prefix.** `node:` and `tag:` are quiet and subtly
  differentiated; `relay:` is filled, distinct in hue, with its mono prefix; `state:` carries the
  tint of its severity behind its mono prefix. No chip carries a lock or other icon, fenced ones
  included (D25).

**Self-reported names** (D22, widening D20). Wherever a Node is named — a Fleet row, the Node
detail heading, Compare's column headings, a pin chip — its self-reported hostname is the
**primary label**, and the verified Node ID is drawn **secondary** beside or beneath it: smaller,
mono, muted, and always in full. The hostname takes the trust lane's outline treatment (a dashed
underline, never a fill or a trust chip), and the word "self-reported" is visible where it is
read: the heading, the Fleet table's Node column header (below 600px, the Node cell's own label),
Compare's column headings, and every row's accessible name. Because the verified ID is always
beside it, two Nodes claiming one hostname stay distinguishable. Only RFC 1123 hostname characters
qualify; anything else, a value shaped like a Node ID (`node-` then only hex), or nothing, falls
back to the Node ID as the primary label, not repeated beside itself. Selectors, links, pins and
`?account=` always **use** verified IDs; only the display order changes.

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

**Green is narrow on purpose.** A 10,000-cell field of saturated green would drown the few amber
cells (rule 2). It is used anyway because the liveness dot and the `success` chip are green, and a
wall that drew `normal` grey beside a green dot for the same Node contradicted itself. **Green
never means "healthy"** — Relay knows only whether a machine answered (the four questions). It
means reachable, or it worked; nothing else may take it.

**Interactive is the Relay mark's teal** (`#0a8276` light, `#4fb3a8` dark). Every text and fill
pairing it takes must clear 4.5:1 in both themes, so light link text uses a darker step and the
dark primary button carries dark text. It stays distinct from green by role and shape: green is a
state fill (liveness dot, `success` chip, wall cells); the accent is text, outlines, buttons and
the one live dot, which sits on a screen with no liveness dot. `TestConsole_AccentPairsClearAA`
enforces the contrast rule.

**Red marks failure and the destructive button** (D24). Beyond the `failure` and `timeout`
outcomes, red marks the button of an act that revokes, disables or lowers authority — only the
button, never a row, a chip or a deny — because an act that cannot be undone must look it. A deny
is still slate (rule 1), and a failed Task is the only *outcome* drawn red.

### Luminance is a second channel, not decoration

Hue carries the meaning; **luminance carries the separation**. The pixel wall's four buckets must
sit in four distinct luminance bands: a green `normal` 1.09:1 from amber `attention` differs almost
only on the red-green axis, which a deuteranope or protanope lacks.

Any new categorical colour must clear **3:1 against its surface** (WCAG 1.4.11) and **1.2:1
against every sibling under simulated deuteranopia and protanopia**.
`TestFleet_WallBucketsSurviveColourBlindness` enforces both. The weakest pair is grey against
indigo in the dark theme, at 1.22:1; closing it needs a non-colour channel (a border, or a distinct
cell shape for `fenced`) and is open.

Everything else is a near-white or near-black neutral. Two deviations from
`console-wireframe-brief.md` are recorded in `99-open-decisions.md`.

## Outcome vocabulary — all eight

From `proto/relay/v1/relay.proto`. Three are different kinds of "it did not run" and must not be
collapsed.

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

**Plan renderer** (Job detail). Fan-out summary with the cap arithmetic visible,
risk-class badge, grouped per-Node verdicts with expansion, and the plan hash in mono — the hash
is what an approval commits to. Pinned once rendered.

**Segmented outcome bar** (Job detail, Activity). Minority segments carry a **floor
width**: at 10,000 Nodes, 14 denies are 0.14% and would vanish, and they are why anyone is looking.

**The deny block** (Job detail, Activity). The rule verbatim, in mono, with file and
line, plus a link to the Node's effective Policy. An
operator gets from *denied* to *I know which file to change* without leaving the Console — and the
Console is visibly unable to change it for them. The footer that says so is the capability layer's
shared refusal text (the same bytes MCP and the Control API return in `refusal_explanation`),
never re-authored per screen.

**Verified / asserted chips** (everywhere). See the trust lane above.

**Kind label** (Job detail, Activity, Accounts). The word `human` or `machine`, set immediately
after a trust chip, never inside it. **It is not a chip**: no pill, border or fill — small
upper-case lettering with wide tracking in the secondary text colour, so it cannot be read as a
verified or asserted identity. Nothing about it is encoded in colour, and `human` and `machine`
share one treatment on every screen and in both themes. It qualifies the verified lane only:
**where a kind label is drawn, it is drawn only beside a verified (filled) chip**, never beside an
asserted `on_behalf_of`. It is not a trust signal: `machine` beside a filled chip is still an
identity the Relay authenticated.

**Where a kind label is drawn beside the actor of a record, it is read from that record as it was
written, and never looked up from the Account registry's current kind.** Where the record carries
no kind, no label is drawn and nothing is inferred. A registry read would let an Account converted
later relabel its own history ([04](04-activity.md), "Kind is never read from the registry"). The
Accounts screen ([15](15-accounts-and-tokens.md)) describes Accounts as they are now, so it reads
the registry's current kind, in the same treatment.

**Label chips** (everywhere). Four namespaces, per the table above.

**Policy fingerprint** (Fleet, Node detail, Compare; D23). The full hash, in mono, is always drawn.
Beside it sits a **Policy alias** — a name a human `admin` gave that fingerprint
(`docs/specs/query.md`), drawn to a human Account only — or, where none is set or the viewer is a
machine Account (which is drawn no alias name), a neutral **per-render letter** (A, B, C…) in order
of first appearance on the page, so "the Nodes on B" can be said aloud. A letter is not stored, not
stable across pages, carries no colour, and never ranks fingerprints ("majority", "outlier",
"normal"): the fleet's most common Policy is not its desired one (invariant 9, D1). An alias is
display only — never a Selector term, a filter value or an input to anything; filters and links
carry the hash — and is never shown without the full fingerprint, so a misleading name cannot hide
which Policy it is. On the Fleet view's Policy fingerprint facet and Node detail's Fingerprints
panel, a human `admin` sees an **Edit alias** control beside the fingerprint; the headline, the
deviation table and Compare carry none, and for every other role, and for a machine Account at any
role, it is absent. A reported value that is not a well-formed fingerprint is drawn short, as
before, and carries neither a name nor a control.

**Step-up modal** (every privilege-granting act). A session proves a human
authorised the *session*; step-up proves a human intended *this action*. It carries a credential
no agent session holds.

**Control-plane banner** (every screen, whenever a condition holds). Amber, in a slot above
content. It is the Console's only surface for conditions about **the control plane itself**;
everything else answers the four questions, which are about machines.

Three conditions, in descending urgency:

| Condition | Says |
|---|---|
| **Freeze engaged** | all new Task dispatch halted; in-flight Tasks keep running and Preflights still resolve; who engaged it and when |
| **Relay certificate near expiry** | automatic rotation has failed; the whole fleet fail-closes when it lapses |
| **CA near expiry** | the trust root every Node pins is running out; there is no rotation path today (D14) |

Freeze states what is *still true* on purpose: an emergency stop that looks like a total outage
gets released in a panic.

The two certificate conditions fire only when automation has already failed, so they are rare and
mean something. They are operational alarms, not configuration; nothing here is editable
(invariant #11). Once the Relay's leaf actually lapses the Console is unreachable too, so the
banner is a warning ahead of the event and can never be the only alarm.

### Identifiers render verbatim

Node IDs, token IDs, fingerprints, label keys and values, Account and token names and Operation
names are case-sensitive and never case-transformed. An upper-cased eyebrow, caption, heading or
table header resets case on the identifier (`<code>`, or the font-neutral `.ident` wrapper inside
prose). In a table or feed a long identifier scrolls with its container and is never broken; in a
card it may soft-wrap, because a card's value is read, not compared across columns.

## Standing notes and situational messages

**Show, don't tell** (D34). The Console carries meaning in its data, chips, controls and tooltips;
prose is the exception. Screens carry two kinds of prose, told apart by one rule:

- A note rendered **unconditionally on every view of the screen** — what the screen cannot show
  yet, how it pages, why a filter it was asked for is absent, a property the product always has —
  is a **standing note**.
- A note rendered **because of this request, this caller or this record's state** — a part of the
  URL that could not be read, a read that failed, "you already signed this", "your role cannot
  decide this" — is a **situational message**.

**A standing note is deleted unless the screen would be wrong without it.** "Wrong" means the
screen would state or imply something untrue — not that it would leave a true property unsaid.
Before a standing note survives, try to carry its meaning another way: in the data itself, a chip,
a control's label, or a tooltip (`title`) on the thing it qualifies. A property the product always
has — that the Relay never writes a Node's Policy, that every Console read is audited, how a page
is sized — belongs in the docs and in what is said about the product, not on the screen. A
standing note that does survive is one plain sentence of at most ~15 words beside what it
qualifies.

**No screen carries an "About this screen" disclosure** (D31): a closed box of caveats is read by
nobody and makes every screen look unfinished. Deleting a note is the answer, never collapsing it.

**Situational messages stay visible.** They are never collapsed, hidden or moved into a tooltip;
the operator needs them for the thing in front of them — "Part of this URL could not be read", a
read that failed, a refusal. **When a note's class is in doubt, it is situational and stays
visible.** A note that qualifies a claim the screen visibly makes ("every figure is exact", "this
is the feed") is situational too, because hiding it makes the claim stronger than the truth.

**Visible does not mean boxed.** A visible note is one plain sentence drawn as part of the control
or figure it qualifies, in the quiet note style. The dashed `gap` box is for a message about this
request, caller or record that the operator must stop and read, never for a standing note.

## Refreshing a screen

A screen listing things that arrive on their own — calls, Jobs, Nodes and their state — may offer
a **Refresh** control.

- **Where a screen offers a Refresh control, it reloads the page with the current query
  preserved.** It is a plain link to the same screen; it never splices rows into the page someone
  is reading (rule 6).
- **A Refresh makes exactly the reads a page load makes**, and those reads are audited
  (`docs/specs/audit-and-read-lane.md`). The control carries no sentence saying so (D34): that a
  Console read is audited is a property of every read, and it lives in the docs. Nothing on a
  screen claims a record the trail does not hold.
- **A Refresh is a deliberate act by the operator.** The Console never reloads a screen on a
  timer: [README](README.md) records the owner decision "No scheduled or repeated reads. Every read
  is a deliberate, audited act."

### How old a page is

A server-rendered page is a snapshot, so a screen says how old it is (D30). Where a screen states
when it was rendered, it states it **relatively** — "rendered 40s ago" — inside a `<time>` element
whose `datetime` carries the absolute UTC instant and whose `title` shows it. The server computes
the text at render. A script from the Console's own origin (`11-console-shell.md`, CSP) may advance
it while the page is open; it reads no data, makes no request and never reloads, and with scripts
off the page still reads correctly as at render. An old page says so **in words and weight** —
"rendered 12 min ago, Refresh to re-read", heavier — never in amber: an old page is the operator's
to refresh, not an alarm.

## Form controls — one treatment

Every text input, password input and select takes **one treatment**, the one the sign-in page and
filter bar carry: canvas background, a subtle 1px border, the control radius, the surrounding body
font, and the one focus ring (2px, the interactive colour). Its label is always visible — small
upper-case muted lettering above or beside the control — and never replaced by a placeholder.
Nothing suppresses a focus ring or shrinks a control below its target size. There is no second
input style; a form that renders browser defaults is a defect.

A label and its control are **one unit** in a single wrapper, label above control, so a wrapping
filter bar never leaves a label beside a different field.

Buttons carry **the weight of what they do to authority**:

| The act | Weight | Treatment |
|---|---|---|
| **Grants** authority — create an Account, raise a role, re-enable an Account, mint a credential | primary | filled in the interactive colour, and always beside the password field it spends |
| **Destroys or reduces** authority — revoke a credential, disable an Account, lower a role, revoke a Node, and any later revoke or disable | danger | outlined in the muted red: red border and red text, no fill — and it asks a named confirmation first |
| Stops work in flight — cancel | quiet | outlined, no fill, primary text colour |
| Reads or navigates — apply a filter, sign in | primary | as today |

Granting and destroying are told apart by **fill against outline** — a channel that survives
greyscale and every colour-vision deficiency — by hue, and by the password field only a granting
form carries (D24). A form that can both grant and reduce (setting a role; spec 15 splits it into
Raise and Lower) takes the granting weight, because it carries the password field. Where two
answers to one question must not be weighted, both take one neutral treatment.

**A destructive act asks a named confirmation.** Its button performs nothing: it opens a
server-rendered confirmation page, reached by GET, that names the target and consequence in one
sentence — "Revoke token `dev-fleet-approver`? Anything using it fails immediately; this cannot be
undone." — and holds the one POST form, with its CSRF token, beside a plain link back. It is a
page, not a `confirm()` dialog or a script, so it works with scripts off and under the strict CSP.
It is a presentation step, not a control: the capability layer decides the act exactly as without
it, and no act gains or loses step-up (spec 15; revocation still takes no password, because an
emergency brake that costs one is routed around).

## The incident ladder

Two rungs, in ascending blast radius. Every screen that offers one makes its position legible.
Quarantine, the rung that once sat below them, is cut from the MVP
(roadmap: relay/quarantine), and so is the Incident screen that gathered the rungs.

| Rung | Fences | Who | Reversible |
|---|---|---|---|
| Revoke a Node | one Node | `admin` + step-up | no |
| Freeze | the whole fleet | `operator`+ to engage, `admin` + reason to lift | yes |

Cancel is not on the ladder — it stops one in-flight Task and stops nothing future. Every rung
leaves in-flight Tasks running; Cancel is the only instrument for those.

There is no actor-scoped rung. Account suspension (ADR-0035) is **deferred, not adopted** (#443);
stopping one actor is revoking its API Tokens (spec 15) or Freeze. Freeze engage is
**human-principal only** — a machine Account, whatever its role, cannot pull the cord.

## Navigation

Five destinations in two groups. The grouping makes the model legible and the absence of a
settings section, and of any execution surface, visible.

```
Observe      Fleet · Activity
Administer   Add Nodes · Accounts · Access
```

There is no `Run` destination: the Console watches and does not execute (ADR-0052). There is no
`Policy` destination: the Policy author is cut (roadmap: relay/policy-catalog-and-live-reload),
and Policy aliases are edited where fingerprints are shown, on the Fleet view and Node detail.
There is no `Incident` destination (roadmap: relay/quarantine).

There is no `Approvals` destination: the Console has no approval surface (ADR-0044, D21). A
parked request is answered in-band through the requesting client, or on the Control API.

There is no `Jobs` destination (D6): Activity renders Job rows and filters to them. **Job detail is
its own page**, reached from any dispatch row in Activity and from a Node's recent Tasks. There is
no Agents destination either: it is folded into Activity ([04](04-activity.md), D17).

Role changes the nav **structurally**. A `viewer` sees a smaller Console: what it may not use
is absent, not disabled. *Absent* beats *forbidden* (ADR-0026).

## Narrow width

At 800px and below the shell stacks: the nav sits above the content and, with the signed-in block,
folds behind a **Menu** control (a label tied to a hidden checkbox — no script; Space toggles it).
Below 600px the Fleet deviation table and the Accounts table reflow to cards, each cell carrying its
column name, and Compare stacks its Nodes, each value labelled by the Node's name. No page scrolls
sideways; a wide table scrolls inside its own container.

## Technical frame

Server-rendered Go + HTMX, internal-only, SSE for liveness. No SPA, no client build pipeline.
Strict CSP (no inline script), CSRF tokens on every mutating route, SameSite session cookies
(ADR-0009). Per ADR-0026 these are controls on a fleet-RCE path, not hygiene, and the review bar
is high accordingly.

The Console is a **thin adapter over the one capability layer**. It renders and requests; it never
decides. The `no_dispatch` structural guard extends to the Console package: a Console file that
holds any concrete capability service (`*capability.Execution`, `Approvals`, `ReadLane`,
`AccountAdmin`, `Control`, `Recorder` — or the retired `capability.Service`), calls any of their
constructors (or the retired `capability.New`), or reaches capability's internal dispatch
must fail to compile the test suite.
