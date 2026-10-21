# 99 — Open decisions

**Read this before writing Console code.** It records each decision the screen specs depend on:
what is settled, by whom, and what is still open. Something drawn in a wireframe is not decided
until it is recorded here or in an ADR.

Per AGENTS.md, an implementing agent has **no merge authority** and must **stop and flag a human
rather than guess on a hard call**. Every open item below is a hard call.

---

## Blocking — needs an ADR before the code lands

### D1. The `state:` Label namespace — **RESOLVED 2026-08-24 — drafted as [ADR-0034](../../adr/0034-state-labels-relay-derived-namespace.md)**

**What:** a fourth namespace of Relay-derived labels, targetable by Selectors, writable by nobody.

**Why it exists:** operational state is what fleet maintenance targets — "run this on the ones that
are behind". Labels target; Facts do not; daemon version and the fingerprints are *neither* (`Hello`
carries `daemon_version` and `Facts` as separate fields).

**ADR-0034 is merged**, with the GLOSSARY.md and invariant #7 amendments. Its Consequences carry
the review's additions: the `cert-expiring` window is 25% of `LeafValidity` remaining, `tag:`
parsing lands in the same Selector change, and the security-lane assertion lives on the `relay:`
write path (#430).

#### The governing rule: every `state:` label is Node-local and objective

Computable from one Node's registry record, with **no reference to any other Node**.

The first draft defined `state:policy-drift` as "fingerprint behind the fleet's mode". Roll a
Policy to 51% of the fleet and the mode flips, so the other 49% become "drifted" without anything
about them changing: a Selector targeting it would **silently invert its meaning mid-rollout**. It
also smuggles desired-state past invariant #9 — "behind" needs a notion of what the fleet *should*
run, and GLOSSARY.md defines fingerprints as an observation, not a target.

#### The closed vocabulary

Two shapes, both Node-local.

**Boolean markers**

| Label | True when |
|---|---|
| `state:offline` | not currently connected |
| `state:outdated` | daemon below the Relay's configured dispatch minimum (ADR-0014) |
| `state:template-unloadable` | the Node's template set failed to load; vocabulary empty, fail closed |
| `state:cert-expiring` | identity certificate within the configured warning window of `NotAfter` and not yet renewed (D4) |

**Key=value state facts**

| Label | Value |
|---|---|
| `state:daemon-version=` | the version reported in `Hello` |
| `state:policy-fingerprint=` | the fingerprint reported in `Hello` / `PolicySnapshot` |
| `state:template-fingerprint=` | the template-set fingerprint, or the literal `unloadable` |

**Drift is not a label.** It stays an observation — the facet rail's fingerprint distribution and a
count on the rollup card. "The ones that are behind" is `state:policy-fingerprint=4b18…c02`:
Node-local, objective, stable under rollout. Click the old fingerprint in the facet rail and the
filter fills in.

#### Resolution model

`state:` terms are **evaluated at Selector-resolution time** as predicates over registry data, not
materialised. Every label is Node-local, so this is cheap and always correct; materialising would
mean recomputing on every `Hello`, `PolicySnapshot`, disconnect and min-version change, and keeping
a copy that can go stale. The accepted cost is a second code path in Selector resolution beside
label matching.

#### Also settled

- The vocabulary is **closed** and lives in the contract. Free-form state labels would become a
  second `tag:` with none of the guarantees, and Selectors written against them would silently
  stop matching when a definition changed.
- `state:` is **never** a valid security-lane target (invariant #7): it is computed partly from
  what the Node itself reports, so a compromised Node can influence it.
- **No Account of any role can write one**, enforced structurally, not by permission check.
- `state:` labels appear in `list_nodes` output, so the AI-agent and the Control API target them
  identically to the Console. No Console-only concept.

**Rejected:** folding into `relay:` (mixes derived state into the security lane); extending
Selector grammar to comparisons like `daemon.version < 1.4.2` (a bigger change to the domain
language, and unnecessary once fingerprints are targetable); the `tag:` bridge (a snapshot that
goes stale).

### D2. Stopping one agent — **DEFERRED 2026-08-24 — [ADR-0035](../../adr/0035-account-suspension.md) drafted, then not adopted**

**Outcome: cut.** Suspension was plumbing for a control nothing yet needs, and review found the
draft could lock every admin out (an `operator` may suspend admins; lifting is an admin call; every
call from a suspended Account is refused). Disconnect had no object: MCP is stateless (ADR-0028),
so there is no connection to drop and no "agent session". Stopping one actor is **revoking its API
Tokens** or **Freeze**; the incident ladder stays at ADR-0020's three rungs. The design — an
Account-scoped, reversible brake that refuses every call, with Freeze's engage/lift asymmetry — and
the constraints any revival must meet are recorded in ADR-0035 and #443.

## Needs a ruling — smaller, but not an implementer's call

### D3. The word "outdated" — **RESOLVED 2026-08-24**

**Settled by the code.** `Outdated` is a live field on the MCP wire: `tools_execution.go` returns
it on every Preflight entry, and `mcp_plan_test.go` pins ADR-0014's meaning.

**`outdated` means: the Node's daemon is below the Relay's configured dispatch minimum.**
`ui-advisory.md`'s use of the word for Policy-fingerprint drift is wrong, and D1 removed that
concept from the UI anyway.

The Console uses **`state:outdated`**, matching the wire. `state:version-gated` would have given an
operator two words for one thing across MCP and the Console (GLOSSARY.md, *Avoid*). Renaming the
wire field was rejected: ADR-0014 requires additive-only evolution within `relay.v1`.

### D4. `state:cert-expiring` — **RESOLVED 2026-08-24: include it**

Node identity certificates carry `LeafValidity = 336 * time.Hour` (`relay/internal/ca/ca.go`). The
Relay issued each one, so it knows every Node's `NotAfter`; "expires within the warning window and
has not renewed" is computable from one Node's record — D1's Node-local rule.

**It is an alarm, not a to-do list.** Renewal is fully automatic: `rpc Renew` is cert-authenticated
over mTLS, the daemon runs `renew::run` as a spawned task, the Relay reissues for the **same
`node_id`** derived from the verified peer cert, and renewals are jittered. `state:cert-expiring`
fires only when **that automation has failed** on a specific Node, so it is rare and meaningful. It
is the only early warning: otherwise `state:offline` reports the Node after the two-week fuse has
burned down.

**Why 336 hours:** a stolen Node key self-expires in two weeks, whether or not anyone noticed and
revoked it. Automatic renewal makes the short lifetime free.

**Settled in review: 25% of `LeafValidity` remaining** (84h). The daemon renews at a jittered
50–75% of the lifetime (relay-transport `renew`), so under a quarter left means the whole renewal
window was missed; a threshold inside the jitter window would alarm on a healthy fleet. It is Relay
configuration (invariant #11), a fraction so it tracks any change to the lifetime.

### D5. Colour deviations from the brief — **RESOLVED 2026-08-24: both accepted**

1. **Amber is split from indigo.** Amber means *attention now* (Freeze, `state:offline`,
   `state:outdated`, `state:cert-expiring`, over-cap notes). Indigo means *the security lane*
   (`relay:` labels and the acts that set them). The brief reserved amber for Freeze and
   quarantine, then used it for the odd Node out in the pixel wall; splitting keeps quarantine bound
   to `relay:` rather than sharing a colour with "this machine is unreachable".
2. **One muted red exists**, on `failure` and `timeout`. A Task that ran and failed is not routine.
   Everything else that stops a Task is a boundary doing its job and stays neutral — above all
   `denied_by_policy`, which is slate. *Widened by D24:* the red also marks the **button** of an act
   that revokes, disables or lowers authority; it still marks no other outcome.

`console-wireframe-brief.md` rule 1 should be updated to match.

### D6. The `Jobs` nav destination — **RESOLVED 2026-08-24: dropped**

Activity already renders Job rows and filters to them, so a Jobs destination would be a duplicate
list. **Job detail remains its own page**, reached from any dispatch row in Activity and from a
Node's recent Tasks.

### D7. Policy as its own nav item — **RESOLVED 2026-08-24: keeps its slot**

Policy authoring is recurring work and the deny-to-fix loop is central to the trust story;
enrollment is mostly a one-off by comparison. Folding Policy under "Node setup" would bury the
screen operators return to.

### Resulting navigation — eight destinations, three groups

```
Observe      Fleet · Activity
Act          Run · Policy
Administer   Add Nodes · Accounts · Access · Incident
```

Approvals left with D21; `00-foundations.md` carries the current list.

### D15. CSP violation reporting — **DEFERRED (#460)**

Spec 11 calls a CSP violation a security event that should be reported. The Console ships the rest
of spec 11's CSP but no `report-to`/`Reporting-Endpoints` pair, deliberately: a reporting group
with no endpoint behind it looks like a working control while silently dropping every report.
Four reasons:

1. **A report sink is an unauthenticated POST.** The Reporting API delivers to whatever endpoint
   the header names with no credential attached, so the sink is attacker-reachable by
   construction. It needs a body cap, a rate limit and a redaction rule before it is safe to
   expose at all — none of which exists yet.
2. **It cannot live behind this file's own control.** The browser's Reporting API sends reports
   without this Console's CSRF token and, by default, without credentials, so routing reports
   through `Secure` would have it 403 every report it was supposed to receive. It needs a route
   outside both `Secure` and the authenticator — a THIRD hole in the control plane's auth
   wrapper, whose extent `Unauthenticated`'s own doc asserts is exactly two routes and no more.
3. **Where reports go is an open product decision, not an implementation detail.** If a CSP
   violation is a security event per spec 11, it belongs in the audit trail — under a `kind` that
   does not exist yet — against ADR-0025's posture that the Relay authors its own audit records
   rather than accepting one from an unauthenticated caller.
4. **It is on neither spec 11's acceptance list nor v0.6.0's.**

**What would close it:** a ruling on the sink (most likely a new audit `kind`, given (3)), plus a
bounded, rate-limited, unauthenticated route to receive it — its own change.

### D16. What the Console calls a Policy preflight — **RESOLVED 2026-09-20: "Preflight" (#575)**

**What:** ADR-0038 gave the word **Plan** to an approved route of execution and renamed the
no-execution preview **Policy preflight**. On the Console both meanings could appear at once, so a
control labelled "Plan" would be ambiguous.

**Ruling (owner, 2026-09-20):** the Console says **Preflight**: the composer's primary action, the
rendered verdict, and the outcome chip for a preflight call. **Plan** is reserved for the approved
route (ADR-0038) and the plan hash an approval commits to (ADR-0027): the Job's Plan block and every
"plan hash" keep the word, and the shared Plan renderer keeps its name (00). The wire still spells
the option `plan` (GLOSSARY.md): the spelling is contract, the label is copy.

The pre-ADR notes `docs/design/console-wireframe-brief.md` and `docs/design/ui-advisory.md` were
deliberately not swept: they are the pre-ADR record, and each carries a header note pointing here.

### D17. Agents folded into Activity; Access split out — **RESOLVED 2026-09-29 (owner)**

**What:** the Agents screen (03) and Activity (04) were split by grain, which did not match the
questions people bring: "what did the AI-agents do?" was on one screen, and "who signed in?" was
mixed into the other with the fleet's changes.

**Ruling (owner, 2026-09-29):**

1. **Activity is the call-grained feed.** It absorbs the Agents stream, and a dispatching call's
   row is its Job, so one `mutate` across thousands of Nodes stays one row. The Agents screen is
   retired; its list of recently active Accounts survives as a strip and `?account=` filter on
   Activity ([04](04-activity.md)).
2. **Reads are hidden by default**, one click away, and reads made from this Console stay left out
   within them unless asked for.
3. **The split is by the reader's question.** Activity keeps approvals, freeze, Node revokes and
   Enrollment Tokens, because they change the fleet. Sign-ins, step-up, Account changes and API
   Token mints and revokes move to a new admin-only screen, **Access** ([20](20-access.md)),
   because they change who can get in.
4. **Access is admin-only in the Console only.** The route is not mounted below `admin`; the
   records stay on the audit read lane under its existing role rules, so the Control API is
   unchanged. Making the records themselves admin-only would be a capability-layer decision, and it
   was not taken.
5. **Password changes were not on the trail**, because the host-side commands wrote no audit
   record. **Resolved:** `relay init`, which replaced them, writes its records in the same
   transaction as the change, attributed to `local-host` ([20](20-access.md)).

Agents leaves Observe, and Access joins Administer.

*Amended 2026-10-01 (owner):* point 1's strip is gone; Activity keeps the `?account=` filter and
Running now. Point 3 no longer holds for Activity: it lists tool calls only, so freeze transitions,
Node revokes and Enrollment Token mints and revokes stay on the audit trail undrawn. The Access half
of point 3 is unchanged ([04](04-activity.md), Grain).

### D18. Running now; the Account filter names an ID — **RESOLVED 2026-09-30 (owner)**

**Why:** with running Jobs on Activity at their own time, a Job that has run for hours sits pages
down the stream. The Agents screen had shown every running Job on its first page.

**Ruling (owner, 2026-09-30):**

1. **Activity gets a "Running now" section** above the stream ([04](04-activity.md)):
   longest-running first, five per page, paged on its own cursor, following `?account=` and
   neither the kind chips nor the time window, never reordering under the reader.
2. **Cancel lives in that section only.** A running Job appears in the section and in the stream;
   the stream row links to the section's entry, which owns the one Cancel.
3. **`?account=` names the verified Account ID, never a name**, on Activity and wherever links into
   it are drawn (the "Who is active" strip, the Accounts screen's last-tool-call link). An entry
   with no verified ID is listed, unlinked.
4. **Spec 04's row-kind table names `other`**, which the screen has always shown.
5. **Raw Exec's tier is made conspicuous everywhere it is drawn**: its chip gets a treatment of
   its own, and Job detail stops naming an Operation called `raw_exec` as the tier, before the
   Agents screen is removed.

*Amended 2026-10-01 (owner):* point 4 is reversed: Activity draws no `other` row, and a record
kind no tool-call family claims stays on the audit trail. In point 3, the "Who is active" strip is
gone; the Accounts screen's last-tool-call link still uses the verified Account ID.

### D19. A failed sign-in records the typed name only when it is a real Account's — **RESOLVED 2026-09-30 (owner)**

**Why:** a failed sign-in recorded whatever was typed as the username. Someone who types their
password into that box has had it stored in the audit trail and shown on Access.

**Ruling (owner, 2026-09-30):** record, and show, the typed name only when it matches an existing
Account; otherwise record no typed text. The check is made when the attempt is recorded, so the
secret is never stored. The trail may therefore tell "unknown name" from "wrong password" for a
real Account; that is acceptable because only admins read these records, through Access, and admins
already see every Account. The sign-in **response** stays one indistinguishable refusal in message
and time (spec 12). Any future surface that reads the audit trail must not return failed sign-in
records below `admin` ([20](20-access.md)). This reversed spec 20's earlier "no which-half
indication" rule; it does not touch spec 12.

### D21. Approval leaves the Console — **RESOLVED 2026-10-18 (owner), [ADR-0044](../../adr/0044-the-console-does-not-decide-approvals.md)**

The owner: *"Approvals should be cut out of the UI completely."* The Console has no approval
surface — no Approvals destination or nav count, no queue (14), no approval object (08), no
approve or deny, no step-up for one, and no bulk decision. Approvals are answered in-band through
the requesting client, or out-of-band on the Control API, which the owner chose to keep as the
manual rescue. The Console still renders what an approval left behind on another record: approver
chips on Job detail (13) and the `approval` row in Activity (04), which no longer links to a
decision.

Made moot: D10's Console half (the card's diff placement, the queue's fan-out tiebreak) and the
queue's unaudited read (#779). Specs 08 and 14 are retired stubs; the screens are removed
(`docs/specs/approval.md` AP-80).

**Not settled by it — needs the owner:** whether "cut out of the UI completely" also reaches
[19 — Approval rules](19-approval-rules.md), the page where an `admin` edits the gate rules
(`approval.md` AP-72). ADR-0044 removed the *decision* surface only. If the rules page goes too,
AP-72's "edited only in the Admin Console" leaves the rules with no writer at all, which is an
invariant 11 question (reach-bounding settings change only by a human Account with step-up),
not a screen change.

### D20. Hostname is the visual primary — **RESOLVED 2026-10-01 (owner)**

**Ruling (owner, 2026-10-01):** the hostname is the visual primary on Fleet rows and the Node
detail H1, marked self-reported, with the verified Node ID beneath it in mono. Selectors, links and
`?account=`/Node references keep using verified IDs. *Widened by D22* to wherever a Node is shown.

### Owner review of the running Console — **RESOLVED 2026-10-18 (owner)**

Taken with the owner on 2026-10-18, after a review of the running Console in a browser. Each is a
ruling; where it overturned a written rule, that rule was amended in place.

### D22. Hostname first everywhere — **RESOLVED 2026-10-18 (owner)**

Widens D20. Wherever a Node is shown to a human — Fleet, Node detail, Compare's column headings, the
pin chips, any other mention — the self-reported hostname is the primary label, marked
self-reported, and the verified Node ID is secondary beside it: smaller, mono, muted, in full and
never truncated. With no usable hostname the Node ID is the primary label. Selectors, links, pins
and `?account=` still use verified IDs; only the display order changed (`00-foundations.md`,
"Self-reported names").

### D23. Policy aliases — **RESOLVED 2026-10-18 (owner)**

A human `admin` may set, rename or clear a human-readable alias for a Policy fingerprint, from the
Fleet view or Node detail; each change is audited with its old and new value, and takes no step-up
because an alias gates nothing. The full hash is always drawn beside the alias. An alias is display
only: never a Selector term, never a filter value, never an input to Policy evaluation or anything
security-relevant, and never Policy — it is metadata the Relay holds about a fingerprint, so
invariant 2 is untouched. Where no alias is set, the Console draws a neutral per-render letter (A,
B, C…) with no colour and no "majority", "outlier" or "normal" wording, for D1's reason: the
commonest Policy is not the desired one (invariant 9). The capability is `docs/specs/query.md`;
the write is v0.6.0, so the Fleet view's no-mutation acceptance excepts it (spec 01).

### D24. Destructive acts look dangerous and confirm by name — **RESOLVED 2026-10-18 (owner)**

Revoke, Disable and Lower role — and any later revoke or disable — take the danger style (outlined
in the muted red) and ask a confirmation that names the target and the consequence, as a
server-rendered step with no script. Replaces the rule that a reducing act is "never red" and
quiet (`00-foundations.md`, "Form controls"; spec 15) and amends D5. The step-up matrix is
unchanged: revocation still takes no password.

### D25. No lock on `relay:` chips — **RESOLVED 2026-10-18 (owner)**

`relay:` is filled, distinct in hue, and carries its mono prefix, with no icon; a fenced chip has
none either. The lock the foundations once required is dropped, not restored.

### D26. A refused Fleet filter is said where it was typed — **RESOLVED 2026-10-18 (owner)**

The count reads "filter not applied", the refusal sits under the field, marked invalid, and the
whole fleet stays visible below but de-emphasised. Validation is on submit, server-side, by the one
Selector parser; nothing parses a Selector in the browser (spec 01, "A refused filter").

### D27. System state is the Fleet view's headline — **RESOLVED 2026-10-18 (owner)**

The reachable count and the Policy-fingerprint count, with aliases, are stated first and largest;
there is no approvals count. Healthy groups stay compressed to one line, collapsed with a native
`<details>` (spec 01).

### D28. Compare shows differences only, by default — **RESOLVED 2026-10-18 (owner)**

A GET toggle, on by default; "nothing differs" said in words; a differing row emphasised by weight
and a border, never by a new hue and never on a cell; a "not reported" column still marks its row
(spec 02).

### D29. Activity's first-run state is one explanatory block — **RESOLVED 2026-10-18 (owner)**

Only with nothing recorded and no filter applied: the feed's and Running now's empty messages fold
into one block saying what will appear and how, the live-region sentence stays, and the filters
sit in a closed `<details>`. With a filter applied and nothing matching, the filters stay open
(spec 04, "Nothing recorded yet").

### D30. Freshness in words, never on a timer — **RESOLVED 2026-10-18 (owner)**

The Fleet view gets a Refresh link. Render times read relatively ("rendered 40s ago") with the
absolute UTC time in `datetime` and `title`; an old page says so in words and weight, never amber.
An external same-origin script may advance the relative text; nothing reloads on a timer
(`00-foundations.md`, "How old a page is").

### D31. No "About this screen" disclosure — **RESOLVED 2026-10-18 (owner)**

Dropped from every screen. A standing note is visible, as one sentence beside what it qualifies,
or deleted when its substance is in the docs; a note the Console must be visibly bound by was
never collapsed and still is not (`00-foundations.md`, "Standing notes and situational messages").
*Tightened by D34 (2026-10-21):* a standing note is now deleted unless the screen would be wrong
without it, and the exception for a note the Console must be visibly bound by is withdrawn.

### D32. Accounts: the selected panel first, creation behind a button — **RESOLVED 2026-10-18 (owner)**

The selected Account's panel is at the top; the create form is behind **New account** in a native
`<details>`. The role selects preselect the current role, not submittable; Lower role is never drawn
dimmed with it selected — a hint says "choose a lower role" instead (spec 15).
*Superseded by D35 (2026-10-21)* for layout: there is no selected-Account panel, and New account
is a modal. The role-select rules stand.

### D33. Access draws an Account ID as an identifier — **RESOLVED 2026-10-18 (owner)**

A subject Account ID a record carries is drawn in the identifier treatment, not as raw text, and a
name only where the record carries one. Resolving IDs to current names stays deferred until #659
(spec 20).

### Owner review, "show, don't tell" — **RESOLVED 2026-10-21 (owner)**

Taken with the owner on 2026-10-21, after a Playwright crawl of the running Console (#1106, #1109,
#1107). Each is a ruling; where it overturned a written rule, that rule was amended in place.

### D34. Show, don't tell — **RESOLVED 2026-10-21 (owner, #1106)**

Tightens D31. Data, chips, controls and tooltips carry meaning; prose is the exception. A standing
note is **deleted unless the screen would be wrong without it**; situational messages stay visible.
A Refresh control carries no sentence saying a Refresh is audited — the reads still are
(`docs/specs/audit-and-read-lane.md`); the screen just does not say so (`00-foundations.md`,
"Refreshing a screen").

On invariant 2: Node detail's dashed "There is no path from this screen to this Node's Policy" box
is **deleted, with no replacement tag**. That the Relay never writes a Node's Policy is a known
property of the product and belongs in the docs and marketing material, not on the screen. The
property itself is unchanged; only the sentence goes. This withdraws D31's clause that such a note
is never collapsed.

The per-note dispositions, as amended into the screen specs:

| Screen | Note | Disposition |
|---|---|---|
| every screen with Refresh | "Every Refresh is an audited read." | deleted |
| Fleet | "every Node here is reachable, current and permitted — no state label…" | deleted |
| Fleet | "Every Node in `web`, oddest first." caption | visually hidden (screen readers only) |
| Node detail | label-namespace legend | deleted; each chip's tooltip says who sets it |
| Node detail | "These counts are observations, never evidence of equal Policy or trust." | deleted |
| Node detail | "Received at …, 3h ago: a receipt time, not a query time." | "Received 3h ago", the instant in the tooltip |
| Node detail | invariant-2 box | deleted, no replacement (above) |
| Node detail | "output not retained" on read-class Recent Tasks | deleted, as on Activity |
| Compare | caption "Only rows that differ are shown", two footnotes | deleted |
| Activity | lede, live-counter sentence, page-size sentence | deleted; the live control reads "Live · N new" |
| Activity | "Output was not retained…" on every read row | deleted |
| Activity | "N consecutive identical calls … on the audit trail", "N calls collapsed into M rows" | a `×N` chip, its time range in the tooltip |
| Accounts | role-ceiling and OAuth-password notes | deleted |
| Accounts | "The value is shown once…" | kept as "Shown once." |
| Access | admins-only, no-subject-filter, older-failed-sign-in and page-size notes | deleted |
| Access | "OAuth sign-ins happen at the identity provider…" | drawn only when OAuth is configured |

### D35. Accounts is one list; New account and Edit are modals — **RESOLVED 2026-10-21 (owner, #1109)**

Supersedes D32's layout. Modelled on Gleipnir's account-management screen, copying the pattern and
not the code: one table (Name, Kind, Role, Status, Last authentication, Last tool call for machine
Accounts, and Edit and Disable/Enable in the row); **New account** in the page header opens a modal
with a live "what this role may do" panel beside the role radios; **Edit** opens the same modal in
edit mode holding role, state and the Account's API Tokens. Modals are native `<dialog>` driven only
by the external same-origin script; every act is a CSRF-bearing POST; without JavaScript each falls
back to a page (`/console/accounts/<name>` for an Account) with **Back to Accounts**. Step-up, the
self-target and last-admin refusals, reveal-once, and the named confirmation for destructive acts
are unchanged (spec 15; [11](11-console-shell.md), "Modals").

**Still open:** the model's badge colours (a hue per role; status green or red) against the colour
budget (D5, D24), and whether an Active sessions list belongs beside the own-password form.

### D36. An Account changes only its own password — **DECIDED 2026-10-21 (owner, #1107); ADR pending**

A signed-in human Account may change only its **own** password, from a **your account** surface
reached from the signed-in block. There is no admin reset of another Account's password. Spec 15
records the design as *Designed, pending ADR*; nothing is built until the ADR merges. The ADR
settles proof of the current password, session rotation and revocation, the Access record, how a
Console-created human Account gets its first password, and that the change is reach, not security
floor, under invariant 11. `docs/specs/accounts-and-access.md` still describes an admin reset as
intended; it is an aspirational spec, and reconciling it is the ADR's change.

## Prerequisites that already exist as issues

### D8. [#397](https://github.com/Felag-Engineering/relay/issues/397) — three route families have no role gate — **RESOLVED: gates landed**

Enrollment-token mint, Node revoke and Freeze engage/release authenticated the caller and never
checked a role, so a `viewer` could do all three; that blocked specs 09 and 16.

**Resolved (2026-08-24).** Five floors are enforced from the one `authz.RoleGate`: mint `admin`,
token revoke `admin`, Node revoke `admin`, Freeze engage a **human** `operator`+, Freeze release
`admin` with a reason. Freeze's floor lives in `capability.Control`, so the Console inherits it;
mint and revoke are checked at the Control API surface, because `capability`'s import allowlist
bars `internal/enroll` and `internal/revocation`. Every refusal is audited as a `refusal` with the
Account, and `TestEveryRouteIsRoleClassified` fails any route added without a declared floor.

**Still owed:** ADR-0020 asks for `admin` **+ step-up re-authentication** on Node revoke, and the
Control API has no step-up mechanism (`api/nodes.go`). Spec 16 may state the role requirement as
enforced; it may not yet promise the step-up.

### D13. [#403](https://github.com/Felag-Engineering/relay/issues/403) — the Relay's server certificate never rotates — **RESOLVED: the leaf rotates in-process**

The server leaf was issued once at process start with the Node-identity lifetime, so a Relay up
past fourteen days would have served an expired certificate to the fleet and the Console alike.
**Resolved** (E2a in `../self-serve-enrollment.md`): the leaf has its own constant,
`ca.ServerLeafValidity` (24h), and is re-issued in-process before it expires, with each rotation
logged and counted (`serverCertObserver`, `relay/cmd/relay/main.go`). Its sibling
[#404](https://github.com/Felag-Engineering/relay/issues/404) — one multi-SAN certificate for both
listeners (ADR-0031 decision 1) — is open, so each listener still has its own leaf.

### D14. CA rotation has no story — **raised as [#412](https://github.com/Felag-Engineering/relay/issues/412)**

`caValidity = 10 * 365 * 24 * time.Hour`. Ten years is a long horizon, but it is not "never", and
the more urgent case is unbounded: **if the CA key is ever compromised, there is no rotation path
at all.**

Rotation is hard by design. The join string pins the **CA fingerprint**, and the daemon verifies
the presented chain against that pin *before anything else*. Every Node's trust anchor is that one
CA, and the daemon's security model distrusts the Relay, so the Relay cannot simply hand out a new
anchor.

Not a Console concern. Recorded because it surfaced while specifying certificate expiry, and a
trust-root rotation story is cheap to design now and expensive to retrofit. Open as decision issue
**#412**, for an ADR covering planned rotation and CA-key compromise, which may want different
answers.

### D9. The SSE seam must cover MCP tool calls — **RESOLVED 2026-08-24: widen it**

The call-grained stream (now Activity, spec 04) needs **MCP tool-call events**, a third publisher
beside registry and Job transitions: a `list_nodes` call changes no registry state and creates no
Job.

**One in-process pub/sub, four publishers** — registry transitions, Job transitions, MCP tool
calls, and **enrollment attempts** (spec 10's watch: Relay-side outcomes only, token ID never
plaintext). Events carry monotonic IDs from a bounded per-publisher ring buffer so a client can
resume from `Last-Event-ID`; a client too far behind receives a `gap` event and reloads its region
rather than pretending continuity.

**A hard constraint on the tool-call publisher.** Its events carry **arguments** — file paths,
Selectors, and for `raw_exec` the full argv. That is the point and it is fine. It must **never**
carry read *results*: ADR-0025's no-retention property is about the data, not about one table, and
an event bus that ships read output has leaked it just as surely as an audit row that stores it.
Assert this structurally, the way `no_dispatch` is asserted.

### D10. The approval record needs a shape key — **RESOLVED 2026-08-24, and it is a v0.5.0 decision**

*(Console half moot since D21: specs 08 and 14 are retired, so the diff placement and the fan-out
tiebreak have no screen. The shape key stands in the approval domain; what renders its diff is an
open question in `docs/specs/approval.md`.)*

The anti-fatigue diff — "same as what you approved Tuesday, except the fan-out grew 1,180 →
2,214" — has to find *the last approved action of the same shape*, so the approval record must be
queryable by shape.

**Add one field: a shape key.** A hash over the Operation and the **normalised Selector**,
deliberately **excluding** fan-out and any argument expected to vary. Finding the prior approval
becomes a lookup rather than a scan, and "same shape, different scale" is precisely what the diff
exists to express.

**Why this could not wait.** Retrofitting means a migration over records whose shape key cannot be
recomputed — normalising a Selector after the fact is guesswork, and the approval trail is the data
you least want to guess about. It landed as a retrofit (#415) before any production approval
records existed. For a Grant (#378) the key hashes the Scope.

**What the v0.5.0 work must settle:** the normalisation rules for a Selector (term order,
whitespace, namespace canonicalisation), and which arguments are part of the shape versus part of
the scale. Getting the second wrong in either direction breaks the feature: too strict and every
approval looks novel, too loose and a materially different action reads as routine.

**Rejected:** scanning the audit trail at render time (a scan on the most latency-sensitive screen,
with a fuzzy definition of "matching"); storing a resolved pointer to the prior approval at write
time (moves comparison logic into the write path, where an error is baked into history).

**Settled by #415.** Three answers, in code:

*Selector normalisation.* Terms are projected from the **typed** `Predicate`, never from Selector
text: the namespace travels as its own length-prefixed field, so a `tag:` term can never normalise
into anything a `relay:` one could collide with (invariant 7). Terms are sorted by
(namespace, key, value) as strings and **exact** duplicates dropped — `node:a=b, node:a=c` is not
collapsed. Nothing is case-folded, whitespace-trimmed inside a term, or Unicode-normalised, because
`Selector.Matches` is an exact map lookup: folding would let two Selectors that target *different*
Nodes share a key. Whitespace-insensitivity comes from the parser, which already trims around terms.
The only folding anywhere is `ToLower` on a Grant's account and Operation names, matching
`Grant.Covers`' `EqualFold` — the rule is **fold where the matcher folds, and nowhere else**.

*Shape versus scale.* Declared per Operation in `opvocab.Descriptor.ArgClasses` and cross-checked
against the daemon's golden Operation schema, so an argument the daemon grows without a class fails
a test. `pkg.install.version` is **scale** — the textbook "argument expected to vary"; classifying
it as shape would make every step of a rollout look novel. Every other native argument is shape. A
**Template Operation** has declared nothing, so every one of its arguments is shape, and every
**Raw Exec** argv element is shape: "never inferred" means we do not guess which element is scale.
A Grant's key also excludes `MaxFanOut` — a ceiling is fan-out, and "same scope, ceiling grew
10 → 500" is the diff the callout exists to shout rather than hide behind a novel-looking key.

*The retrofit.* A pre-#415 **grant** request is recomputed exactly, because its Scope is fully
stored. A pre-#415 **Plan** record cannot be: `approval_requests` never stored the Selector or the
arguments, and this section already rules out guessing. Each such record gets a unique
`legacy:<request id>` key, so it is its own shape and the read seams refuse it — the callout can
never say "you approved this Tuesday" about a record whose shape nobody knows.

**Where the diff inputs come from** (settled by #426, for the retired card): a Grant's numbers from
the `approval_grants` scope/window columns, reached by `GrantByRequest` (deliberately not
`ActiveGrants`: the prior Grant is usually expired or exhausted); a Plan's scale arguments and
Selector from the park's own `approval_requested` audit record, joined on `approval_id` — two
exact-id reads of records already found by shape key, not a scan. The fan-out comes from nowhere:
a park creates no Job, so "1,180 → 2,214" is unavailable until the resolved fan-out is on the
approval record (#469).

---

## Proposed, not specified

### D11. A read-egress view — **RESOLVED 2026-08-24: specified as [17](17-read-egress.md); REVERSED 2026-10-01**

**Reversed 2026-10-01 (owner decision):** the screen is dropped. Activity ([04](04-activity.md))
is the single log of control-plane traffic; read-class calls appear there as `read` and read-class
`dispatch` rows. [17](17-read-egress.md) is retired.

It was proposed because ADR-0021, ADR-0022 and ADR-0025 build read-exposure machinery the Console
did not surface. Its limit carries over to Activity: the trail can say a read happened, by whom,
of what and when, but never what it contained.

### D12. A capability preview — "what could this Account actually do?"

Given a role and the fleet's live Policy, render the reachable envelope before someone is handed
the keys. Turns an abstract role grant into a concrete blast radius. More speculative; raised, not
pursued.

---

## Known gaps with no spec yet

**None.** Every screen named in earlier drafts has a spec.

Two dimensions cut across every screen and are drawn nowhere: a `viewer` sees a **structurally
smaller** Console, not a greyed-out one, and `console_execution = off` removes Run **entirely**.
*Absent* beats *forbidden* (ADR-0026).

---

## Review, 2026-08-24 — what changed after the issues were cut

What still governs:

- **There are no agent sessions.** MCP is stateless (ADR-0028). Disconnect is gone; Suspend is
  deferred (D2, #443).
- **v0.6.0 "zero mutating routes"** means *no Console route reaches the capability layer's write
  or dispatch path*. A session, a saved view or an audit query is not that. **Cancel is v0.7.0.**
- **`console_execution`** lands with the composer (v0.7.0, spec 05), as file-only Relay
  configuration. Until then the shell's property is that the nav is built from mounted routes.
- **Backend seams:** audit/Job query seams live in the capability layer's read lane; saved views
  need a preference store (#442).
- **A batch is a Grant** over a Scope (ADR-0027).
- **Day one** shows Relay-side enrollment rejections only; daemon-side fingerprint rejections are
  invisible to the Relay by design (#444 for a handshake-abort hook).
- **Login throttling** carries its own defaults (spec 12), with progressive delay and no hard
  lockout.
- **Freeze engage is human-principal only.**
