# 20 — Access

**No artboard.** Who got into the control plane, and who changed who can get in. **Admin only.**
**Milestone v0.6.0.**

**Governing:** ADR-0010, ADR-0025, ADR-0026, invariants #10, #11, `12-login.md`,
`15-accounts-and-tokens.md`.
**Backend:** the audit query seam through the **capability layer's read lane** (#441, never
Console→store), filtered to the identity and authentication record kinds.

Activity ([04](04-activity.md)) answers "what was asked of the control plane, and what did it do
to the fleet?". This screen answers "who got in, and who changed who can get in?" (D17).

## What this screen is for

The first questions after a compromise are about identity: who signed in, from where, who failed
to, who created this Account, who made it an admin, who minted it a credential. Those answers are
on the audit trail; this screen gives them to the person who acts on them, an admin, in one
place.

## Row kinds

| Kind | Records | Carries |
|---|---|---|
| `sign-in` | `login_succeeded`, `login_failed`, `login_throttled`, `logout` | the Account where the record names one, the outcome, the source address; on a failed or throttled attempt, the name typed **only where it is a real Account's name** |
| `step-up` | `step_up`, `step_up_failed`, `step_up_throttled` | the session's Account, the outcome |
| `account` | `account_create`, `account_role`, `account_enable`, `account_disable`, `password_set`, `password_clear` | who acted, on which Account, and the change (new role, enabled, disabled, password set or removed — never the password) |
| `api-token` | `api_token_mint`, `api_token_revoke` | who acted, for which Account, the token's ID — never its value; a mint by `relay init` is the same kind |

**A failed sign-in records the name typed only where it is a real Account's name** (D19). A
person who types their password into the username box has typed a secret, and a trail that kept
every typed name would store it. So the name is recorded, and drawn, only when it matches an
existing Account at the time of the attempt; otherwise the record carries no typed text and the
row says "a name that is not an Account". The check is made **when the attempt is recorded**, so
the secret is never stored.

This lets the trail tell "unknown name" from "wrong password" for a real Account. That is
acceptable because of **who reads it**: only an admin, through this screen, and an admin already
sees every Account on [15](15-accounts-and-tokens.md).
The distinction never reaches the person signing in: the sign-in response stays one message in
one time for every failure ([12](12-login.md), "No user enumeration"). A failed **step-up** is
unaffected — it always runs against the session's own Account.

**A throttled attempt is not a failed one.** It was refused before any credential was compared, so
it is drawn as throttled and never counted as a guess.

**Where a password is set, it is a row here.** The host-side `relay init` sets the first admin's
password and mints its first API Token (`--admin`), and re-mints a lost API Token (`--recover`).
Each writes its record in the same transaction as the change, so a change that cannot be recorded
is not made. Those rows are attributed to `local-host` (the host lever the freeze signal also
records), not to any Account, and the screen draws them as the Relay host rather than as a verified
or asserted chip. A `password_clear` on an Account that had no password is still a row; its record
says `removed=false` and the screen says none was set, so the trail never claims a removal that did
not happen.

**Enrollment Tokens are not here.** They join Nodes rather than authenticate callers, and one list
would mix fleet growth with credential issuance. Their mints and revokes stay on the audit trail;
Activity does not draw them either.

## Who may see it

**Admin only, in the Console.** The route is not mounted below `admin`, so it answers the same 404
as any unmounted path — a 403 would disclose that the screen exists. It is absent from a
non-admin's nav ([11](11-console-shell.md)).

**This narrows the Console only (owner decision, 2026-09-29).** Hiding a screen is a narrowing an
adapter may make on its own (invariant 10). No Control API or MCP route reads the audit trail, so
this screen is the only reader of these records. **Where any other surface comes to read the
audit trail, it must not return failed sign-in records below `admin`**: they say which names are
real Accounts (D19). That restriction is the capability layer's to make, as part of that change.

## Identity on every row

The verified/asserted grammar from `00-foundations.md`. The actor of an `account` or `api-token`
row is verified: the Relay authenticated it. The exception is a host-lever row naming `local-host`
as its actor: root on the Relay host, which no Account's credential proves, so it is neither a
verified nor an asserted chip. The verified actor chip links to this screen filtered by that
Account's ID; the dashed chip appears only when the claimed name differs from the verified one, or
when the attempt failed or was throttled. The subject — the Account created, changed or given a
token — is drawn from the record as written: by Account ID, and by name only on `account_create`
and the host password rows; an `api_token_revoke` names only the token. A name the record does not
carry would be a registry lookup reporting the Account as it is now ([04](04-activity.md), "Kind is
never read from the registry"). **A subject's ID is resolved to its current name once an audited
Account-read path exists (#659)** (D33): drawn beside the ID and marked as the name *now* — "now
`dev-approver`" — never as what the record said. Until then the screen shows only what the record
carries. No kind label is drawn: these records carry none.

**An Account ID the record carries is drawn as an Account ID, not as text** (D33). Where a record
names its subject by ID — inside the record's reason — the screen draws it in the identifier
treatment (mono, in full; `00-foundations.md`, "Identifiers render verbatim"), with a small
"Account" caption so it reads as one value rather than part of a `key=value` string. It is not a
trust chip: formatting an ID asserts nothing about who authenticated. A name is drawn beside it
only where the record itself carries one, and, until #659, never looked up.

**OAuth sessions have no sign-in row.** An OAuth sign-in happens at the identity provider, not at
the Relay, which sees only authenticated calls. This screen lists Console sign-ins, and one visible
sentence says that OAuth sign-ins are not among them.

## Filtering and refresh

Kind chips, an Account filter over the **actor**, a failures-only toggle, and time controls: a
relative window and an explicit range. The Actor box takes the Account's ID (D18), and its
placeholder says so; lookup by name waits for an audited Account-read path (#659). Rows are never
read from the registry. There is no filter by **subject**: the subject is in the record's free-text
reason, which the audit query seam cannot filter on. One visible sentence beside the filters says
so, rather than offering a filter that would search the page and call it history. Refresh follows
`00-foundations.md` ("Refreshing a screen").

## Must not appear

- A password, a password hash, or any part of an API Token's value, at any age.
- A typed name on a failed sign-in that is not a real Account's name — it may be a password.
- Anything that tells the person signing in which half was wrong: that stays one refusal
  ([12](12-login.md)).
- Tool calls — those are [04 — Activity](04-activity.md). Fleet events (Freeze transitions, Node
  revokes, Enrollment Tokens) are not here either; they are on the audit trail.
- Any control. Disabling an Account and revoking a token are [15](15-accounts-and-tokens.md).

## Acceptance

- [ ] An admin answers "who signed in, who failed to, and who changed an Account or minted it a
      credential" from this screen, for a chosen time range.
- [ ] A subject is shown as its record names it; nothing on a row is read from the registry.
- [ ] A non-admin gets a 404 for the route and no nav item.
- [ ] A failed sign-in for a real Account's name shows that name; one for any other name shows no
      typed text, and the name is absent from the stored record, not only from the page.
- [ ] The sign-in response is still byte- and time-indistinguishable across every failure.
- [ ] A throttled attempt is drawn as throttled and is not counted as a failure.
- [ ] A password set, and a token minted, with `relay init` is a row here attributed to `local-host`.
