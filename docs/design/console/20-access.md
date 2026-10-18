# 20 — Access

**No artboard.** Who got into the control plane, and who changed who can get in. **Admin only.**
**Milestone v0.6.0.**

**Governing:** ADR-0010, ADR-0025, ADR-0026, invariants #10, #11, `12-login.md`,
`15-accounts-and-tokens.md`.
**Backend:** the audit query seam through the **capability layer's read lane** (#441, never
Console→store), filtered to the identity and authentication record kinds.

*(Owner decision, 2026-09-29: sign-ins and Account changes moved here from
[04 — Activity](04-activity.md), and the Agents screen was folded into Activity. Activity answers
"what was asked of the control plane, and what did it do to the fleet?". This screen answers "who
got in, and who changed who can get in?")*

## What this screen is for

The first questions asked after a compromise are about identity: who signed in, from where, who
failed to, who created this Account, who made it an admin, and who minted it a credential. Those
answers are on the trail today (#297, #418, #477), mixed into the fleet's activity. This screen
gives them to the person who acts on them, an admin, in one place.

## Row kinds

| Kind | Records | Carries |
|---|---|---|
| `sign-in` | `login_succeeded`, `login_failed`, `login_throttled`, `logout` | the Account where the record names one, the outcome, the source address; on a failed or throttled attempt, the name typed **only where it is a real Account's name** |
| `step-up` | `step_up`, `step_up_failed`, `step_up_throttled` | the session's Account, the outcome |
| `account` | `account_create`, `account_role`, `account_enable`, `account_disable`, `password_set`, `password_clear` | who acted, on which Account, and the change (new role, enabled, disabled, password set or removed — never the password) |
| `api-token` | `api_token_mint`, `api_token_revoke` | who acted, for which Account, the token's ID — never its value; a mint by `relay bootstrap-token` is the same kind |

**A failed sign-in records the name typed only where it is a real Account's name** (owner
decision, 2026-09-30, D19). A person who types their password into the username box has typed a
secret, and a trail that kept every typed name would store it. So the name is recorded, and drawn,
only when it matches an existing Account at the time of the attempt; otherwise the record carries
no typed text and the row says "a name that is not an Account". The check is made **when the
attempt is recorded**, not when this screen draws it, so the secret is never stored anywhere.

This does let the trail tell "unknown name" from "wrong password" apart for a real Account, which
the trail previously refused to do. That is acceptable because of **who reads it**: only an admin,
through this screen, and an admin already sees every Account on [15](15-accounts-and-tokens.md).
The distinction never reaches the person signing in: the sign-in response stays one message in
one time for every failure ([12](12-login.md), "No user enumeration"). A failed **step-up** is
unaffected — it always runs against the session's own Account.

**A throttled attempt is not a failed one.** It was refused before any credential was compared, so
it is drawn as throttled and never counted as a guess.

**Where a password is set, it is a row here.** Passwords are set or removed only by the host-side
`relay console-password` command, and the first API Token is minted by `relay bootstrap-token`; each
writes its record in the same transaction as the change, so a change that cannot be recorded is not
made (#782). Those rows are attributed to `local-host` (the host lever the freeze signal also
records), not to any Account, and the screen draws them as the Relay host rather than as a verified
or asserted chip. A `password_clear` on an Account that had no password is still a row; its record
says `removed=false` and the screen says none was set, so the trail never claims a removal that did
not happen.

**Enrollment Tokens are not here.** They join Nodes rather than authenticate callers.
Conflating the two in one list would mix fleet growth with credential issuance, the same reason
the trail keeps their kinds apart. Their mints and revokes stay on the audit trail. Activity no
longer draws them either (owner decision, 2026-10-01, #829), and giving fleet events a home is
follow-up work.

## Who may see it

**Admin only, in the Console.** The route is not mounted below `admin`, so it answers the same 404
as a path that was never mounted — a 403 would itself disclose that the screen exists. It is absent
from a non-admin's nav, following the nav rule in [11](11-console-shell.md).

**This narrows the Console only, and says so (owner decision, 2026-09-29).** Hiding a screen is a
narrowing an adapter may make on its own (invariant 10). Today no Control API or MCP route reads
the audit trail, so this screen is the only reader of these records. **Where any other surface
comes to read the audit trail, it must not return failed sign-in records below `admin`**: they
now say which names are real Accounts (D19). That restriction would be the capability layer's to
make, and it is part of that change, not a later one.

## Identity on every row

The verified/asserted grammar from `00-foundations.md`. The actor of an `account` or `api-token`
row is verified: the Relay authenticated it. The exception is a host-lever row, which names
`local-host` as its actor: root on the Relay host, which no Account's credential proves, so it is
neither a verified nor an asserted chip. The verified actor chip links to this screen filtered by
that Account's ID, and the dashed chip appears only when the claimed name differs from the
verified one, or when the attempt failed or was throttled. The subject — the Account created, changed or given a
token — is drawn from the record as written. Today that record names the subject by Account ID, and
by name only on `account_create` and on the host password rows; an `api_token_revoke` names only the token. Where the screen
shows a subject's name that the record does not carry, it would be a registry lookup reporting
the Account as it is now, the problem [04](04-activity.md) describes under "Kind is never read from
the registry". **Whether to resolve a subject's ID to its current name is open**, and until it is
decided the screen shows what the record carries. No kind label is drawn: these records carry none.

**An Account ID the record carries is drawn as an Account ID, not as text** (owner decision,
2026-10-18, D32). Where a record names its subject Account by ID — inside the record's reason, today
— the screen draws it in the identifier treatment (mono, in full, never truncated,
`00-foundations.md` "Identifiers render verbatim"), set apart from the surrounding words with a
small "Account" caption so it reads as one value rather than as part of a `key=value` string. It is
not a trust chip: it has neither the filled nor the dashed treatment, because formatting an ID the
record carries asserts nothing about who authenticated; the actor keeps its verified chip. A name is
drawn beside it only where the record itself carries one — `account_create`'s `name=`, the host
password rows — and never looked up. Resolving an ID to its current name stays deferred until an
audited Account-read path exists (#659).

**OAuth sessions have no sign-in row.** An OAuth sign-in happens at the identity provider, not at
the Relay, which sees only authenticated calls. This screen lists Console sign-ins, and one visible
sentence says that OAuth sign-ins are not among them.

## Filtering and refresh

Kind chips, an Account filter over the **actor**, a failures-only toggle, and time controls: a
relative window and an explicit range. The Actor box takes the Account's ID (D18), and its placeholder
says so. Looking an Account up by name is deferred until an audited Account-read path exists
(#659): the registry read it needs is one no audit record covers. Rows are never read from the
registry. There is no filter by **subject** yet: the subject is
written into the record's free-text reason, which the audit query seam cannot filter on. The
screen says so in one visible sentence beside the filters rather than offering a filter that would
search the page and call it history. It follows the Refresh rules in `00-foundations.md`
("Refreshing a screen"): a deliberate click, never a timer, and every reload is an audited read.

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
- [ ] A password set or removed with `relay console-password`, and a token minted with `relay bootstrap-token`, is a row here attributed to `local-host`.
