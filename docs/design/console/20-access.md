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
| `sign-in` | `login_succeeded`, `login_failed`, `login_throttled`, `logout` | the Account where the record names one, the outcome, the source address |
| `step-up` | `step_up`, `step_up_failed`, `step_up_throttled` | the session's Account, the outcome |
| `account` | `account_create`, `account_role`, `account_enable`, `account_disable`, `password_set`, `password_clear` | who acted, on which Account, and the change (new role, enabled, disabled, password set or removed — never the password) |
| `api-token` | `api_token_mint`, `api_token_revoke` | who acted, for which Account, the token's ID — never its value; a mint by `relay bootstrap-token` is the same kind |

**A failed sign-in or step-up says it failed and nothing more.** Its record deliberately carries no
indication of which half was wrong, because a trail that separated "unknown Account" from "wrong
password" would be an enumeration oracle readable by anyone with audit access. The screen does not
reconstruct that distinction from anything else.

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

**Enrollment Tokens are not here.** They join Nodes rather than authenticate callers, so they stay
on [04 — Activity](04-activity.md) with the fleet's other membership events. Conflating the two in
one list would mix fleet growth with credential issuance, the same reason the trail keeps their
kinds apart.

## Who may see it

**Admin only, in the Console.** The route is not mounted below `admin`, so it answers the same 404
as a path that was never mounted — a 403 would itself disclose that the screen exists. It is absent
from a non-admin's nav, following the nav rule in [11](11-console-shell.md).

**This narrows the Console only, and says so (owner decision, 2026-09-29).** The records this
screen lists remain on the audit read lane under its existing role rules, so the Control API
returns them to any Account those rules already allow. Hiding a screen is a narrowing an adapter
may make on its own (invariant 10). Making the records themselves admin-only would be a decision
of the capability layer, not of this screen, and it has not been taken.

## Identity on every row

The verified/asserted grammar from `00-foundations.md`. The actor of an `account` or `api-token`
row is verified: the Relay authenticated it. The exception is a host-lever row, which names
`local-host` as its actor: root on the Relay host, which no Account's credential proves, so it is
neither a verified nor an asserted chip. The subject — the Account created, changed or given a
token — is drawn from the record as written. Today that record names the subject by Account ID, and
by name only on `account_create` and on the host password rows; an `api_token_revoke` names only the token. Where the screen
shows a subject's name that the record does not carry, it would be a registry lookup reporting
the Account as it is now, the problem [04](04-activity.md) describes under "Kind is never read from
the registry". **Whether to resolve a subject's ID to its current name is open**, and until it is
decided the screen shows what the record carries. No kind label is drawn: these records carry none.

**OAuth sessions have no sign-in row.** An OAuth sign-in happens at the identity provider, not at
the Relay, which sees only authenticated calls. This screen lists Console sign-ins; the disclosure
says that OAuth sign-ins are not among them.

## Filtering and refresh

Kind chips, an Account filter over the **actor**, a failures-only toggle, and time controls: a
relative window and an explicit range. There is no filter by **subject** yet: the subject is
written into the record's free-text reason, which the audit query seam cannot filter on. The
disclosure says so rather than offering a filter that would search the page and call it history. It follows the Refresh rules in `00-foundations.md`
("Refreshing a screen"): a deliberate click, never a timer, and every reload is an audited read.

## Must not appear

- A password, a password hash, or any part of an API Token's value, at any age.
- Any split of a failed sign-in or step-up into "unknown Account" and "wrong password".
- Tool calls or fleet events — those are [04 — Activity](04-activity.md).
- Any control. Disabling an Account and revoking a token are [15](15-accounts-and-tokens.md).

## Acceptance

- [ ] An admin answers "who signed in, who failed to, and who changed an Account or minted it a
      credential" from this screen, for a chosen time range.
- [ ] A subject is shown as its record names it; nothing on a row is read from the registry.
- [ ] A non-admin gets a 404 for the route and no nav item.
- [ ] A failed sign-in carries no indication of which half was wrong.
- [ ] A throttled attempt is drawn as throttled and is not counted as a failure.
- [ ] A password set or removed with `relay console-password`, and a token minted with `relay bootstrap-token`, is a row here attributed to `local-host`.
