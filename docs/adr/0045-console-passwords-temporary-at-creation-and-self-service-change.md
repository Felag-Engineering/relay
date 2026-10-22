# Console passwords: a temporary password at creation, and a self-service change

**Status:** Accepted (owner decision 2026-10-22, #1107). Supersedes the Console owner decision of
2026-09-19 that only `relay init --admin` sets a Console password, and the 2026-10-21 decision
(D36) that a Console-created human Account gets no password from the Console. Invariant 11 is
clarified, not amended: its text is unchanged.

A human signs in to the Admin Console with a local password (ADR-0009, ADR-0010). Until this
decision exactly one surface could set one: `relay init --admin`, on the Relay's host, for the
founding admin (ADR-0030, amended 2026-10-16). The Console owner decision of `2026-09-19` made
that the rule — "no capability seam can set one" — and the Accounts screen was built to it.

The consequence showed up in the dev fleet. An `admin` can create a human Account in the
Console, give it a role, and enable it, and that Account **can never sign in**. Its only other
way in is OAuth, and OAuth has never run live against a real identity provider (#351; the human
OIDC browser flow is unbuilt, `12-login.md`). So today the Console has exactly one human user
per Relay, and every other person who should use it either shares the founding admin's
password or does not use it at all. Sharing a password destroys the per-human attribution that
was the Console's reason to have its own sign-in (ADR-0009).

On `2026-10-21` the owner decided that a signed-in human may change only their own password,
and left open how a Console-created human gets a *first* one. On `2026-10-22`, amending that,
the owner decided:

1. **The first admin** sets their password through `relay init` (unchanged).
2. **A new human Account** gets a **temporary password** from the `admin` who creates it, in
   the create flow.
3. **The first sign-in with a temporary password** goes straight to a change-password form,
   before anything else, so the admin never knows the person's real password.
4. **A signed-in human changes only their own password** in the Console, proving the current
   one. There is no admin reset of someone else's password beyond the temporary one at
   creation.
5. **Each change is recorded** on Access — time, actor, subject Account, source address — and
   never the password or its hash.
6. **Invariant 11 is clarified, not amended.** Setting a temporary password at creation and a
   self-service change are credential *issuance*, like minting an API Token in the Console; they
   do not change the *terms* on which credentials are accepted. First-admin bootstrap stays
   host-side.

The rationale the owner gave: password sign-in stays because OAuth/OIDC is not working yet, and
password sign-in is the only way a second human can use the Console.

This ADR writes those down, and settles the specifics they left open. Each specific below
marked **(proposed)** was settled in drafting, not by the owner, and is confirmed or overturned
by the human who merges this ADR.

## The decision

1. **Creating a human Account in the Console issues it a temporary password.** The `admin`
   creating the Account takes the act; the Relay generates the value — long, random, from the
   same source as an API Token's secret — and the create response shows it **once**, in the
   response body, with `Cache-Control: no-store`, never in a URL, a `Location` header or a
   browser history entry: the reveal-once discipline of an API Token mint, and the one other
   write on the Accounts screen that does not post-redirect-get (`15-accounts-and-tokens.md`).
   The admin passes it to the person out of band. **(proposed: generated rather than typed by
   the admin.)** A typed temporary password is a secret the admin chose, which people pattern
   and reuse across the Accounts they create; a generated one is unguessable for the window it
   is live, and the admin still never learns the real password because of decision 3.
   Every human Account created in the Console receives one **(proposed)**; a human who should
   sign in only through OAuth simply never redeems it, and it expires. A machine Account never
   has a password, from any surface.

2. **Setting it is part of the create act, and takes that act's step-up.** Creating an Account
   is already a privilege-granting act that takes step-up, consulting the recent-authentication
   window (`15-accounts-and-tokens.md`, owner decisions `2026-09-19` and `2026-10-05`). The
   temporary password rides the same act and the same step-up; it adds no second prompt. The
   Account, its temporary password, and their audit records are written in one transaction, so
   an issuance that cannot be recorded is not made.

3. **A temporary password expires 72 hours after it is issued (proposed).** The lifetime is a
   constant in the Relay's code, not configuration (see *Invariant 11, read* for why). An
   expired temporary password is refused at sign-in with the one indistinguishable credential
   failure every other failure gets (`12-login.md`, "No user enumeration").

4. **While an Account has never set its own password, an `admin` may issue it a fresh temporary
   password (proposed).** This is the one place this ADR reaches past the owner's words, and it
   is flagged as such: the owner's item 4 allows no reset "beyond setting the temporary one at
   creation", and decision 3 makes a temporary password expire. Without a re-issue, a
   person who did not sign in within 72 hours — or whose message carrying the password was lost —
   has an Account that can never sign in, which is the failure this ADR exists to end. A
   re-issue is the same act as at creation: Console-only, `admin`, step-up, generated, shown
   once, recorded, and it replaces the previous temporary password. **Once the Account's human
   has set their own password, no surface sets it again.** If the owner rejects this, a person
   who misses the window gets a new Account.

5. **The first sign-in with a temporary password establishes a restricted session.** It reaches
   the change-password form and sign-out, and nothing else: every other Console route answers a
   `GET` with a redirect to the form and refuses any other method. It can take no granting act;
   its only step-up is the form's own proof of the current password (decision 7). It ends on the Console's ordinary session lifetimes. The form is the same form
   as the self-service change (decision 6), proving the temporary password as the current one,
   so a stolen restricted session alone cannot set the Account's password. A successful change
   rotates the session identifier and leaves an ordinary session; the temporary password stops
   being accepted at that moment.

6. **A signed-in human changes only their own password**, from the **your account** surface
   reached from the shell's signed-in block (`11-console-shell.md`), on a form holding the
   current password, the new password and its confirmation. No role, on any surface, sets
   another Account's password, except the temporary password of decisions 1 and 4.

7. **Proving the current password is a step-up, taken per act (proposed).** It is the step-up
   the glossary defines — re-proving presence against the session's own Account without ending
   the session — and it is recorded and throttled as one: `step_up`, `step_up_failed`,
   `step_up_throttled`, under the same progressive per-Account delay with no hard lockout
   (`12-login.md`). **The recent-authentication window never satisfies it.** A change is the one
   act by which a hijacked session could lock the human out of their own Account; inside the
   window it would need no password at all. A submitted current password is always verified in
   the request.

8. **The new password is bounded by length, and nothing else (proposed).** At least 12 bytes
   and at most 4096 — the bounds the Relay already enforces on the password `relay init` sets
   (12 because the sign-in throttle has no hard lockout, so an attacker gets slow, unlimited
   attempts; 4096 because the KDF's work is otherwise attacker-chosen). It must differ from the
   current password. There are no composition rules and no history beyond that, following NIST
   SP 800-63B. The confirmation must match. The same bounds apply on the forced change.

9. **A change ends the Account's other Console sessions and rotates this one (proposed).** Every
   other Console session of the Account is ended at the change, so a human who changes their
   password because they suspect a hijacked session evicts it. This session's identifier is
   rotated, as on every successful step-up. API Tokens are untouched: revoking one remains its
   own act on the Accounts screen, and a password change is not a token compromise response.

10. **Each issuance and each change is a row on Access.** Two record kinds join the `account`
    kind on `20-access.md`, each carrying the time, the verified actor, the subject Account's
    ID, and the source address, and **never the password, the temporary password, or either
    hash**:
    - `password_temporary_set` — an `admin` issued a temporary password, at creation or by
      re-issue. The actor is the admin; the subject is the new Account.
    - `password_change` — a human set their own password. Actor and subject are the same
      Account; the record says whether it redeemed a temporary password (`forced=true`) or
      replaced the human's own (`forced=false`), and how many other sessions it ended.
    Each is written in the transaction that makes the change. The proof of the current password
    writes its step-up row as well (decision 7).

11. **Console only (proposed).** The capability layer holds both acts; the Admin Console is the
    only adapter that exposes them. The Control API creates human Accounts without a temporary
    password and exposes no password act, and MCP exposes no Account administration at all. An
    API Token carries no step-up, so a bearer token — including an AI-agent's on an `admin`
    machine Account — could otherwise mint a human identity with a password it holds. This is
    the narrowing invariant 10 allows an adapter, as ADR-0010's 2026-09-15 amendment did for the
    reach-bounding settings.

## Invariant 11, read

Invariant 11: *neither a credential nor the Relay itself can change the terms on which
credentials are accepted.* The security floor is the configuration that bounds *who may
authenticate, and how recently they proved it* — listeners, which CA and TLS material, auth
bootstrap, the identity provider, session and step-up windows, `console_execution`, the approval
notification path.

The owner's reading, recorded here so no later change has to re-derive it:

- **A password is a credential, issued under the terms; it is not a term.** The terms are which
  kinds of credential the Relay accepts, against which trust roots, with what proof of recency.
  Issuing a credential under them changes none of them. That is how the Relay has always treated
  an API Token, which an `admin` mints in the Console behind step-up, and an Account, which an
  `admin` creates there. Were "who may authenticate" to mean the set of credential holders,
  every Account create and every token mint would be floor, and no reading of the invariant has
  ever said that.
- **Auth bootstrap stays host-side.** The first credential, when no human Account exists, is
  still made only by `relay init` on the Relay's host (ADR-0030). Every act in this ADR needs an
  authenticated human session already holding a credential, and the issuing act needs step-up
  on top. No unauthenticated request issues a credential, and the setup-code alternative
  ADR-0030's 2026-10-16 amendment rejected stays rejected.
- **The terms these acts run under are not writable.** The KDF and its parameters, the length
  bounds, the temporary password's lifetime, the restricted session, and the throttle are fixed
  in the Relay's code; the session and step-up windows they consult are floor values in the
  Relay's configuration file. No surface writes any of them. **Were any of them made
  configurable, it would bound how a credential is accepted and so belong to the floor** —
  which is why the temporary password's lifetime is a constant and not a setting.

The invariant text in `AGENTS.md` is unchanged. The threat model's invariant-11 row records this
reading.

## Why

1. **A Console with one human user is not the Console ADR-0009 designed.** Per-human identity,
   per-human attribution and per-human revocation were the reasons the Console has its own
   sign-in instead of a shared token. A deployment where every human signs in as the founding
   admin has none of them.
2. **OAuth is the intended answer and is not available.** The human OIDC browser flow is unbuilt
   and OAuth has not run against a real identity provider (#351). Waiting for it would leave
   every Console-created human Account unusable for an unknown time.
3. **The admin never holds the person's real password.** A temporary password the admin issues,
   redeemed by a forced change, gives the person a working first sign-in without making the
   admin a standing holder of their credential, and without any reset path that would let one
   human take over another's Account.
4. **Changing your own password is ordinary hygiene, and the only lever a human has.** Without
   it, a human who suspects their password is known can do nothing short of asking an admin to
   disable their Account.

## Consequences

- **A hijacked `admin` session can mint a new Console identity.** With step-up (or inside the
  recent-authentication window), it can create a human Account and read its temporary password
  from the response. That is the reach a hijacked admin session already has — it can create an
  `admin` machine Account and mint an API Token for it today — now with a Console identity
  rather than only an API one. It is bounded the same way: `admin`, step-up, every act a row on
  Access attributed to the verified admin. `docs/security/threat-model.md` records it under the
  **Hijacked Console session** adversary.
- **A hijacked session cannot change its victim's password.** The current password is proved per
  act and the window never stands in for it (decision 7). Conversely, a human who changes their
  password ends every other session of their Account (decision 9): a new recovery lever.
- **A temporary password in transit is a live credential for up to 72 hours.** It travels by
  whatever channel the admin uses — chat, a ticket — and anyone who reads it there can sign in
  before the person does. What it reaches is a restricted session that can only set the
  Account's password, after which the real owner's sign-in fails and the admin sees both a
  `password_change` row and a confused colleague. Accepted on the bound of the lifetime and the
  restricted session; the admin re-issues (decision 4) or disables the Account.
- **A forgotten password is not recoverable by anyone else.** No admin reset exists, by the
  owner's decision. A human who forgets a password they set has their Account disabled and is
  given a new one; the founding admin who forgets theirs, with no other `admin`, has no Console
  until OAuth works — `relay init --recover` re-mints an API Token and never touches a password,
  as before. Stated plainly because it is the cost of the owner's item 4.
- **ADR-0030's boundary is unchanged.** The `relay` binary gains no verb, and every act here is
  on a credentialed surface, which is where ADR-0030 put everything that is not the first
  credential. ADR-0030 carries a dated note saying so.
- **Consumers updated with this ADR:** `docs/design/console/15-accounts-and-tokens.md` (the
  temporary password in New account, the re-issue, and *Your own password* moved from pending to
  designed); `12-login.md` (the forced change and the restricted session; its "admin-mediated
  reset" fallback withdrawn); `20-access.md` (the two record kinds); `11-console-shell.md` (the
  signed-in block's link); `99-open-decisions.md` (D36 amended, D37 recorded); the Console
  `README.md`; `GLOSSARY.md` (**Temporary password**); `docs/security/threat-model.md` (the
  invariant-11 row and the Hijacked Console session adversary); ADR-0030 (a dated note); and
  `docs/specs/accounts-and-access.md`, an aspirational spec, with a note where it describes an
  admin reset.
- **Named as consumers, not edited here:** `docs/operations/relay-install.md`,
  `docs/operations/control-plane-credential.md` and `docs/dev-fleet.md` say the password
  `relay init` sets is the only Console password any surface sets. That is true until the
  implementation lands, and they change in the PR that makes it false.

## Alternatives considered

**Keep passwords host-only; Console-created humans are OAuth-only.** The 2026-09-19 decision,
and the first option #1107 put to the owner. Rejected because OAuth does not work yet, so it
means one human user per Relay for an unknown time.

**An admin reset of any Account's password.** The direct reading of "change an Account's
password from the Account page" (#1109), and what `docs/specs/accounts-and-access.md` described.
Rejected by the owner on `2026-10-21` and again on `2026-10-22`: it lets one human's credential
set another's, which is an Account-takeover path behind nothing stronger than the step-up the
attacker may already be inside. The temporary password is the narrowest version of it — only an
Account whose human has never set a password, and redeemed by a forced change.

**A one-time setup link instead of a temporary password.** The same shape as a temporary
password with a URL around it, and the link is a credential in a URL, which the Console's
reveal-once rule forbids. It also invites an emailed delivery, which `12-login.md` already
rejects as weaker than the sign-in it protects. Rejected.

**Let the window satisfy the self-service change.** Consistent with the four privilege-granting
Account acts (owner decision `2026-10-05`). Rejected for the change alone: those acts grant
authority to someone else and are audited for review; a password change takes the Account away
from its owner, and inside the window it would need nothing but the session.
