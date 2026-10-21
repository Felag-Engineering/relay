# 12 — Login

**No artboard.** The only unauthenticated surface in the Console. **Milestone v0.6.0.**

**Governing:** ADR-0009, ADR-0010, ADR-0024.
**Backend:** the Account model — local password hashed at rest, optional OIDC; session issuance;
audit.

## What this screen is for

Establishing a **per-human identity** that every subsequent action is attributed to. ADR-0009
rejected reusing the MCP static admin token for humans because it yields no per-human identity, RBAC or audit.

## The screen

Deliberately plain: product name, username, password, sign in. An OIDC button when a provider is
configured. Nothing else — no marketing, no version string, no fleet statistics, no links that
reveal whether this deployment exists or how big it is.

## Local password

Local username/password is the **baseline**, so small fleets without an IdP can use the Console;
OIDC is an additional method, not a replacement (ADR-0009, which accepts that the Relay holds
password hashes).

- Hashed at rest with a memory-hard KDF. Never logged, never echoed, never in a URL.
- **No user enumeration.** A wrong username and a wrong password produce the same message and the
  same response time.
- Throttled per source and per Account. Defaults: per source, 10 failures a minute then `429`
  with backoff; per Account, a **progressive delay** that doubles per consecutive
  failure and caps at 60s. **No hard lockout**: a lockout lets an attacker lock the admin out of
  the Console during the incident they are causing, which is worse than the brute force it
  prevents. Every throttled attempt is audited.

## Sessions

Issue the session per `11-console-shell.md`. **Rotate the session identifier on login** — a fixed
identifier across the authentication boundary is session fixation.

No "remember me" that survives the absolute lifetime, and no persistent token that bypasses
**step-up**: step-up is the intent binding the entire execution surface rests on (ADR-0026), and a
convenience that pre-satisfies it removes the control.

## OIDC

Optional and additional (ADR-0024 covers the resource-server side for machine callers; this is the
human browser flow). Standard authorization-code flow with PKCE, state and nonce verified. Map the
provider's identity onto an Account that already exists — **provisioning an Account as a side
effect of a successful login is an unreviewed grant of access**, and roles come from the Account
model, not from a token claim, until IdP-group federation is designed.

## Audit

Every attempt, successful or not, with source address and method. Sign-out too. This is the first
link in the chain `ui-advisory.md` requires end-to-end: **login → action → audit record**.

## Must not appear

- Any hint of whether a username exists.
- Any fleet or deployment information before authentication.
- A password field that is not `type="password"` with autocomplete hints set appropriately.
- A "reset password" flow weaker than the login it protects. If self-service reset is not designed,
  the answer is an admin-mediated reset, not a mail-a-link stopgap.

## States

- **Already signed in** → redirect to the saved view.
- **Session expired mid-action** → return here with a message saying what was interrupted, then
  back to where they were. Do not silently discard the work.
- **Slowed down** → say so plainly, and when the next attempt is accepted; do not pretend the
  password was wrong.
- **OIDC configured** → both methods offered; neither is presented as the "insecure" one.

## Acceptance

- [x] Wrong username and wrong password are indistinguishable in message and timing.
- [x] The session identifier changes on successful login.
- [x] Every attempt is audited with source and method.
- [x] No route other than login, its assets and health is reachable unauthenticated. The one
      exception is a fixed redirect: with the Console mounted, exactly `GET /` answers `302` to
      `/console/` before authentication runs. It reads no credential and its target is
      constant, so it reveals only that the Console is there, which `/console/` already does
      (`TestRootRedirect_AnswersExactlyGetRoot`,
      `TestE2E_RootRedirectsToTheConsoleOnlyWhenItIsMounted`).
- [x] No persistent credential satisfies step-up.
- [ ] A successful OIDC login for an unknown subject is refused, not auto-provisioned.
      **Not implemented.** The human OIDC browser flow is unbuilt, so this is untested rather
      than met. ADR-0024's resource-server half (machine callers) exists.
- [x] Repeated failures slow an Account down and never lock it out; the delay is visible and audited.
