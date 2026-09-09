# CA key custody & disaster posture

The Relay hosts the fleet's private certificate authority (ADR-0006): an ECDSA
P-256 CA that signs every Node identity certificate at enrollment and renewal,
and the Relay's own server certificates. This document covers what that key is,
how to protect it, and the compromise runbook — whose end state, "burn it down",
is deliberately just a re-run of the enrollment playbook
([enrollment.md](enrollment.md)) against a fresh CA.

## What is on disk

The CA lives in the Relay's `-ca-dir` / `RELAY_CA_DIR` (default `./ca-data`;
production example `/var/lib/relay/ca`), created automatically on first Relay
start (`relay/internal/ca`):

| File | Perms | Contents |
|---|---|---|
| *(the directory)* | `0700` | |
| `ca-key.pem` | `0600` | The CA private key. **The crown jewel** — whoever holds it can mint a certificate for any `node_id` and impersonate any Node to the Relay, or impersonate the Relay to the fleet. |
| `ca-cert.pem` | `0644` | The CA certificate (10-year validity). Public: this is the pinned bootstrap bundle distributed to Nodes as `ca-bundle.pem` and the trust anchor control-plane clients use. |

Facts that bound the blast radius, useful when reasoning about incidents:

- **Node identity certificates are short-lived** (~14 days, auto-renewed over
  mTLS with jitter). A leaked *Node* key ages out fast — revoke the Node
  (`POST /api/v1/nodes/{node_id}/revoke` with a JSON body `{"reason": "..."}`,
  required as of #487; instant Relay-side refusal) and move on. Only a leaked
  *CA* key calls for the full runbook below.
- **A stolen CA key alone does not grant execution.** A forged Node cert lets an
  attacker *be a Node* (receive what that Node would receive, feed false
  results), and a forged server cert plus a network position lets them
  impersonate the Relay — but every real Node's Policy is local and
  deny-by-default (ADR-0002), and an impersonated Relay still cannot push
  Policy, labels in the `relay:` namespace, or binaries. Bad — but bounded.
- **The Relay refuses to start on a half-present CA** (key without cert or vice
  versa) rather than silently regenerating and orphaning every issued cert.

## Custody rules

1. **Permissions are enforced by creation, kept by discipline.** The CA is
   created `0700`/`0600`; nothing should ever loosen that. The `-ca-dir` must be
   readable only by the Relay's runtime user (the example unit in
   [relay-install.md](relay-install.md) keeps it under `StateDirectory` mode
   `0700`).
2. **Back up `ca-key.pem` — encrypted, offline, out-of-band.** Without a backup,
   losing the Relay host means the "burn it down" runbook (every Node
   re-enrolls). With one, host loss is a restore: put the two files back in
   `-ca-dir` on a rebuilt host and the fleet reconnects as if nothing happened.
   Encrypt the backup to an offline key (e.g. `age`/GPG to a hardware token) and
   store it where a Relay-host compromise cannot reach it. Back up the store
   (`-store-path`) alongside it — registry, revocations, and audit live there.
3. **The key never travels otherwise.** Not in git, not in config management,
   not in logs (the `ca` package never logs, by design), not on operator
   laptops. Only `ca-cert.pem` is distributed — and its *integrity* still
   matters: it is what a first-boot Node trusts to identify the Relay, so it
   ships through reviewed config management like everything else
   ([enrollment.md](enrollment.md)).
4. **No cross-environment sharing.** A staging fleet gets its own Relay and its
   own CA; a compromise in one environment must not be a credential for
   another.

## Compromise runbook — "burn it down"

Treat the CA key as compromised if the Relay host is compromised, the key was
ever readable by an untrusted party, or a backup's encryption is in doubt. There
is no partial remedy — certificate-level revocation cannot outrun an attacker
who can mint new certs — so the recovery replaces the trust root outright. It is
designed to be boring: **a fresh CA plus the same enrollment playbook you
already ran.**

1. **Freeze first.** `kill -USR1 <relay-pid>` on the Relay host (or
   `POST /api/v1/freeze/engage`): all new dispatch halts fleet-wide while you
   work (ADR-0013). If the Relay host itself is the compromised asset, stop the
   Relay instead — a down Relay dispatches nothing.
2. **Stop the Relay.** No new certificates can be minted while it is down;
   existing Node certs age out within ~14 days regardless of what you do next.
3. **Retire the old CA.** Move the old `-ca-dir` aside for forensics (do not
   reuse any of it). Rotate the control-plane credential too
   ([control-plane-credential.md](control-plane-credential.md)) — assume
   everything on the host leaked. Invalidate old CA backups.
4. **Start the Relay clean.** On a rebuilt (or at minimum re-secured) host,
   start the Relay with an empty `-ca-dir`: it mints a fresh CA on startup.
   Every existing Node cert is now untrusted — the whole fleet is
   disconnected, which is the *point*: nothing signed by the old key works
   anywhere anymore. Keeping the existing store preserves the audit trail;
   old registry entries go stale and can be revoked or left to be superseded.
5. **Mint a fresh Enrollment Token** with the same scopes as the original
   rollout ([enrollment.md](enrollment.md)). Rotate the Vault entry.
6. **Re-run the enrollment playbook** against the whole fleet with two changed
   inputs: the new `ca-cert.pem` (pushed to `/etc/relay-daemon/ca-bundle.pem`)
   and the new token in the env file — **plus one extra task**: clear each
   Node's persisted identity so the daemon re-enrolls instead of retrying its
   now-worthless cert:

   ```yaml
   - name: Clear old identity (forces re-enrollment against the new CA)
     ansible.builtin.file:
       path: "/var/lib/relay-daemon/{{ item }}"
       state: absent
     loop: [key.pem, cert.pem, ca_bundle.pem, node_id]
     notify: restart relay-daemon
   ```

   Everything else — binary, unit, Policy — is already in place and untouched.
   Each Node enrolls as a new `node_id` with fresh relay-space Labels from the
   token scope; Policy never left the Nodes (ADR-0002), so enforcement is
   identical the moment they reconnect.
7. **Verify and thaw.** Confirm the fleet via `list_nodes` (expected count,
   fresh `last_seen`, correct `relay:` labels, uniform Policy fingerprints —
   [policy-as-code.md](policy-as-code.md)), then release the Freeze with an
   audited reason (`kill -USR2`, or `POST /api/v1/freeze/release` with a
   `reason`).

The reason this runbook stays cheap: enrollment was built for config-management
loops from day one (ADR-0006), so "re-key the entire fleet" is not a special
disaster procedure — it is the normal bulk-enrollment path with a fresh trust
root. Keeping the enrollment playbook rehearsed (it ran at least once, at fleet
bring-up) *is* the disaster preparedness.

## What this does not cover (yet)

- **No CRL/OCSP.** Node revocation is a Relay-side denylist (instant, persisted)
  plus passive ~14-day cert expiry; there is no certificate-level revocation
  infrastructure — another reason CA compromise ends in full re-key rather than
  selective revocation.
- **No CA key rotation short of re-enrollment.** A planned root rotation uses
  the same runbook, minus the forensics and minus the freeze urgency.
- **No HSM/KMS custody.** The key is a `0600` PEM on the Relay host today;
  hardware-backed custody would be a future hardening step.
