# CA key custody & disaster posture

The Relay hosts the fleet's private certificate authority (ADR-0006): an ECDSA P-256 CA that
signs every Node identity certificate at enrollment and renewal, and the Relay's own server
certificates. This document covers what that key is, how to protect it, and the compromise
runbook, whose end state ("burn it down") is a re-run of the enrollment playbook
([enrollment.md](enrollment.md)) against a fresh CA.

## What is on disk

The CA lives in the directory `ca.dir` names in `relay.toml` (a required key; the example is
`/var/lib/relay/ca`). The Relay creates it on first start (`relay/internal/ca`):

| File | Perms | Contents |
|---|---|---|
| *(the directory)* | `0700` | |
| `ca-key.pem` | `0600` | The CA private key. **The crown jewel** — whoever holds it can mint a certificate for any `node_id` and impersonate any Node to the Relay, or impersonate the Relay to the fleet. |
| `ca-cert.pem` | `0644` | The CA certificate (10-year validity). Public: the trust anchor control-plane clients use. Nodes pin it by the fingerprint in the join string and keep a copy as `ca_bundle.pem` in their state directory. |

Facts that bound the blast radius:

- **Node identity certificates are short-lived** (~14 days, auto-renewed over mTLS with
  jitter). A leaked *Node* key ages out fast: revoke the Node
  (`POST /api/v1/nodes/{node_id}/revoke` with a required JSON body `{"reason": "..."}`;
  instant Relay-side refusal) and move on. Only a leaked *CA* key calls for the runbook below.
- **A stolen CA key alone does not grant execution.** A forged Node cert lets an attacker *be
  a Node* (receive what that Node would receive, feed false results), and a forged server cert
  plus a network position lets them impersonate the Relay. But every real Node's Policy is
  local and deny-by-default (ADR-0002), and an impersonated Relay still cannot push Policy,
  `relay:` labels, or binaries. Bad, but bounded.
- **The Relay refuses to start on a half-present CA** (key without cert or vice versa) rather
  than silently regenerating and orphaning every issued cert.

## Custody rules

1. **Permissions are set at creation and kept by discipline.** The CA is created
   `0700`/`0600`; nothing should loosen that. `ca.dir` must be readable only by the Relay's
   runtime user (the example unit in [relay-install.md](relay-install.md) keeps it under
   `StateDirectory`, mode `0700`).
2. **Back up `ca-key.pem`: encrypted, offline, out-of-band.** Without a backup, losing the
   Relay host means the "burn it down" runbook (every Node re-enrolls). With one, host loss is a
   restore: put the two files back in `ca.dir` on a rebuilt host and the fleet reconnects.
   Encrypt the backup to an offline key (e.g. `age`/GPG to a hardware token) and store it where
   a Relay-host compromise cannot reach it. Back up the store (`store.path`) alongside it:
   registry, revocations, and audit live there.
3. **The key never travels otherwise.** Not in git, not in config management, not in logs (the
   `ca` package never logs), not on operator laptops. Only `ca-cert.pem` is distributed.
4. **No cross-environment sharing.** A staging fleet gets its own Relay and its own CA; a
   compromise in one environment must not be a credential for another.

## Compromise runbook — "burn it down"

Treat the CA key as compromised if the Relay host is compromised, the key was ever readable by
an untrusted party, or a backup's encryption is in doubt. There is no partial remedy:
certificate-level revocation cannot outrun an attacker who can mint new certs, so recovery
replaces the trust root outright. It is designed to be boring: **a fresh CA plus the same
enrollment playbook you already ran.**

1. **Freeze first.** `kill -USR1 <relay-pid>` on the Relay host (or
   `POST /api/v1/freeze/engage`): all new dispatch halts fleet-wide (ADR-0013). If the Relay
   host itself is compromised, stop the Relay instead: a down Relay dispatches nothing.
2. **Stop the Relay.** No new certificates can be minted while it is down; existing Node certs
   age out within ~14 days regardless.
3. **Retire the old CA.** Move the old `ca.dir` aside for forensics (reuse none of it). Rotate
   every API Token too: mint each caller a replacement and revoke the old one
   ([control-plane-credential.md](control-plane-credential.md)), assuming everything on the host
   leaked. Invalidate old CA backups.
4. **Start the Relay clean.** On a rebuilt (or at minimum re-secured) host, start the Relay
   with an empty `ca.dir`: it mints a fresh CA on startup. Every existing Node cert is now
   untrusted and the whole fleet disconnects, which is the *point*: nothing signed by the old
   key works anywhere. Keeping the existing store preserves the audit trail; old registry
   entries go stale and can be revoked or left to be superseded.
5. **Mint a fresh Enrollment Token** for the size of the fleet, with the same initial tags as
   the original rollout ([enrollment.md](enrollment.md)). Its join string carries the new CA's
   fingerprint. Rotate the Vault entry.
6. **Re-join the whole fleet** with the new join string, **after one extra task**: clear each
   Node's persisted identity, so the daemon joins again instead of retrying its now-worthless
   cert:

   ```yaml
   - name: Clear old identity (forces re-enrollment against the new CA)
     ansible.builtin.file:
       path: "/var/lib/relay-daemon/{{ item }}"
       state: absent
     loop: [key.pem, cert.pem, ca_bundle.pem, node_id]
     notify: restart relay-daemon
   ```

   Then run `sudo relay-daemon join` on every Node with the new join string fed from the
   operator's side, by the SSH loop or the release's Ansible role; the string never goes in a
   file on the Node ([enrollment.md](enrollment.md), ADR-0048). Binary, unit and Policy are
   already in place and untouched. Each Node enrolls as a new `node_id`, with a new
   `relay:node-id` and the token's initial tags; Policy never left the Nodes (ADR-0002), so
   enforcement is identical the moment they reconnect.
7. **Verify and thaw.** Confirm the fleet with `list_nodes` (expected count, fresh `last_seen`,
   correct tags, uniform Policy fingerprints;
   [policy-as-code.md](policy-as-code.md)), then release the Freeze with an audited reason
   (`kill -USR2`, or `POST /api/v1/freeze/release` with a `reason`).

The runbook stays cheap because enrollment was built for config-management loops (ADR-0006):
re-keying the fleet is the normal bulk-enrollment path with a fresh trust root. Keeping the
enrollment playbook rehearsed *is* the disaster preparedness.

## What this does not cover (yet)

- **No CRL/OCSP.** Node revocation is a Relay-side denylist (instant, persisted) plus passive
  ~14-day cert expiry, which is another reason CA compromise ends in a full re-key.
- **No CA key rotation short of re-enrollment.** A planned root rotation uses the same
  runbook, minus the forensics and the freeze urgency.
- **No HSM/KMS custody.** The key is a `0600` PEM on the Relay host; hardware-backed custody
  would be a future hardening step.
