# Enrollment workflow

How Nodes join the fleet: minting a scoped Enrollment Token, enrolling one Node by
hand, and bulk-enrolling a fleet through config management (ADR-0006). Companion
documents: [relay-install.md](relay-install.md),
[relay-daemon-install.md](relay-daemon-install.md),
[ca-disaster-recovery.md](ca-disaster-recovery.md) — whose "burn it down" recovery
is exactly a re-run of the playbook in this document.

## How enrollment works (ADR-0006, in brief)

A Node enrolls by presenting a **reusable, scoped, expiring, revocable Enrollment
Token** over server-authenticated TLS (no client certificate yet — `Enroll` is the
single certless RPC) together with a CSR. The Relay validates the token, generates
the `node_id` itself (the CSR subject is discarded — a daemon can never choose its
own identity), signs a ~14-day client certificate with `CN = node_id`, and stamps
the token's scope as relay-space Labels on the new registry entry. Everything after
that first RPC is mTLS; renewal is automatic and never uses a token again.

The token is the *enrollment* credential, distinct from the per-Node *identity*
certificate: it can only enroll, never run Operations. One reusable token lets
config management register hundreds of Nodes in a loop while each Node still
receives its own certificate. The risk of reuse is bounded by short TTL, scope,
`max_uses`, and instant revocation.

## 1. Mint a token

`POST /api/v1/enrollment-tokens` on the Relay's control plane (bearer-credential
auth; [control-plane-credential.md](control-plane-credential.md)):

```console
$ curl --cacert ca-cert.pem \
    -H "Authorization: Bearer $CONTROL_PLANE_CREDENTIAL" \
    -H "Content-Type: application/json" \
    -d '{"scope": ["relay:env=prod", "relay:cohort=web"], "ttl_seconds": 86400, "max_uses": 200}' \
    https://relay.example.internal:9443/api/v1/enrollment-tokens
{
  "id": "3f8a…",
  "token": "3f8a….K7m2…",
  "scope": ["relay:env=prod", "relay:cohort=web"],
  "expires_at": "2026-08-10T12:00:00Z",
  "max_uses": 200
}
```

- **`scope`** — required, non-empty, every entry `relay:`-prefixed with a
  non-empty bare key and a (possibly empty) value whose every byte is in
  `[A-Za-z0-9._-]`; a violating entry is refused with `400` and never
  sanitised (#555). These become the Node's relay-space Labels:
  Node-immutable, reserved for the security-sensitive lane (quarantine,
  remediation, secret-distribution targeting). A token scoped to
  `relay:env=prod` makes every Node it enrolls *provably* prod for that lane,
  with no per-Node human labeling. A token minted before this rule existed
  whose scope violates it is now refused at enrollment — with the ordinary
  "enrollment token rejected" every other rejection returns — rather than
  stamping a malformed label; mint a replacement token.

  **Before upgrading, check your existing scopes.** The rule is narrower than
  what the Selector parser accepts, so a scope like `relay:tier=pci/1` worked
  and matched before and is refused now. Two things change on upgrade, and
  the second is the one to plan for:

  1. Tokens whose scope violates the rule stop enrolling. Re-mint them.
  2. Nodes **already enrolled** under such a scope keep their stored label in
     the database, but the Relay stops SERVING it — it disappears from the
     Console, the Control API and MCP, and from Selector matching. A
     security-lane Selector such as `relay:tier=pci/1` will then resolve to
     fewer Nodes than it did before, with nothing logged at the moment it
     happens. Nothing is deleted and no quarantine can be lost (`quarantine`
     and `on` are both inside the allowlist), but targeting does change.

  Audit with `GET /api/v1/nodes` before you upgrade and compare the
  `relay_labels` you get back afterwards; re-enrol any Node whose label the
  new rule refuses, under a re-minted, conforming scope.
- **`ttl_seconds`** — required, `> 0`, at most one year. Size it to the
  enrollment window, not to convenience: for a planned bulk run, hours or a day.
- **`max_uses`** — optional; `<= 0` or absent means unlimited. For a planned run
  of N Nodes, set it a little above N.
- **`token`** — the plaintext credential (`<id>.<secret>`), returned exactly
  once, never persisted or logged by the Relay (it stores only the secret's
  hash). Put it straight into your secret store (e.g. Ansible Vault).

Revoke a token at any time — this also cascade-revokes every Node it enrolled:

```console
$ curl --cacert ca-cert.pem \
    -H "Authorization: Bearer $CONTROL_PLANE_CREDENTIAL" \
    -X DELETE https://relay.example.internal:9443/api/v1/enrollment-tokens/<id>
```

## 2. Enroll one Node by hand

Install the daemon per [relay-daemon-install.md](relay-daemon-install.md), with an
env file carrying the token and the pinned bootstrap CA bundle (the Relay's
`ca-cert.pem` — no secrets in it, but its *integrity* matters: it is what stops a
MITM from impersonating the Relay to a first-boot Node):

```sh
# /etc/relay-daemon/relay-daemon.env   (0600 root:root)
RELAY_ADDR=https://relay.example.internal:7654
RELAY_CA_BUNDLE_PATH=/etc/relay-daemon/ca-bundle.pem
RELAY_POLICY_PATH=/etc/relay-daemon/policy.toml
RELAY_NODE_LABELS=env=prod,role=web,site=us-east-1
RELAY_ENROLLMENT_TOKEN=3f8a….K7m2…
```

```console
$ sudo systemctl enable --now relay-daemon
$ journalctl -u relay-daemon | tail
# first run: enrollment, identity persisted to /var/lib/relay-daemon,
# then mTLS connect and "received Ping from Relay"
```

Enrollment is idempotent: once an identity exists in the state dir, restarts skip
enrollment entirely and the token in the env file is unused (it can be removed
after the first success — the bulk playbook below leaves that to token expiry).

Note the two Label namespaces at work: `RELAY_NODE_LABELS` become node-space
(`node:…`) Labels — node-rooted, Relay-immutable, for routine targeting — while
the token's scope became relay-space (`relay:…`) Labels the Node can never alter.

Each `RELAY_NODE_LABELS` key and value must match `[A-Za-z0-9._-]+` (an empty
value is fine — a bare `role` entry is a legitimate marker). A pair outside that
alphabet is REFUSED at enrollment — the whole request fails, with no
certificate and no registry row, so a human watching the install sees it
immediately — and DROPPED at reconnect, where only that one label is omitted
and the Node stays connected. Neither case sanitises the value into something
it never was: a label the Relay cannot render as a single Selector term is
refused, not rewritten (#504).

## 3. Bulk enrollment via config management

One reusable scoped token + a loop over inventory. An Ansible-flavored role
(tasks abbreviated; the artifact pin and digest live in group_vars, the token in
Vault):

```yaml
# group_vars/prod.yml
relay_daemon_version: "0.1.0-beta"
relay_daemon_sha256: "<digest copied from SHA256SUMS at pin time>"
relay_addr: "https://relay.example.internal:7654"
relay_enrollment_token: "{{ vault_relay_enrollment_token }}"
```

```yaml
# roles/relay_daemon/tasks/main.yml
- name: Fetch relay-daemon artifact (digest verified BEFORE install)
  ansible.builtin.get_url:
    url: "https://github.com/Felag-Engineering/gleipnir-relay/releases/download/\
          v{{ relay_daemon_version }}/relay-daemon-{{ relay_daemon_version }}-x86_64-unknown-linux-musl"
    dest: /usr/local/bin/relay-daemon
    mode: "0755"
    # Operator-pinned digest, not fetched at install time: a mismatch fails the
    # task before the file is moved into place (verify-then-install,
    # release-artifacts.md).
    checksum: "sha256:{{ relay_daemon_sha256 }}"

- name: Install hardened systemd unit
  ansible.builtin.copy:
    src: relay-daemon.service        # daemon/packaging/relay-daemon.service
    dest: /etc/systemd/system/relay-daemon.service
    mode: "0644"

- name: Install pinned bootstrap CA bundle
  ansible.builtin.copy:
    src: ca-cert.pem                 # the Relay CA's public certificate
    dest: /etc/relay-daemon/ca-bundle.pem
    owner: root
    group: root
    mode: "0644"

- name: Install Policy (root-owned, never group/world-writable)
  ansible.builtin.copy:
    src: "{{ relay_policy_file }}"   # from the IaC repo; see policy-as-code.md
    dest: /etc/relay-daemon/policy.toml
    owner: root
    group: root
    mode: "0644"
  notify: restart relay-daemon

- name: Write env file (carries the Enrollment Token — 0600, from Vault)
  ansible.builtin.template:
    src: relay-daemon.env.j2
    dest: /etc/relay-daemon/relay-daemon.env
    owner: root
    group: root
    mode: "0600"
  no_log: true

- name: Enable and start relay-daemon
  ansible.builtin.systemd:
    name: relay-daemon
    enabled: true
    state: started
    daemon_reload: true
```

```jinja
{# roles/relay_daemon/templates/relay-daemon.env.j2 #}
RELAY_ADDR={{ relay_addr }}
RELAY_CA_BUNDLE_PATH=/etc/relay-daemon/ca-bundle.pem
RELAY_POLICY_PATH=/etc/relay-daemon/policy.toml
RELAY_NODE_LABELS=env={{ relay_env }},role={{ relay_role }}
RELAY_ENROLLMENT_TOKEN={{ relay_enrollment_token }}
```

Run it across the fleet:

```console
$ ansible-playbook -i inventory/prod site.yml --limit 'new_nodes'
```

Each Node enrolls itself on first daemon start; already-enrolled Nodes are no-ops.
The Relay rate-limits enrollment (per-IP and globally —
[relay-install.md](relay-install.md)); for very large batches raise
`RELAY_ENROLL_GLOBAL_RATE` for the window or let the daemons' retry/backoff spread
the burst.

## 4. Verify the rollout

From an MCP client (or any Control API consumer), `list_nodes` shows every
enrolled Node with its Labels (node-space and relay-space reported separately),
Facts, `last_seen`, and Policy fingerprint:

- every expected Node present, `relay:env=prod` stamped from the token's scope;
- `policy_fingerprint` uniform across the cohort
  ([policy-as-code.md](policy-as-code.md));
- `outdated: false` everywhere, when a minimum daemon version is set
  ([iac-upgrades.md](iac-upgrades.md)).

The mint and every enrollment are in the audit trail, attributed to the token id.

## 5. After the window

- Let the token **expire** (its TTL was sized to the window), or revoke it
  explicitly if it is no longer needed — remembering that revoking a token
  cascade-revokes the Nodes it enrolled, so explicit token revocation is for
  "that token/batch should not exist", not routine cleanup.
- Rotate the Vault entry; nothing on the Nodes needs it again.
- Single-Node removal is `POST /api/v1/nodes/{node_id}/revoke` — instant refusal
  at the Relay, independent of certificate expiry. It requires a JSON body
  `{"reason": "..."}` saying why (#487); without one it answers 400 and revokes
  nothing.
