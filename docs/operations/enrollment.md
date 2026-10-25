# Enrollment workflow

How Nodes join the fleet: minting a scoped Enrollment Token, enrolling one Node by hand, and
bulk-enrolling a fleet through config management (ADR-0006). See also
[relay-install.md](relay-install.md), [relay-daemon-install.md](relay-daemon-install.md), and
[ca-disaster-recovery.md](ca-disaster-recovery.md), whose "burn it down" recovery is a re-run
of the playbook in this document.

## How enrollment works (ADR-0006, in brief)

A Node enrolls by presenting a **reusable-by-choice, scoped, expiring, revocable Enrollment Token** and a
CSR over server-authenticated TLS (`Enroll` is the single certless RPC). The Relay validates
the token, generates the `node_id` itself (the CSR subject is discarded, so a daemon can never
choose its own identity), signs a ~14-day client certificate with `CN = node_id`, and stamps
the token's scope as relay-space Labels on the new registry entry. Everything after that first
RPC is mTLS; renewal is automatic and never uses a token again.

The token can only enroll, never run Operations. One reusable token lets config management
register hundreds of Nodes in a loop while each Node still gets its own certificate. Short
TTL, scope, `max_uses`, and instant revocation bound the risk of reuse.

## 1. Mint a token

`POST /api/v1/enrollment-tokens` on the Relay's control plane (`$RELAY_TOKEN` is an API
Token; [control-plane-credential.md](control-plane-credential.md)):

```console
$ curl --cacert ca-cert.pem \
    -H "Authorization: Bearer $RELAY_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"scope": ["relay:env=prod", "relay:cohort=web"], "ttl_seconds": 86400, "max_uses": 200}' \
    https://relay.example.internal:9443/api/v1/enrollment-tokens
{
  "id": "3f8a…",
  "token": "3f8a….K7m2…",
  "join_string": "glp_join_…",
  "scope": ["relay:env=prod", "relay:cohort=web"],
  "expires_at": "2026-08-10T12:00:00Z",
  "max_uses": 200,
  "unlimited": false
}
```

- **`scope`** — required and non-empty. Every entry is `relay:`-prefixed, with a non-empty
  bare key and a (possibly empty) value whose every byte is in `[A-Za-z0-9._-]`; a violating
  entry is refused with `400`, never sanitised. These become the Node's relay-space Labels:
  Node-immutable, reserved for the security lane (quarantine, remediation,
  secret-distribution targeting). A token scoped to `relay:env=prod` makes every Node it
  enrolls *provably* prod for that lane, with no per-Node labeling. Upgrading a Relay whose
  existing tokens or Nodes carry scopes outside this alphabet: see
  [Scopes from an earlier Relay](#scopes-from-an-earlier-relay).

  **Changing in the MVP (ADR-0050).** A mint will name optional **initial tags** (`tag:`
  labels) in place of a `relay:` scope. The enrollment writes them on each Node it enrolls,
  and an `operator` can change them afterwards like any tag. A mint naming a `relay:` label
  will be refused, naming it; every Node gets `relay:node-id` from the enrollment itself. This
  runbook describes the release you run until then.
- **`ttl_seconds`** — required, `> 0`, at most one year. Size it to the enrollment window: for
  a planned bulk run, hours or a day.
- **`max_uses`** — required unless `unlimited` is true; a positive number of Nodes. For a
  planned run of N Nodes, set it a little above N.
- **`unlimited`** — `true` asks explicitly for unlimited use within the TTL; exclusive with a
  positive `max_uses`. A mint naming neither is refused with `400`.
- **`token`** — the plaintext credential (`<id>.<secret>`), returned exactly once and never
  persisted or logged by the Relay, which stores only the secret's hash. Put it straight into
  your secret store (e.g. Ansible Vault).
- **`join_string`** — the token wrapped with the Relay's advertised node-plane address and the
  SHA-256 fingerprint of its CA certificate. A secret, returned once, here only. A Node
  enrolls with it: the daemon reads it from `RELAY_JOIN`, pins the Relay's CA from the
  fingerprint before sending the token, and needs no CA file configured by hand.

Revoke a token at any time. This also cascade-revokes every Node it enrolled:

```console
$ curl --cacert ca-cert.pem \
    -H "Authorization: Bearer $RELAY_TOKEN" \
    -X DELETE https://relay.example.internal:9443/api/v1/enrollment-tokens/<id>
```

### Scopes from an earlier Relay

The scope rule is narrower than what the Selector parser accepts, so a scope like
`relay:tier=pci/1` was once accepted and is refused now. On upgrade:

1. Tokens whose scope violates the rule stop enrolling, with the ordinary "enrollment token
   rejected". Re-mint them.
2. Nodes **already enrolled** under such a scope keep their stored label, but the Relay stops
   serving it: it disappears from the Console, the Control API, MCP, and Selector matching. A
   security-lane Selector such as `relay:tier=pci/1` then resolves to fewer Nodes, with
   nothing logged when it happens. The quarantine label, `relay:quarantine=on`, is inside the
   alphabet and is kept.

Before upgrading, record `GET /api/v1/nodes` and compare the `relay_labels` you get back
afterwards; that comparison is the audit.

After an upgrade, the Relay names affected Nodes at every startup: a read-only scan logs each
as `stored label declined on read-back` (fields: `namespace`, `node_id`, `key`,
`key_truncated`, `malformed_part`), then a `startup scan: stored labels declined on read-back`
summary per non-empty namespace with `labels_declined_at_scan`/`nodes_affected_at_scan`
totals, `reported` (capped at 50 per namespace), and `truncated`. The declined **value** is
never logged: read it from the store row or the token scope you are re-minting.
`relay_labels_declined_total{namespace="relay"}` on `/metrics` is the ongoing signal between
startups, but it counts read-back *events*, not distinct Labels, and is traffic-driven: it
stays flat both when nothing is wrong and when nothing has read an affected Node.

**The log is a sample, not a roster.** If `truncated` is `true`, the scan named 50 findings
for that namespace and only counted the rest. The Control API cannot show a declined Label, so
enumerate the rest against the store:

```sh
# Every Node carrying a stored relay-space Label the Relay will not serve.
# Run against a COPY of the database, or with the Relay stopped: the Relay
# holds a single SQLite connection and this is a read you do not want to
# queue behind.
sqlite3 /var/lib/relay/relay.db \
  "SELECT node_id, key FROM relay_labels
    WHERE key GLOB '*[^A-Za-z0-9._-]*' OR value GLOB '*[^A-Za-z0-9._-]*' OR key = ''
    ORDER BY node_id, key;"
```

Swap `relay_labels` for `node_labels` for the other namespace, which self-heals on the Node's
next Hello and is usually less urgent. The `GLOB` pattern is the alphabet inverted, a
convenience for enumeration; `registry.WellFormedLabel` is the gate the Relay applies.

**Neither signal repairs anything.** Re-minting a conforming token and re-enrolling each
affected Node is the only fix.

## 2. Enroll one Node by hand

Install the daemon per [relay-daemon-install.md](relay-daemon-install.md), with an env file
carrying the join string from step 1. It holds the Relay's address, its CA fingerprint and the
token, so no CA file is copied to the Node; the fingerprint is what stops a MITM from
impersonating the Relay to a first-boot Node.

```sh
# /etc/relay-daemon/relay-daemon.env   (0600 root:root)
RELAY_JOIN=glp_join_…
RELAY_POLICY_PATH=/etc/relay-daemon/policy.toml
RELAY_NODE_LABELS=env=prod,role=web,site=us-east-1
```

A daemon with no identity and no `RELAY_JOIN` logs `no identity and no RELAY_JOIN: nothing to
enroll with` and exits 0, so systemd shows a clean stop. If `systemctl status relay-daemon`
says inactive after the first start, check the env file first.

```console
$ sudo systemctl enable --now relay-daemon
$ journalctl -u relay-daemon | tail
# first run: enrollment, identity persisted to /var/lib/relay-daemon,
# then mTLS connect and "received Ping from Relay"
```

Enrollment is idempotent: once an identity exists in the state dir, restarts skip enrollment
and `RELAY_JOIN` is unused. It can be removed after the first success; the bulk playbook below
leaves that to token expiry.

Two Label namespaces are at work: `RELAY_NODE_LABELS` become node-space (`node:…`) Labels,
node-rooted and for routine targeting, while the token's scope became relay-space (`relay:…`)
Labels the Node can never alter.

Each `RELAY_NODE_LABELS` key and value must match `[A-Za-z0-9._-]+` (an empty value is fine: a
bare `role` entry is a legitimate marker). A pair outside that alphabet is REFUSED at
enrollment (the whole request fails, with no certificate and no registry row, so the install
shows it at once) and DROPPED at reconnect (only that label is omitted and the Node stays
connected). Neither case rewrites the value: a label the Relay cannot render as a single
Selector term is refused.

## 3. Bulk enrollment via config management

One reusable scoped token and a loop over inventory. An Ansible-flavored role (tasks
abbreviated; the artifact pin and digest live in group_vars, the token in Vault):

```yaml
# group_vars/prod.yml
relay_daemon_version: "X.Y.Z"   # the published tag without its leading `v`
relay_daemon_sha256: "<digest copied from SHA256SUMS at pin time>"
relay_join: "{{ vault_relay_join }}"   # the join_string from the mint
```

```yaml
# roles/relay_daemon/tasks/main.yml
- name: Fetch relay-daemon artifact (digest verified BEFORE install)
  ansible.builtin.get_url:
    url: "https://github.com/Felag-Engineering/relay/releases/download/\
          v{{ relay_daemon_version }}/relay-daemon-{{ relay_daemon_version }}-linux-amd64"
    dest: /usr/bin/relay-daemon
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

- name: Install Policy (root-owned, never group/world-writable)
  ansible.builtin.copy:
    src: "{{ relay_policy_file }}"   # from the IaC repo; see policy-as-code.md
    dest: /etc/relay-daemon/policy.toml
    owner: root
    group: root
    mode: "0644"
  notify: restart relay-daemon

- name: Write env file (carries the join string — 0600, from Vault)
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
RELAY_JOIN={{ relay_join }}
RELAY_POLICY_PATH=/etc/relay-daemon/policy.toml
RELAY_NODE_LABELS=env={{ relay_env }},role={{ relay_role }}
```

Run it across the fleet:

```console
$ ansible-playbook -i inventory/prod site.yml --limit 'new_nodes'
```

Each Node enrolls itself on first daemon start; already-enrolled Nodes are no-ops. The Relay
rate-limits enrollment per IP and globally ([relay-install.md](relay-install.md)). For very
large batches, raise `enrollment.global_rate_per_minute` in `relay.toml` for the window (a
SIGHUP applies it), or let the daemons' retry and backoff spread the burst. In the MVP both
limits become fixed, with the per-IP limit raised to about 60 a minute, so some 200 Nodes
behind one NAT address join in minutes with no setting to change.

## 4. Verify the rollout

From an MCP client or any Control API consumer, `list_nodes` shows every enrolled Node with
its Labels (node-space and relay-space reported separately), Facts, `last_seen`, and Policy
fingerprint. Check:

- every expected Node is present, with `relay:env=prod` stamped from the token's scope;
- `policy_fingerprint` is uniform across the cohort ([policy-as-code.md](policy-as-code.md));
- `outdated: false` everywhere, when a minimum daemon version is set
  ([iac-upgrades.md](iac-upgrades.md)).

The mint and every enrollment are in the audit trail, attributed to the token id.

## 5. After the window

- Let the token **expire** (its TTL was sized to the window), or revoke it if it is no longer
  needed. Revoking a token cascade-revokes the Nodes it enrolled, so explicit revocation is for
  "that token or batch should not exist", not routine cleanup. Each cascaded Node gets its own
  revocation record, attributed to the revoking Account, with a reason naming the token.
- Rotate the Vault entry; nothing on the Nodes needs it again.
- Single-Node removal is `POST /api/v1/nodes/{node_id}/revoke`: instant refusal at the Relay,
  independent of certificate expiry. It requires a JSON body `{"reason": "..."}`; without one
  it answers 400 and revokes nothing.
