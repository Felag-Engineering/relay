# Enrollment workflow

How Nodes join the fleet: minting an Enrollment Token that names initial tags, enrolling one Node by hand, and
bulk-enrolling a fleet through config management (ADR-0006). See also
[relay-install.md](relay-install.md), [relay-daemon-install.md](relay-daemon-install.md), and
[ca-disaster-recovery.md](ca-disaster-recovery.md), whose "burn it down" recovery is a re-run
of the playbook in this document.

## How enrollment works (ADR-0006, in brief)

A Node enrolls by presenting a **reusable-by-choice, expiring, revocable Enrollment Token** and a
CSR over server-authenticated TLS (`Enroll` is the single certless RPC). The Relay validates
the token, generates the `node_id` itself (the CSR subject is discarded, so a daemon can never
choose its own identity), signs a ~14-day client certificate with `CN = node_id`, stamps
`relay:node-id` on the new registry entry (the only `relay:` label enrollment writes), and
writes the token's **initial tags** on the Node as the minting Account's act. Everything after
that first RPC is mTLS; renewal is automatic and never uses a token again.

The token can only enroll, never run Operations. One reusable token lets config management
register hundreds of Nodes in a loop while each Node still gets its own certificate. Short
TTL, `max_uses`, and instant revocation bound the risk of reuse.

## 1. Mint a token

`POST /api/v1/enrollment-tokens` on the Relay's control plane (`$RELAY_TOKEN` is an API
Token; [control-plane-credential.md](control-plane-credential.md)):

```console
$ curl --cacert ca-cert.pem \
    -H "Authorization: Bearer $RELAY_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"initial_tags": ["tag:env=prod", "tag:cohort=web"], "ttl_seconds": 86400, "max_uses": 200}' \
    https://relay.example.internal:9443/api/v1/enrollment-tokens
{
  "id": "3f8a…",
  "token": "3f8a….K7m2…",
  "join_string": "glp_join_…",
  "initial_tags": ["tag:env=prod", "tag:cohort=web"],
  "expires_at": "2026-08-10T12:00:00Z",
  "max_uses": 200,
  "unlimited": false
}
```

- **`initial_tags`** — optional; zero or more tags, each `tag:key=value`, written as the first
  tags of every Node the token enrolls. The key is at most 63 bytes and the value at most 255,
  every byte in `[A-Za-z0-9._-]`; a key may be named once, at most 64 tags. A malformed entry is
  refused with `400`, never sanitised. A `relay:` label is refused with `400`, naming it,
  whoever mints: `relay:` labels are written only by the Relay action that defines them, and
  every Node gets `relay:node-id` from the enrollment itself. Only a **human** Account may
  name an initial tag: a machine Account naming any is refused with `403`, and a machine
  Account's mint naming none is unaffected. Once written, an initial tag is an ordinary tag:
  an `operator` changes or removes it like any other, and each one is a `tag_write` record in
  the audit trail attributed to the Account that minted the token. A request still sending the
  old `scope` field is refused as an unknown field with `400`; update any script that mints.
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
  enrolls with it: `relay-daemon join` reads it from a prompt or standard input, pins the
  Relay's CA from the fingerprint before sending the token, and needs no CA file configured by
  hand. It is never written to the Node or placed in an environment file.

Revoke a token at any time. This also cascade-revokes every Node it enrolled:

```console
$ curl --cacert ca-cert.pem \
    -H "Authorization: Bearer $RELAY_TOKEN" \
    -X DELETE https://relay.example.internal:9443/api/v1/enrollment-tokens/<id>
```

### Upgrading from a Relay that stamped a token's scope

An earlier Relay stamped a token's `scope` onto each Node as `relay:` labels. This Relay writes
the token's initial tags instead, and `relay:` keeps only Relay-defined keys. Migration 0033
runs once, at the first start, and converts what exists:

- **Copied to tags.** Every `relay:` label other than `relay:node-id`, on a Node enrolled by a
  token a **human** Account minted, is copied to a `tag:` label of the same key and value,
  attributed to that Account. Each copy is a `tag_write` record in the audit trail whose reason
  ends `(upgrade: copied from Enrollment Token <id> scope)`. The audit chain is extended, not
  rewritten.
- **Unused tokens convert.** An unused human-minted token's scope becomes its `initial_tags`, so
  it writes the same labels as tags on the Nodes it enrolls from now on. A token that has
  already enrolled a Node keeps its scope unconverted and enrolls with no tags: re-mint it.
- **Nothing is deleted.** The `relay:` labels stay on upgraded Nodes and a `relay:` Selector
  still matches them, but the tags are what you regroup from here. Nodes enrolled before this
  release get no `relay:node-id`.
- **Not copied, and listed.** At startup the Relay logs a warning for each Node it could not
  copy a label for, with `node_id`, `reason` and the `keys` (never the values), so a person can
  tag the Node by hand. The reasons are `minted_by_machine_or_unknown_account` (a machine
  Account's token, or one whose Account no longer exists), `declined` (the label is outside
  the tag alphabet or length bounds, for example `relay:tier=pci/1`), `tag_exists` (the Node
  already has a tag of that key, which is never overwritten), `tag_limit` (the Node already
  carries 64 tags) and `node_id_mismatch` (a scope that named `relay:node-id` with another
  Node's ID).
- **Per-token warnings.** `an Enrollment Token's scope could not be read` (the stored scope was
  not valid JSON; it was not converted), `Enrollment Token scope entries were not converted to
  initial tags` (entries dropped converting a human token's scope, with their keys), and
  `an Enrollment Token a machine or unknown Account minted carries a scope that is no longer
  stamped` for a token that could still enroll Nodes: re-mint it from a human Account. A
  human-minted token that has been used and could still enroll Nodes gets `a used Enrollment
  Token keeps a scope that is no longer stamped`: re-mint it.
- **A summary line** reports `tags_copied`, `nodes_listed` and `tokens_converted`.

A stored token whose legacy scope holds an entry outside the label alphabet (for example
`relay:tier=pci/1`) still stops enrolling, with the ordinary "enrollment token rejected":
re-mint it with initial tags.

To list every Node that carries a `relay:` label other than `relay:node-id` and has no tag of
that key, run this against a copy of the database or with the Relay stopped (the Relay holds a
single SQLite connection):

```sh
sqlite3 /var/lib/relay/relay.db \
  "SELECT r.node_id, r.key FROM relay_labels r
    WHERE r.key <> 'node-id'
      AND NOT EXISTS (SELECT 1 FROM tag_labels t WHERE t.node_id = r.node_id AND t.key = r.key)
    ORDER BY r.node_id, r.key;"
```

The tag alphabet is narrower than what the Selector parser accepts, so a `relay:` label like
`relay:tier=pci/1` could be stored by an earlier release. Such a label is not copied, and the
Relay stops serving it on read-back: it disappears from the Console, the Control API, MCP, and
Selector matching, and a `relay:tier=pci/1` Selector then resolves to fewer Nodes, with nothing
logged when it happens. The quarantine label, `relay:quarantine=on`, is inside the alphabet and
is kept. Before upgrading, record `GET /api/v1/nodes` and compare the `relay_labels` you get
back afterwards; that comparison is the audit.

After an upgrade, the Relay names affected Nodes at every startup: a read-only scan logs each
as `stored label declined on read-back` (fields: `namespace`, `node_id`, `key`,
`key_truncated`, `malformed_part`), then a `startup scan: stored labels declined on read-back`
summary per non-empty namespace with `labels_declined_at_scan`/`nodes_affected_at_scan`
totals, `reported` (capped at 50 per namespace), and `truncated`. The declined **value** is
never logged: read it from the store row.
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
that holds no join string, then give the join string from step 1 to `relay-daemon join`. The
string holds the Relay's address, its CA fingerprint and the token, so no CA file is copied to
the Node; the fingerprint is what stops a MITM from impersonating the Relay to a first-boot
Node.

```sh
# /etc/relay-daemon/relay-daemon.env   (0600 root:root; no secret in it)
RELAY_POLICY_PATH=/etc/relay-daemon/policy.toml
RELAY_NODE_LABELS=env=prod,role=web,site=us-east-1
```

```console
$ sudo relay-daemon join
Paste the join string (input is hidden):
$ journalctl -u relay-daemon | tail
# mTLS connect and "received Ping from Relay"
```

`join` pins the Relay's CA, enrolls, persists the identity to `/var/lib/relay-daemon`, and
starts the unit. It writes the join string nowhere and never touches the env file, whose
labels it reads. A daemon with no identity logs `no identity: nothing to connect with;
exiting until this Node is enrolled with relay-daemon join` and exits 0, so systemd shows a
clean stop; if `systemctl status relay-daemon` says inactive, run `join`. A failed `join`
leaves nothing on disk. `RELAY_JOIN` is not a setting: the daemon refuses to start while it is
set, so do not put the join string in the env file.

Enrollment is idempotent: once an identity exists in the state dir, `relay-daemon join` changes
nothing and exits 0, so config management may rerun it, and restarts never enroll.

Three Label namespaces are at work: `RELAY_NODE_LABELS` become node-space (`node:…`) Labels,
node-rooted and for routine targeting; the token's initial tags become tag-space (`tag:…`)
Labels the Node can never alter and an `operator` can change; and `relay:node-id` is the one
relay-space (`relay:…`) Label enrollment writes.

Each `RELAY_NODE_LABELS` key and value must match `[A-Za-z0-9._-]+` (an empty value is fine: a
bare `role` entry is a legitimate marker). A pair outside that alphabet is REFUSED at
enrollment (the whole request fails, with no certificate and no registry row, so the install
shows it at once) and DROPPED at reconnect (only that label is omitted and the Node stays
connected). Neither case rewrites the value: a label the Relay cannot render as a single
Selector term is refused.

## 3. Bulk enrollment via config management

One reusable token and a loop over inventory. An Ansible-flavored role (tasks
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

- name: Write env file (settings only — no secret, 0600)
  ansible.builtin.template:
    src: relay-daemon.env.j2
    dest: /etc/relay-daemon/relay-daemon.env
    owner: root
    group: root
    mode: "0600"

- name: Reload systemd
  ansible.builtin.systemd:
    daemon_reload: true

- name: Enroll and start relay-daemon (a no-op on an enrolled Node)
  ansible.builtin.command:
    cmd: /usr/bin/relay-daemon join
    stdin: "{{ relay_join }}"
  no_log: true

- name: Enable and start relay-daemon (converges if join's own start failed)
  ansible.builtin.systemd:
    name: relay-daemon
    enabled: true
    state: started
```

`ansible.cfg` must set `pipelining = True`. This is required, not a tuning note: without it
Ansible stages the module arguments, the join string included, in a temporary file on the
Node, which is where this design says it never lives (DI-45). The join string goes in on
`stdin:` and never in `cmd:`, so it is in no argument and no environment variable either.

```jinja
{# roles/relay_daemon/templates/relay-daemon.env.j2 #}
RELAY_POLICY_PATH=/etc/relay-daemon/policy.toml
RELAY_NODE_LABELS=env={{ relay_env }},role={{ relay_role }}
```

Run it across the fleet:

```console
$ ansible-playbook -i inventory/prod site.yml --limit 'new_nodes'
```

Each Node enrolls when `join` runs; already-enrolled Nodes are no-ops. The Relay
rate-limits enrollment per IP and globally ([relay-install.md](relay-install.md)). Both
limits are fixed: about 60 a minute per source address and 50 a minute overall, so some 200 Nodes behind one NAT address join in about four minutes. A
`join` the Relay refuses for rate persists nothing and is simply run again; for a much larger
batch, stagger the `join` runs.

## 4. Verify the rollout

From an MCP client or any Control API consumer, `list_nodes` shows every enrolled Node with
its Labels (node-space, relay-space and tag-space reported separately), Facts, `last_seen`, and Policy
fingerprint. Check:

- every expected Node is present, with `tag:env=prod` written from the token's initial tags
  (each one is a `tag_write` record attributed to the Account that minted the token) and
  `relay:node-id` set to its Node ID;
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
