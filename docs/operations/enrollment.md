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
Token; [control-plane-credential.md](control-plane-credential.md)). Run this on the Relay host
while the control plane listens on loopback, the package's default. `relay-ca-cert.pem` is the
copy of the CA certificate made in [relay-install.md](relay-install.md) §3, and
`relay.example.internal` stands for your `tls.hostname`. Once you have widened
`control_plane.listen_address`, drop `--resolve`.

```console
$ curl --cacert relay-ca-cert.pem \
    --resolve relay.example.internal:9443:127.0.0.1 \
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
  hand. It is never written to the Node or placed in an environment file. Its integrity rides on
  the channel you moved it over: see [Moving a join string](#moving-a-join-string).

Revoke a token at any time. This also cascade-revokes every Node it enrolled:

```console
$ curl --cacert relay-ca-cert.pem \
    --resolve relay.example.internal:9443:127.0.0.1 \
    -H "Authorization: Bearer $RELAY_TOKEN" \
    -X DELETE https://relay.example.internal:9443/api/v1/enrollment-tokens/<id>
```

### Moving a join string

The join string's integrity rides on the channel you moved it over. The CA fingerprint inside
it is the only thing a Node that has never reached the Relay trusts, so whoever can change the
string on the way can put in their own address and fingerprint, and the Node enrolls with
their Relay instead (ADR-0031). Move it only over a channel that protects it from alteration
as well as from reading: your vault, an SSH session to the Node, the Ansible role's standard
input. Never over chat, email or a ticket.

The string is a bearer credential until it is used or expires (threat-model R41). Size
`max_uses` and `ttl_seconds` to the run. Mint through the Control API, the only mint surface
today.

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

Install the daemon package per [relay-daemon-install.md](relay-daemon-install.md), then give
the join string from step 1 to `relay-daemon join`. The
string holds the Relay's address, its CA fingerprint and the token, so no CA file is copied to
the Node; the fingerprint is what stops a MITM from impersonating the Relay to a first-boot
Node.

The package placed `/etc/relay-daemon/relay-daemon.env` (0600 root:root; no secret in it), which
already carries `RELAY_POLICY_PATH` and `RELAY_TEMPLATE_DIR`. Add this Node's labels to it:

```console
$ sudoedit /etc/relay-daemon/relay-daemon.env
# add: RELAY_NODE_LABELS=env=prod,role=web,site=us-east-1
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

One reusable token and a loop over inventory. Config management installs the daemon package and
runs `relay-daemon join` with the join string from your vault; the string never goes in a file
on the Node.

**The release's Ansible role (DI-45).** Download `relay_daemon-<version>.tar.gz` and the
daemon package(s) for your architectures from the same release, and verify them per
[release-artifacts.md](release-artifacts.md#verify-then-install). Extract the role into a roles
path. Put the verified packages in one controller directory: it may hold both architectures,
but only one version, because the role installs the single package that matches the Node. The
role checks the package's version, read from its metadata, against its own release and refuses
another: the refusal names the package's version, the role's release and the directory, and
changes nothing on the Node. The fix is to put that release's package in the directory and run
again. Put the join string in the vault with
`ansible-vault encrypt_string --stdin-name relay_daemon_join_string`, and paste its output (a
`relay_daemon_join_string: !vault |` block) into `group_vars/new_nodes/vault.yml` beside the
playbook. Ansible loads that file for every host in `new_nodes`, which is how the play below
defines the variable the role requires; run it with `--ask-vault-pass` or a vault password file.

```yaml
- hosts: new_nodes
  become: true
  pre_tasks:
    - name: Create the daemon's configuration directory
      ansible.builtin.file:
        path: /etc/relay-daemon
        state: directory
        owner: root
        group: root
        mode: "0755"

    - name: Write env file (settings only, no secret, 0600)
      ansible.builtin.template:
        src: templates/relay-daemon.env.j2    # relative to this playbook
        dest: /etc/relay-daemon/relay-daemon.env
        owner: root
        group: root
        mode: "0600"
  roles:
    - role: relay_daemon
      vars:
        relay_daemon_package_dir: /srv/relay-daemon-packages
  tasks:
    # Optional: a Policy fragment of yours. The role places none (DI-45).
    - name: Place a Policy fragment
      ansible.builtin.copy:
        src: policies/10-nginx.toml
        dest: /etc/relay-daemon/policy.d/10-nginx.toml
        owner: root
        group: root
        mode: "0644"
      notify: "relay_daemon : Restart relay-daemon"
```

The env file comes first because the package places its own only when none exists, and `join`
reads the labels from this file at enrollment. Because `/etc/relay-daemon` and the env file
exist before the package's first install, the package treats them as yours: it never replaces
the env file, and `apt purge` leaves both. The package still places its default `policy.toml`,
since `policy.d` did not exist.

```jinja
{# templates/relay-daemon.env.j2, beside your playbook #}
RELAY_POLICY_PATH=/etc/relay-daemon/policy.toml
RELAY_NODE_LABELS=env={{ relay_env }},role={{ relay_role }}
```

What the role guarantees and refuses:

- The join string travels on standard input and reaches no file, argv or log on the Node.
- It forces pipelining; `requiretty` in sudoers breaks that, and the task fails. It refuses a
  Node where sudo records standard input (`log_input`).
- Before it changes anything on the Node, it refuses a daemon package whose version is not the
  role's release, naming both versions and the directory, and refuses a directory holding several packages for the Node's
  platform.
- It changes nothing on an enrolled Node, and fails on a partial identity.
- It never upgrades; see [iac-upgrades.md](iac-upgrades.md).
- A controller callback plugin that records task arguments (ARA, for example) would receive the
  string, so don't enable one.

The role's [Limits](../../daemon/packaging/ansible/relay_daemon/README.md#limits) hold the rest.

Run it across the fleet:

```console
$ ansible-playbook -i inventory/prod site.yml --limit 'new_nodes'
```

**Without Ansible: an SSH loop** (ADR-0048 decision 3). Install the verified package on each
Node first. Then, from your workstation:

```bash
read -rsp 'Join string: ' JOIN; echo   # nothing echoes, nothing reaches shell history
failed=()
for host in $(cat new-nodes.txt); do
  printf '%s\n' "$JOIN" | ssh "$host" sudo -n relay-daemon join || failed+=("$host")
done
unset JOIN
(( ${#failed[@]} )) && printf 'failed: %s\n' "${failed[@]}"
```

`printf` is a shell builtin, so the string is in no process's arguments. `ssh` without `-t`
means `join` reads standard input as piped text. `sudo -n` needs passwordless sudo: without it
sudo fails rather than prompts, and `requiretty` in sudoers makes it refuse with no terminal, so
that host fails. Never pass `-o StrictHostKeyChecking=no`: an unverified host key could hand
the string to a host that is not yours. Unlike the role, the loop does not check for sudo
`log_input` or a session recorder on the Node, and either would record the string. A rerun is
safe: `join` on an enrolled Node changes nothing and exits 0.

Each Node enrolls when `join` runs; already-enrolled Nodes are no-ops. Either way the Relay
rate-limits enrollment per IP and globally ([relay-install.md](relay-install.md)). Both
limits are fixed: about 60 a minute per source address and 300 a minute overall, so some 200 Nodes behind one NAT address join in about three minutes. A
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
