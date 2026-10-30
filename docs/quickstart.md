# Quickstart: a working fleet in thirty minutes

Install the Relay from its package, join two or three Nodes, connect Claude Code, run one read
and one gated mutate. This is the real packaged deployment made smaller; nothing here has to be
undone for production. [relay-install.md](operations/relay-install.md) is the production
reference.

> **Placeholders.** `X.Y.Z` is the release version. `<relay-vm>` is the SSH name of the Relay's
> VM, `node-1 node-2 node-3` are the SSH names of the Nodes' VMs, and `<your-name>` is the name
> of your admin Account. Packages ship from the first release that carries them; see
> [what a release contains](operations/release-artifacts.md#what-a-release-contains).

## What you need

- One VM for the Relay and two or three for Nodes, each on a platform the release's install
  matrix tests: Ubuntu 24.04 or 26.04, Debian 13, Rocky Linux 10 or Amazon Linux 2023, on
  x86_64 or aarch64. [How the matrix gates a release](operations/release-artifacts.md#the-install-matrix-gates-the-packages).
  The commands below are for `.deb` on x86_64; step 1 gives the `.rpm` and arm64 names.
- A Linux workstation (WSL works) with SSH access to each VM, `bash`, `curl`, `cosign` v3 or
  later, and Claude Code, or another MCP client that supports elicitation.
- An account with `sudo` on each VM. Every `sudo` below runs with a terminal, so a password
  prompt works and so does passwordless `sudo`: on the Relay's VM you work inside an
  interactive `ssh <relay-vm>` session, and on a Node you run one `ssh -t <node> "..."`.
- Network: the Nodes reach the Relay's VM on TCP 7654, the Node plane. Open it in any firewall
  or cloud security group. Nothing needs to reach 9443: the control plane stays on the Relay
  VM's loopback and you reach it through an SSH tunnel.

Why the Nodes are VMs: the Relay runs unprivileged, as its own `relay` account with no
capabilities. The relay-daemon runs as root, because administering the server it runs on is
its job, and a container has nothing to administer.

## 1. Download and verify the packages (workstation)

```bash
VERSION="X.Y.Z"
PKGVERSION="${VERSION//-/.}"
BASE="https://github.com/Felag-Engineering/relay/releases/download/v${VERSION}"

# .deb on x86_64. Other forms: relay_${PKGVERSION}-1_arm64.deb and
# relay-daemon_${PKGVERSION}-1_arm64.deb, or the .rpm files
# relay-${PKGVERSION}-1.x86_64.rpm, relay-daemon-${PKGVERSION}-1.x86_64.rpm and their
# .aarch64.rpm twins.
curl -fsSLO "${BASE}/relay_${PKGVERSION}-1_amd64.deb"
curl -fsSLO "${BASE}/relay-daemon_${PKGVERSION}-1_amd64.deb"
curl -fsSLO "${BASE}/SHA256SUMS"
curl -fsSLO "${BASE}/SHA256SUMS.sigstore.json"

cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/Felag-Engineering/relay/.github/workflows/release.yml@refs/tags/v${VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS

sha256sum --check --ignore-missing SHA256SUMS
```

The certificate identity and issuer are the ones in
[release-artifacts.md](operations/release-artifacts.md#verify-then-install), copied exactly;
this block verifies two packages and pins no digest. A failure of either check is fatal: install
nothing. Production pins the package digest in config management; here the cosign-verified
`SHA256SUMS` is the anchor, and verifying once on the workstation means the VMs need no cosign.

## 2. Install and start the Relay (on the Relay's VM)

Copy the package over and open a session. The VM's shell does not have `$PKGVERSION`. Only the
Relay's package is copied, so `./relay_*_amd64.deb` names it whatever the version.

```console
$ scp "relay_${PKGVERSION}-1_amd64.deb" <relay-vm>:   # or: relay-${PKGVERSION}-1.x86_64.rpm
$ ssh <relay-vm>
```

In that session:

```console
$ sudo apt-get install -y ./relay_*_amd64.deb   # or: sudo dnf install -y ./relay-*.x86_64.rpm
$ relay --version
$ sudo grep -n hostname /etc/relay/relay.toml
```

That last check otherwise fails only later, on the Nodes. `tls.hostname` must be a name every
Node resolves to this VM. The package sets it from the VM's fully qualified name; with none
found, the line is commented out and the Relay refuses to start, naming `tls.hostname`. With no
DNS in your lab, set it to the VM's IP address, which a relay-daemon may dial
([relay-install.md §2](operations/relay-install.md#2-configuration-surface)). Edit with
`sudoedit /etc/relay/relay.toml`, which keeps owner and mode. Then start it:

```console
$ sudo systemctl enable --now relay
$ systemctl status relay
```

The package wrote a configuration with the control plane and the Console on `127.0.0.1:9443`,
the CA under `/var/lib/relay/ca`, and two gate rules that make every mutate and every Raw Exec
wait for a person (step 9). [relay-install.md §1](operations/relay-install.md#1-obtain-verify-and-install-the-package)
lists all of it.

## 3. Create the first admin (still on the Relay's VM)

```console
$ sudo -u relay relay init --admin <your-name>
```

It prompts twice for a Console password (not echoed) and prints the first API Token once.
`relay init` refuses root, hence `sudo -u relay`. The token lives seven days (`--ttl` changes
it). Store it in your password manager now; step 4 pastes it on the workstation. A lost token is
replaced with `sudo -u relay relay init --recover <your-name>`.

Copy the public CA certificate where your account can read it, then leave the session:

```console
$ sudo install -m 0644 /var/lib/relay/ca/ca-cert.pem ~/relay-ca-cert.pem
$ exit
```

That file is the public certificate. The CA directory also holds `ca-key.pem`, which you never
copy.

## 4. Reach the control plane from your workstation

```console
$ scp <relay-vm>:relay-ca-cert.pem .
```

Open the tunnel in a **new** terminal and leave it running. The control plane stays on
loopback, and the tunnel rides your SSH host-key check. If a dev fleet is running, it already
binds `127.0.0.1:9443`: stop it, or forward another local port and use that port in every URL
below.

```console
$ ssh -N -L 9443:127.0.0.1:9443 <relay-vm>
```

Every other workstation command runs in the shell you have used since step 1, in the directory
holding the packages and `relay-ca-cert.pem`, because `$PKGVERSION` and the files live there.
Read the token without echo, so it never reaches your shell history, then check the control
plane.

```console
$ read -rsp 'API Token: ' RELAY_TOKEN; echo
$ curl --cacert relay-ca-cert.pem -H "Authorization: Bearer $RELAY_TOKEN" \
    https://127.0.0.1:9443/metrics | head
```

Prometheus metric lines mean TLS verified against your copy of the CA and the token was
accepted. Dialling `127.0.0.1` verifies because the server certificate always names loopback.
`curl -H` and `claude mcp add --header` put the token in that process's command line, visible
to other users of the workstation while it runs.
To widen the control plane beyond loopback instead, see
[relay-install.md §4](operations/relay-install.md#4-the-packaged-systemd-unit).

## 5. Mint a join string (workstation)

```console
$ curl --cacert relay-ca-cert.pem \
    -H "Authorization: Bearer $RELAY_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"initial_tags": ["tag:env=quickstart"], "ttl_seconds": 7200, "max_uses": 3}' \
    https://127.0.0.1:9443/api/v1/enrollment-tokens
{
  "id": "3f8a…",
  "token": "3f8a….K7m2…",
  "join_string": "glp_join_…",
  "initial_tags": ["tag:env=quickstart"],
  …
}
```

- Set `max_uses` to the number of Nodes you will join. Two hours is the Console form's default
  lifetime; [enrollment.md §1](operations/enrollment.md#1-mint-a-token) has every field.
- The join string is a secret, returned once. It carries the Relay's address, its CA
  fingerprint and the Enrollment Token, and it can only enroll a Node, never run anything. Keep
  it on screen for step 6 and do not save it to a file.
- `tag:env=quickstart` becomes each Node's first tag, and every later step targets it.
- The alternative: with the tunnel up, the Console at `https://127.0.0.1:9443/console/`, Add
  Nodes, mints the same kind of token and shows the command and the join string apart. It asks
  for your Console password on every mint, and your browser must trust `relay-ca-cert.pem`;
  never click through the warning.

## 6. Join the Nodes (workstation)

First write the one Policy fragment this quickstart needs, `50-quickstart.toml`:

```toml
[[operation]]
name = "service.restart"
allowed_args = [["systemd-journald"]]
```

The package's default Policy allows the read catalog and denies every mutate and all Raw Exec
(ADR-0022), so a mutate needs a fragment. Never create `/etc/relay-daemon/policy.d` yourself
before the package is installed: a Node whose Policy directory already exists gets no default
Policy. This permits restarting exactly one unit. It lives on
the Node, root-owned; the Relay can read it and never change it (ADR-0002). The fragment is
placed after the install and before `join`, because `join` starts the daemon and the daemon
loads Policy only at start: writing it first means no restart. `systemd-journald` runs on every
supported platform and keeps its log streams across a restart; swap in any unit you can safely
restart.

Then, in the step 1 shell and directory (re-state `VERSION` and `PKGVERSION` first if you
opened a fresh one), one `ssh -t` per Node:

```bash
# .rpm form: scp relay-daemon-${PKGVERSION}-1.x86_64.rpm in place of the .deb, and
# sudo dnf install -y ./relay-daemon-${PKGVERSION}-1.x86_64.rpm
for node in node-1 node-2 node-3; do
  scp "relay-daemon_${PKGVERSION}-1_amd64.deb" 50-quickstart.toml "$node": &&
  ssh -t "$node" "sudo apt-get install -y ./relay-daemon_${PKGVERSION}-1_amd64.deb &&
    sudo install -m 0644 -o root -g root 50-quickstart.toml /etc/relay-daemon/policy.d/ &&
    sudo relay-daemon join"
done
```

On each Node `sudo` may ask for your password, then `join` asks
`Paste the join string (input is hidden):`. Paste the string from step 5. `ssh -t` gives `join`
a terminal, so the prompt does not echo; the string is never in a command line, a file or an
environment variable. Success prints
`enrolled as "<node-id>"; relay-daemon.service is enabled and started`. Running it again on an
enrolled Node changes nothing (`this Node already holds an identity in …; nothing was changed`).
For many Nodes, see [enrollment.md §3](operations/enrollment.md#3-bulk-enrollment-via-config-management):
the release's Ansible role (ADR-0048), and an SSH loop that needs passwordless `sudo`.

**Where the trust comes from.** The CA fingerprint inside the join string is the only thing a
new Node trusts. Whoever could alter the string on its way could send the Node to their own
Relay (ADR-0031). It travelled here inside your SSH sessions; never move one over chat, email
or a ticket. A Node that records `sudo` sessions (`log_input`, a session recorder) records the
pasted string too. If `join` says
`the Relay's CA does not match the join string's CA fingerprint; nothing was sent`, stop: the
Node reached something other than your Relay, or the string was changed. Mint a fresh one.

## 7. Connect Claude Code (workstation)

Claude Code gets its own Account, never the founding admin's token: an admin token reaches Raw
Exec and the administration of every Account for as long as it lives. Make a human Account at the
lowest role that runs this page's Operations. `operator` requests every Operation, read or
mutate; a `viewer` cannot run `disk.usage`. It is a human Account, not a machine Account,
because a human Account's token answers a gate as that person's decision (AP-87), while a
machine Account's answer is machine self-confirmation and would not stand as your approval in
step 9. The Account needs no Console password to hold a token.

In a fresh shell, run the `read -rsp` from step 4 again first, so `RELAY_TOKEN` (the admin's) is
set. These are the first two calls of
[the intended flow](operations/control-plane-credential.md#the-intended-flow):

```console
$ curl --cacert relay-ca-cert.pem -H "Authorization: Bearer $RELAY_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"name": "claude-code", "kind": "human", "role": "operator"}' \
    https://127.0.0.1:9443/api/v1/accounts
{
  "id": "acct-…",
  "name": "claude-code",
  "kind": "human",
  "role": "operator",
  …
}
$ read -rp 'Account id: ' ACCOUNT_ID
$ curl --cacert relay-ca-cert.pem -H "Authorization: Bearer $RELAY_TOKEN" \
    -H "Content-Type: application/json" -d '{"name": "claude-code-quickstart"}' \
    https://127.0.0.1:9443/api/v1/accounts/$ACCOUNT_ID/tokens
{
  "api_token": { … },
  "token": "glp_….…",
  …
}
```

Paste the first response's `id` at the prompt. The second response's `token` is the new API
Token, shown once and living seven days. Read it without echo, then connect Claude Code with it
alone:

```console
$ read -rsp 'Claude Code API Token: ' CLAUDE_TOKEN; echo
$ claude mcp add --transport http relay https://127.0.0.1:9443/mcp \
    --header "Authorization: Bearer $CLAUDE_TOKEN"
$ NODE_EXTRA_CA_CERTS=$PWD/relay-ca-cert.pem claude
```

An http transport is dialled by the `claude` process itself, so that process must trust the CA;
`claude mcp add -e` would not help, and `NODE_EXTRA_CA_CERTS` does. `--header` stores the token
in Claude Code's own configuration, which is why it holds this Account's token and never the
admin's `RELAY_TOKEN`.

Gleipnir or any other MCP client needs the same three things: the URL, the CA certificate and
its own API Token, with a machine Account for one that runs unattended.

## 8. A first read

Ask: "Using the relay tools, list the Nodes matching the Selector `tag:env=quickstart`, then run
disk.usage on them." The calls it should make are
`list_nodes(selector="tag:env=quickstart")`, which shows every Node you joined with
`tag:env=quickstart` among its tag labels (this is your enrollment check), then
`run_operation(selector="tag:env=quickstart", operation="disk.usage")`. `run_operation` returns
`job_status` `running` unless it is given `wait_seconds`, so the model either passes it or polls
`get_job` before it reports results.

- `disk.usage` is in the read catalog the daemon package installs (ADR-0053). `list_operations`
  shows the rest: `proc.list`, `net.listening`, `pkg.inventory`, `service.status`, `log.tail`
  and `file.checksum`, plus the native `system.facts` and `file.read`.
- Reads are not gated, so it just runs.
- Optional: ask for a `file.read` of `/etc/shadow`. Each Node refuses it (`denied_by_policy`);
  the default Policy's deny rules beat its read allowance.

The prompt carries the literal Selector because `run_operation`'s tool description still lists
only `node:` and `relay:` prefixes, so a model may not write a `tag:` term unaided.

## 9. A first mutate, approved in the client

Ask: "Restart systemd-journald on the Nodes matching the Selector `tag:env=quickstart`." The
call is
`run_operation(selector="tag:env=quickstart", operation="service.restart", args={"unit":"systemd-journald"})`.

- The package's gate rule `mutate-needs-a-human` parks it before any Task exists.
- Claude Code advertises elicitation, so Relay answers with a question carrying its own summary
  of the request, the request ID and the plan hash, and Claude Code puts that question to you.
- Accept, and the client retries: the Job runs, each Node reports `success` (the model passes
  `wait_seconds` or polls `get_job` to see it), and the Decision is recorded as yours, a
  token-session answer. Decline, and nothing runs. If no question appears, the request stays
  pending; [approval-gates.md](operations/approval-gates.md#how-an-ai-agent-waits-two-envelopes-one-decision)
  says where a person decides.
- A mutate on any other unit is refused by each Node (`denied_by_policy`) even after you
  approve: approval never widens Policy.

A client that cannot be asked gets a `pending_approval` result instead;
[approval-gates.md](operations/approval-gates.md#how-an-ai-agent-waits-two-envelopes-one-decision)
says how it waits and where a person decides.

## What you cannot lose

Everything this page had you copy can be replaced.

- The join string: mint another, and let the old one expire.
- The admin's API Token: `sudo -u relay relay init --recover <your-name>`.
- Claude Code's API Token: mint another for the `claude-code` Account, as step 7 did.
- The CA certificate: it is public; copy it again.

The Console password is different: keep it safe, because nothing resets it. Nothing on this
page needs it. The one thing that cannot be re-minted is the Relay's CA private key,
`/var/lib/relay/ca/ca-key.pem`, which this page never had you copy. Lose it and every Node must
enroll again. Back up `/var/lib/relay` (the key and the store together), never image the Relay's
VM after its first start, and see [ca-disaster-recovery.md](operations/ca-disaster-recovery.md).

## Next

- [relay-install.md](operations/relay-install.md): widening the control plane, upgrades, and
  [running it with Docker Compose](operations/relay-install.md#7-running-it-with-docker-compose).
- [enrollment.md §3](operations/enrollment.md#3-bulk-enrollment-via-config-management): the
  Ansible role and the SSH loop for many Nodes.
- [policy-as-code.md](operations/policy-as-code.md): Policy fragments through config management.
- [approval-gates.md](operations/approval-gates.md), [control-plane-credential.md](operations/control-plane-credential.md)
  and [ca-disaster-recovery.md](operations/ca-disaster-recovery.md).

To clean up, stop the tunnel in its terminal and run `unset RELAY_TOKEN CLAUDE_TOKEN` in the other.
