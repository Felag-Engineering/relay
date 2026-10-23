# Local dev fleet (`docker compose`)

A one-command, laptop-scale fleet: one **Relay** container and three **relay-daemon**
containers that auto-enroll over CA-pinned mTLS and are drivable through the control plane
(MCP and `/api/v1`). It exists to demo and dogfood the real control path end to end. This
is the **test fleet**; the nine-Node demo fleet has its own runbook
([The demo fleet](#the-demo-profile)).

The test fleet is `deploy/test/`: its `docker-compose.yml` and every configuration file it
loads (`relay.toml`, `approval-gates.json`). Every command below names the file with `-f`
(the `make dev-fleet-*` targets do it for you). The compose project is `relay-test`, fixed by
the file's `name:`, and one per Docker engine: the make targets refuse a fleet another
checkout started. The demo fleet (`deploy/demo/`, project `relay-demo`) publishes the same
host ports, so only one of the two runs per engine and each fleet's up targets refuse while
the other has containers. There is deliberately no root `docker-compose.yml`, so a bare
`docker compose up` does nothing. [deploy/README.md](../deploy/README.md) indexes the three
environments. The single-Relay deployment stack is `deploy/production/docker-compose.yml`
([Running it with Docker Compose](operations/relay-install.md#7-running-it-with-docker-compose)),
and it must never run on a machine that holds a development checkout like this one.

> **DEV-ONLY — no production posture.** Committed credentials, a fixture Policy, one
> host. Ports are bound to `127.0.0.1`; exposing `9443` (`RELAY_PUBLISH_ADDR`) is
> remote code execution for your network. The deployment story is [relay-install.md](operations/relay-install.md).

## Prerequisites

- A checkout of `Felag-Engineering/relay` (one cloned as `gleipnir-relay` works through
  GitHub's redirect).
- Docker Engine with the Compose v2 plugin (`docker compose`, not legacy `docker-compose`),
  2.18 or later: the demo fleet's `down` and `logs` name the OAuth overlay, which uses
  `!reset`.
- Network access to Docker Hub the first time. The binaries are compiled inside multi-stage
  images; no host Go or Rust toolchain is needed.
- **A Docker data root on a Linux filesystem.** The Relay refuses `relay.toml`, its gate files
  and its state directory unless every path component sits on a filesystem whose owner and
  mode the kernel reports itself (ext4, XFS, btrfs, tmpfs, overlayfs). A checkout bind mount
  fails twice over: it carries your uid and mode `0644`, and on Docker Desktop it arrives over
  virtiofs, 9p or FUSE. So the `relay-config` one-shot copies the folder's `relay.toml` and
  `approval-gates.json` onto the `relay-etc` named volume, on the engine's own Linux filesystem
  (Docker Desktop's VM included), as `root:10001` `0640` and `root:root` `0644`, and the Relay
  mounts it read-only at `/etc/relay`. A data root on ZFS or NFS is refused the same way.

Docker is **not** required for `make build`, `make test` or `make lint`. CI never runs the
fleet; it only renders these files with `docker compose config`.

## What is in the box

| Piece | What it is |
| --- | --- |
| `relay` | The Go Relay. Node-plane gRPC on `:7654`, control-plane HTTPS (MCP + `/api/v1`) on `:9443` — distinct listeners, distinct published ports. Runs as UID 10001 with no capabilities, a read-only root filesystem, `/tmp` on tmpfs and `relay-data` as its one writable volume, which holds the CA and the SQLite store. |
| `relay-config` | A one-shot, on the Relay image, that stages `deploy/test/relay.toml` and `deploy/test/approval-gates.json` onto the `relay-etc` volume (see [Prerequisites](#prerequisites)), hands `init`'s two output volumes to UID 10001, then exits. The Relay starts only after it exits 0. |
| `init` | A one-shot, on the Relay image, running as UID 10001 like the Relay (`relay init` refuses root) and reading the same read-only `relay-etc` volume: runs `relay init` to create the first admin, the Console `admin` (with its password and first API Token, see [The Admin Console](#the-admin-console)), creates `dev-approver` (with its token — the approval gate forbids self-approval, see [The approval gate](#the-approval-gate)), mints a `relay:`-scoped Enrollment Token through `POST /api/v1/enrollment-tokens` and writes the response's join string for the daemons, then exits. If it fails, no daemon starts. |
| `daemon-1..3` | Three relay-daemons (Rust, musl static binary). Each has a baked, root-owned Policy fixture and a private state volume, enrolls on first start, and reports health once it has a persisted identity. The two `role=web` Nodes (`daemon-1`, `daemon-2`) also run the dev-fleet demo service; `daemon-3` (`role=db`) loads a different Policy fixture and runs no demo service. |
| `daemon-4..9` (demo fleet only) | Six more relay-daemons, in `deploy/demo/` and not in this fleet. See [The demo fleet](#the-demo-profile). |

Security-relevant choices, made explicit:

- **Policy arrives with the image, never over the wire (ADR-0002).** The fixture Policy is
  three files, `docker/fixtures/policy.web.toml`, `policy.db.toml` and `policy.bastion.toml`
  (the narrowest, demo fleet only), `COPY`d into the daemon image root-owned `0644`. The
  daemon's fail-closed loader refuses a group- or world-writable Policy, or one not owned by
  root. The demo Template pack (`docker/fixtures/templates.d/relay-demo/`) arrives the same way
  under the same rule, and its loader is fail-closed **whole-set**: a bad mode on one template
  file empties the Node's template vocabulary and reports the `unloadable` fingerprint.
- **No CA material reaches a daemon.** `ca-key.pem` lives only on the `relay-data` volume,
  which the short-lived `init` helper mounts **read-write** (it writes the store) and no daemon
  mounts. A daemon receives only the join string, as `RELAY_JOIN`: it pins the Relay's CA from
  the join string's fingerprint before sending the token, and writes the CA to its own state
  volume.
- **The Enrollment Token is `relay:`-scoped.** It can only join Nodes, never call the API or
  run Operations. Enrollment stamps `relay:env=dev` and `relay:fleet=dev` onto each Node; these
  are the labels your Selectors target.
- **The control-plane credential is minted at runtime, not committed.** The control plane
  accepts only per-Account API Tokens (ADR-0023), so the `init` one-shot runs `relay init`
  against the Relay's store to create the first admin and its first API Token, and writes the
  result to a shared volume. On a later `compose up` the admin exists, so it re-mints with
  `relay init --recover` (`docker/dev-fleet-init.sh`). Read it with:

  ```console
  $ docker compose -p relay-test -f deploy/test/docker-compose.yml cp init:/credential/control-credential - | tar -xO
  ```

  It lives on its own volume, which the daemons do not mount: an admin credential readable
  by every Node is exactly what a compromised Node would use to drive the fleet. It is a live
  24h admin credential (`--ttl 24h`) for `admin`. Keeping it on a volume is a dev-fleet
  convenience only; in a real deployment it goes from the operator's terminal straight into
  a secret store ([control-plane-credential.md](operations/control-plane-credential.md)).
  Never copy this one out of the fleet.

## The Admin Console

The Console (ADR-0009) is served on the **same** control-plane listener as MCP and
`/api/v1`, with no new auth path (invariant 10): browser sessions are one of the
authenticator's credential lanes beside API Tokens and OAuth.

```
https://127.0.0.1:9443/console/
```

Your browser will warn about the certificate: the Relay signs its server cert with the CA
it created on first start, which nothing on your laptop trusts. Accept it for the dev fleet, or
add `ca-cert.pem` to your trust store.

Sign in with:

| | |
| --- | --- |
| username | `admin` |
| password | `admin1234567` |

Override either with `CONSOLE_ADMIN_NAME` / `CONSOLE_ADMIN_PASSWORD` before the first
`docker compose -f deploy/test/docker-compose.yml up`. `relay init` sets the password once, when it
creates the admin, so changing it later needs a fresh volume. With `RELAY_PUBLISH_ADDR` beyond
loopback, `init` refuses the committed default password and the fleet does not start.
To reach the fleet by a DNS name, or on port 443, set `FLEET_HOSTNAME` and
`RELAY_PUBLISH_PORT` ([deploy/README.md](../deploy/README.md)).

**Why the password is not shorter.** The Relay refuses any Console password below 12 bytes
(`accounts.MinPasswordBytes`). The sign-in throttle has no hard lockout, which would be a
denial-of-service lever against your own operators, so an attacker gets slow, unlimited
attempts and length is what makes that safe. Behind the credential is the fleet's
administration: Accounts, API Tokens and Enrollment Tokens (ADR-0026).

**Why the password is set locally.** Every other Account is created by a control-plane request
carrying a bearer token. The first cannot be, so it comes from the Relay's own store, written
by `relay init` as the Relay's own uid (ADR-0030): the same answer ADR-0002 gives for Policy,
root it in the filesystem. The dev fleet's single `init` holds both authorities, a bearer token
and the store, on purpose: this is a laptop fleet.

**What you can do there.** Watch the fleet, open a Node, read its daemon-reported effective
Policy, follow the Activity trail, cancel a Job, and administer Accounts and API Tokens. The
Console renders approval records on Activity and Job detail but decides and lists none;
approvals are decided as in [Approving a parked dispatch](#approving-a-parked-dispatch). It
runs nothing, by design: the Console watches and does not execute (ADR-0052). It cannot
change a label yet; editing tags on a Node and in bulk is MVP work (ADR-0050).

## Bring the fleet up

```console
$ make dev-fleet-up
```

The Relay creates its CA and store; `init` runs `relay init` to create the first admin and
its token, creates the other dev Accounts, mints the Enrollment Token and exports the CA cert;
then the daemons enroll. `make dev-fleet-up` returns once every daemon is healthy, which each
becomes only after it has persisted its identity:

```console
$ docker compose -f deploy/test/docker-compose.yml ps
```

> **Troubleshooting.** The Relay healthcheck completes a TLS 1.3 handshake with
> both listeners using `openssl s_client`, verified against the Relay's CA. If it
> never passes, `init` never starts and no daemon enrolls — check
> `docker inspect --format '{{json .State.Health}}' <relay container>` and
> `docker compose -f deploy/test/docker-compose.yml logs relay`. If `init` exits non-zero, read
> `docker compose -p relay-test logs init`: no daemon starts until it exits 0.
>
> `hostfile: refusing <path>: <clause>` in `docker compose -p relay-test logs relay` names the
> file and the reason. A "filesystem" clause means the Docker data root is on an unsupported
> filesystem. A `relay-data` volume left by an older root-run Relay is refused too (the CA and
> store are not owned by 10001): wipe the volumes once with `down -v` ([Cleanup](#cleanup)).
> If `relay-config` exits non-zero, nothing else starts; read
> `docker compose -p relay-test logs relay-config`. A "cannot read /src/..." line there means
> the checkout's file mode hides a file in `deploy/test/` from the one-shot. (The one-shot
> holds `CAP_CHOWN` and `CAP_DAC_OVERRIDE` only, so a `0600` file is still readable; the root
> filesystem and `/src` are read-only and it has no network.)
>
> `refusing: relay-test is running from another checkout` (or `relay-demo`) means stop the
> fleet from that checkout. If that checkout is gone, run
> `docker compose -p relay-test -f deploy/test/docker-compose.yml down` here first (for the
> demo fleet, `docker compose -p relay-demo -f deploy/demo/docker-compose.yml -f
> deploy/demo/oauth.yml down`). `refusing: relay-demo is up and holds the same host ports`
> means run `make demo-down` first.
>
> A fleet that `make dev-fleet-up` started before the fleets split into `deploy/` folders runs
> as project `relay-demo`, which is now the demo fleet's project: `make demo-down` stops it,
> and `docker compose -p relay-demo -f deploy/demo/docker-compose.yml down -v` also removes its
> volumes.

## Verify N enrolled Nodes

**Quick check (no MCP client needed).** The Relay logs every enrollment:

```console
$ docker compose -f deploy/test/docker-compose.yml logs relay
```

You should see three `node enrolled` lines, each with `relay_label_count=2` (the token's
`relay:env=dev` and `relay:fleet=dev`; the log counts labels and does not print them).

**Richer check: list the fleet registry over MCP.** With the client set up as in
[Connecting Claude Code](#connecting-claude-code), call:

```
list_nodes()
```

The result is a `nodes` array of three, each with its `node_id`, `node_labels`,
`relay_labels` and `policy_fingerprint`. `node:` and `relay:` labels come back as separate
maps, never merged, so you can always tell which namespace set a label (ADR-0006). Pass an
optional `selector` to filter, e.g. `list_nodes(selector="relay:env=dev")`.

## Drive the fleet over MCP

### Connecting Claude Code

The control plane's server certificate has a single SAN: `relay`, the in-fleet DNS name,
not `localhost`. So dial it by that name and TLS verifies against the fleet's own CA
(`.dev-fleet/ca-cert.pem`) with no `-k` and no disabled verification. Map the name to
loopback once:

```console
$ grep -q 'relay$' /etc/hosts || echo '127.0.0.1 relay' | sudo tee -a /etc/hosts
```

`make dev-fleet-creds` exports the CA cert and both control-plane credentials (`admin` and
`dev-approver`) to the gitignored `./.dev-fleet/`, for MCP and `/api/v1` alike. Run it, then
add the server:

```console
$ make dev-fleet-creds
$ claude mcp add --transport http relay https://relay:9443/mcp \
    --header "Authorization: Bearer $(cat .dev-fleet/control-credential)"
```

An **http** transport is dialled by the `claude` process itself, so that process must trust
the CA (`claude mcp add -e` would not help). `NODE_EXTRA_CA_CERTS` does it:

```console
$ NODE_EXTRA_CA_CERTS=$PWD/.dev-fleet/ca-cert.pem claude
```

That connects as **`admin`**, the requester, which **cannot** approve its own parked
dispatches; `dev-approver` does that ([The approval gate](#the-approval-gate)).

Claude Code does not implement the MCP Tasks extension, so gated dispatches come back as
`pending_approval` **results**, never task handles. That is the universal path; reach the
Tasks path with
[`scripts/dev-fleet-mcp.sh`](#driving-the-mcp-tasks-extension-scriptsdev-fleet-mcpsh).

### Any other MCP client

Point it at `https://relay:9443/mcp` with:

- **Bearer credential:** `.dev-fleet/control-credential` (from `make dev-fleet-creds`).
- **TLS trust:** `.dev-fleet/ca-cert.pem`. Dial the host as `relay` so the SAN matches —
  never disable verification just to get a connection.

`run_operation` takes a `selector`, an `operation`, and a named-argument **map** keyed by the
Operation's argument names (the Relay maps them to the daemon's positional Policy).

`run_operation` and `raw_exec` return once the Job's Tasks are persisted, with `job_id` and
`job_status: "running"`. For per-Node results, pass `wait_seconds` (up to 300) or poll
`get_job` until `job_status` is `complete`; the examples below assume one of the two. An
answered retry must re-send the call unchanged, `wait_seconds` included.

Happy path: fan `system.facts` (no arguments, `read` class) across every dev Node:

```
run_operation(selector="relay:env=dev", operation="system.facts")
```

Read a file, the `file.read` example from `list_operations`. The dev image bakes in
`/etc/os-release` (busybox has none), and the fixture Policy allows `file.read` on any path but
`/etc/shadow`, so this succeeds on every Node:

```
run_operation(selector="relay:env=dev", operation="file.read", args={"path":"/etc/os-release"})
```

Policy-denied: `service.restart sshd`. The fixture Policy allows `service.restart` only for
`nginx` and `php-fpm`, so the daemon refuses it. Aim it at the one `role=db` Node: on
`relay:env=dev` it reaches three Nodes, a fleet-wide mutate, which the
[approval gate](#the-approval-gate) parks for a human before any Node sees it.

```
run_operation(selector="node:role=db", operation="service.restart", args={"unit":"sshd"})
```

The Node returns `outcome=denied_by_policy`. The verdict is the daemon's; the Relay never
evaluates Policy (ADR-0002, ADR-0011).

## The approval gate

The fleet ships an **approval gate** (`deploy/test/approval-gates.json`, ADR-0027), so
parked dispatches and MCP task handles can be exercised. This section covers the dev fixture;
gates for operators (rule schema, webhook, decision endpoint) are in
[docs/operations/approval-gates.md](operations/approval-gates.md). The nine-Node demo fleet
runs a different, in-band gate, its own folder's `deploy/demo/approval-gates.json`
([The human approver](operations/demo-fleet.md#the-human-approver)).

Each fleet's `relay-config` one-shot stages its folder's `relay.toml` and
`approval-gates.json`; `relay.toml`'s `approval.gate_rules_path` names the staged gate. Which
gate runs is which folder you deploy, never your shell or a `.env`.

Two rules:

| Rule | Matches | Requires |
| --- | --- | --- |
| `dev-fleet-wide-mutates-need-a-human` | `mutate` class, fan-out **≥ 2** | 1 approval from `dev-approver`, out-of-band |
| `dev-raw-exec-always-needs-a-human` | every Raw Exec | 1 approval from `dev-approver`, out-of-band |

The fan-out threshold leaves **both** paths reachable: a mutate on one Node runs straight
through; the same mutate fleet-wide parks. Here `node:role=db` is one Node and runs, while
`relay:env=dev` (three) waits for a human. In the demo fleet `node:role=db` parks too;
read [its runbook](#the-demo-profile) before presenting.

Security-relevant choices, made explicit:

- **The gate is Relay configuration, not a runtime object.** It is staged root-owned `0644`
  onto the read-only config volume, at the path `approval.gate_rules_path` names. To change
  it, edit `deploy/test/approval-gates.json` (or `relay.toml`) and run `make dev-fleet-up`
  again: `relay-config` re-stages the folder and the Relay restarts, with no rebuild. No
  Account of any role can read or loosen it through the API (invariant 11): a credential that
  could edit its own approval requirements would make the mechanism decorative.
- **Loading it is fail-closed.** A malformed, missing, symlinked, or group- or world-writable
  gate file fails Relay startup, never degrading to "nothing needs approval": a broken fixture
  crash-loops the container instead of disarming the fleet.
  `docker compose -f deploy/test/docker-compose.yml logs relay` says what the loader objected to.
- **`requester_allowed` is unset, the strict default.** The requesting Account may **not**
  approve its own dispatch, which is why `dev-approver` exists.
- **`dev-approver`'s credential is on the `control-credential` volume**, which no daemon
  mounts: an approver credential readable by every Node would let a compromised Node approve
  its own remediation.

### Approving a parked dispatch

With both credentials exported by `make dev-fleet-creds`, a gated call comes back as a
`pending_approval` **result** (not an error) carrying a `request_id`, a `plan_hash` and a
Relay-authored `summary`. Decide it as the approver:

```console
$ scripts/dev-fleet-mcp.sh api-approver POST \
    /api/v1/approvals/<request_id>/decision \
    '{"approve":true,"plan_hash":"<plan_hash>","reason":"looks right"}'
```

Then **re-issue the original call unchanged** — approving releases that dispatch, it
does not itself dispatch.

Two properties to watch:

- The **admin** credential cannot decide its own request: it gets
  `409 requester may not decide their own request`, even as an admin.
- The decision arrives on a credential the requesting MCP session does not hold, which is
  what `channel: out-of-band` records.

## Mutates that really run — and where they cannot

### The fixture limit, stated plainly

There is no service manager and no package manager on `busybox:stable-musl`. `pkg.install`
cannot complete on any Node, and `service.restart` cannot complete on a Node without the demo
service (`role=db`, `role=bastion`): it ends in `outcome=failure` with
`stderr="spawn systemctl: No such file or directory"` and **no `exit_code` key**, the
documented contract for a Task that never ran a process
([#389](https://github.com/Felag-Engineering/relay/issues/389)).

On the `role=web` Nodes, `service.restart` **does** run, through a DEV-ONLY `systemctl` shim
(`docker/fixtures/systemctl-shim`). The image bakes it off the `PATH`, and
`docker/daemon-entrypoint.sh` links it to `/usr/local/bin/systemctl` only on Nodes running the
demo service, so the daemon's fixed `systemctl restart <unit>` argv reaches
`/usr/local/bin/dev-fleet-service restart` there and nowhere else. The unit name is ignored
(there is one service), and Policy still decides which units may be asked for (`nginx` and
`php-fpm` on the web fixture). The shim fakes nothing about the outcome: the exit code is
`dev-fleet-service`'s own, from a live HTTP probe of the restarted `httpd`, so a failed restart
reports failure. A dev fleet must never report success it did not observe. The Raw Exec
`systemctl` allow in the web and db fixtures names `/usr/bin/systemctl`, which does not exist,
so it stays inert.

`service.restart sshd` is the deterministic **deny**: the daemon refuses before it execs.

### The real service

`busybox httpd` serves a real docroot on `127.0.0.1:8080`
(`/srv/dev-fleet-service/www/index.html`) on the `node:role=web` Nodes (`daemon-1`,
`daemon-2`), started by `docker/daemon-entrypoint.sh` and managed by the root-owned
`/usr/local/bin/dev-fleet-service`. It has three subcommands and deliberately no `stop`
([why](#why-startrestartstatus-and-not-stop)):

| Subcommand | Exit code | Meaning |
| --- | --- | --- |
| `status` | `0` | serving — prints `state=running pid=… port=…` |
| `status` | `3` | not serving — prints `state=down port=…` |
| `start` | `0` / `1` | idempotent: already serving, or started successfully / failed to start |
| `restart` | `0` / `1` | stopped and restarted successfully / could not act |
| anything else | `2` | usage |

Every exit code but the usage `2` comes from a live HTTP fetch of that file. State is
recorded at `/var/lib/dev-fleet-service/state` (`pid=`, `port=`, `started_epoch=`) only after a
successful probe; `httpd`'s output goes to `/var/lib/dev-fleet-service/httpd.log`. The file has
deliberately no `state=` key: it is not rewritten after a start, so a stored `state=running`
would go on claiming liveness after an out-of-band kill. `pid` and `started_epoch` prove a
restart happened without claiming anything about the present.

### The Raw Exec beat

This beat demonstrates Raw Exec. The typed route to the same repair is the Template pack's
`svc.restart` ([below](#the-template-pack--loaded-enforced-and-dispatchable)), and the other
structured mutate is `service.restart` on the web Nodes, through the shim.

Preflight without dispatching:

```
raw_exec(selector="relay:env=dev", argv=["/usr/local/bin/dev-fleet-service","status"], plan=true)
```

returns per-Node verdicts allow/allow/deny, with no parking and no execution.

The repair:

```
raw_exec(selector="relay:env=dev", argv=["/usr/local/bin/dev-fleet-service","restart"])
```

returns a `pending_approval` result (every Raw Exec parks under
`dev-raw-exec-always-needs-a-human`) carrying `request_id` and `plan_hash`. Approve it as
`dev-approver` ([Approving a parked dispatch](#approving-a-parked-dispatch)), then **re-issue
the same `raw_exec` call unchanged**. Expect **two Nodes** `outcome=success, exit_code: 0` and
**daemon-3** `outcome=denied_by_policy`.

An independent read, through a different Operation and tier, proves the mutate happened. Run
it before and after the restart:

```
run_operation(selector="relay:env=dev", operation="file.read", args={"path":"/var/lib/dev-fleet-service/state"})
```

`pid` and `started_epoch` both change on the web Nodes; the db Node fails to read a file it
never had.

### Why `start|restart|status` and not `stop`

The AI-agent must be able to repair the fleet and never break it; the fault is injected out
of band ([The fault, and resetting between takes](operations/demo-fleet.md#the-fault-and-resetting-between-takes)).
The script has no `stop` and the Policy has no allow for one, so both layers agree.

### The template pack — loaded, enforced and dispatchable

`svc.restart` (`mutate`) and `svc.status` (`read`) are visible through
`list_operations(node_id="<a web node id>")` and `describe_node(...)`'s
`template_vocabulary` (with a real `template_set_fingerprint`; the literal `unloadable`
there means the pack failed to load). Every fixture Node loads the pack; the web fixture's
Policy allows both, and the db fixture's has no rule for either.

Call them like any Operation (ADR-0042):

```
run_operation(selector="relay:env=dev", operation="svc.status")
```

returns `success` on the web Nodes and `denied_by_policy` on the db Node, which has the
Template but whose Policy refuses it. The dispatch is `read` because every Node that reports
`svc.status` reports it `read`; `svc.restart` is `mutate`, so it takes the mutate cap and every
approval rule matching a `mutate`, as `service.restart` does. A Node that does not report a
Template comes back `unsupported` without being sent anything; a preflight (`plan=true`)
reports the same.

`list_nodes()` shows **two distinct `policy_fingerprint` values**, because `daemon-3` loads a
different Policy file: the registry's drift signal.

## Driving the MCP Tasks extension (`scripts/dev-fleet-mcp.sh`)

Relay serves the MCP Tasks extension (SEP-2663, ADR-0028), but **no shipping MCP client
implements it**: not the Go SDK
([go-sdk#626](https://github.com/modelcontextprotocol/go-sdk/issues/626)), TypeScript or
Python. Its capability is advertised in a per-request `_meta` no client sends, so an ordinary
client never reaches `tasks/get`, `tasks/cancel` or the `CreateTaskResult` shim.

`scripts/dev-fleet-mcp.sh` speaks that wire by hand. It is a curl wrapper, not a client
library, so it shows exactly what goes over the wire. `FLEET=test` or `FLEET=demo` picks the
fleet (the make targets set it); unset, it uses `relay-test` if that project has containers,
else `relay-demo`.

```console
$ scripts/dev-fleet-mcp.sh init                 # export CA + both credentials
$ scripts/dev-fleet-mcp.sh call list_nodes      # ordinary client (no Tasks capability)
$ scripts/dev-fleet-mcp.sh call-tasks run_operation '{"selector":"relay:env=dev","operation":"pkg.install","args":{"name":"nginx"}}'
$ scripts/dev-fleet-mcp.sh task-get <taskId>
$ scripts/dev-fleet-mcp.sh task-cancel <taskId>
$ scripts/dev-fleet-mcp.sh raw tasks/update '{}' # served? it must not be
```

The difference between `call` and `call-tasks` is the whole shim: the same gated dispatch
returns a `pending_approval` result to an ordinary client and a `resultType: "task"` handle to
a Tasks-capable one. Both mint the same `taskId`.

## Survive `down` / `up`

```console
$ docker compose -f deploy/test/docker-compose.yml down
$ docker compose -f deploy/test/docker-compose.yml up -d
```

The CA and the SQLite store persist on `relay-data`, and each daemon's identity on its own
`daemonN-state` volume, so the Nodes come back with the **same** `node_id`s and do not
re-enroll. The Relay's logs show reconnects, not a fresh enrollment storm.

To wipe everything (CA, identities, store) and start clean:

```console
$ docker compose -f deploy/test/docker-compose.yml down -v
```

## Where to read the audit trail

Every dispatch, refusal and Policy preflight emits exactly one structured log line, with the
principal, selector, operation or action kind, outcome counts and job ID:

```console
$ docker compose -f deploy/test/docker-compose.yml logs -f relay
```

The full record, including per-Node output, lives in the Relay's SQLite store on the
`relay-data` volume. The log lines deliberately omit operation args, Raw Exec argv and captured
stdout/stderr; they are a summary, not a substitute for the store. The Console's Activity and
Job pages read the store; there is no general audit-query route on the API or MCP.

## The demo profile

The nine-Node fleet is `deploy/demo/`, a separate compose project, `relay-demo`, with its own
`relay.toml` and in-band gate. Its roster, the four beats, the injected fault, `make
demo-reset` and resource usage are in its own runbook,
[docs/operations/demo-fleet.md](operations/demo-fleet.md); drive it with the runbook's `make
demo-*` targets. It shares this fleet's host ports, so `make dev-fleet-down` before a demo and
`make demo-down` after one. Its control plane and first three Nodes are this fleet's, service
for service (`test_fleet_is_the_demo_fleets_first_three_nodes`,
`daemon/tests/dev_fleet_fixtures.rs`), and the DEV-ONLY banner applies with more force: three
times the Nodes sit behind the same committed Console password.
Its [Presenter runbook](operations/demo-fleet.md#presenter-runbook) takes a first-time
presenter from cold to on stage, including
[minting Gleipnir's credentials](operations/demo-fleet.md#credentials-for-gleipnir-copy-paste)
and [the scripted bypass beat](operations/demo-fleet.md#the-bypass-beat-scripted-exactly).

## Scaling the fleet

Each daemon needs its **own** state volume for a stable identity, so daemons are explicit
services rather than replicas. To add a Node, copy a `daemon-N` service block (bump the name,
`HOSTNAME` and its `daemonN-state` volume, and register the volume under `volumes:`). The copy
inherits `RELAY_POLICY_PATH` and a `role=` label; choose both deliberately: `policy.web.toml` +
`role=web` for the demo service and the repair allow, `policy.db.toml` + `role=db` for
neither, or `policy.bastion.toml` + `role=bastion` for neither and less besides.
[The nine-Node roster](operations/demo-fleet.md#the-nine-node-roster) is this copy done six
times.

**A fleet is its file, never a profile.** Neither compose file declares `profiles:`; a new
Node goes in `deploy/demo/docker-compose.yml`, and a change to the Relay, a one-shot or
`daemon-1..3` goes in both files. `test_fleet_is_the_demo_fleets_first_three_nodes` fails the
build otherwise.

## Cleanup

```console
$ docker compose -p relay-test -f deploy/test/docker-compose.yml down -v
$ rm -rf ./.dev-fleet
```

The demo fleet cleans up the same way under its own project
([its runbook](operations/demo-fleet.md)). Volumes from an older checkout may sit under a
directory-named project; remove them once with
`docker compose -p <old-dir-name> -f deploy/test/docker-compose.yml down -v`.
