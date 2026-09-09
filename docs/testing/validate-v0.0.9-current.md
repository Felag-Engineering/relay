# Manual validation — baseline through `v0.0.9`

This is the **baseline** manual validation script (see [README.md](README.md) for the
convention): it covers the entire currently-shipped surface, v0.0.1 → v0.0.9
cumulatively, since no per-milestone scripts existed before it. Later milestones add
delta scripts on top of this one.

Everything here runs on **one Linux x86_64 machine** with no root required, driving the
product only through its real surfaces: the two binaries' CLI, the Control API
(`/api/v1`), the MCP tools, signals, and logs. The two exceptions — reading the audit
store directly, and finding an in-flight Job's ID — are marked where they occur.
Destructive steps (revocation, wrong-CA probes) come last; run them on a throwaway
setup.

Prerequisites: `curl`, `sqlite3` (or `python3` — noted where used), and a checkout that
builds (`make build`). Steps that need a **published release** or that are covered only
by **automated tests** are explicitly marked — see the roll-up list at the end.

Conventions used throughout:

```sh
REPO=/path/to/gleipnir-relay          # your checkout
WORK=$(mktemp -d)                     # scratch dir for CA, store, Policy, daemon state
RELAY_BIN=$REPO/relay/bin/relay
DAEMON_BIN=$REPO/daemon/target/debug/relay-daemon
cd "$WORK"
```

The Relay's control plane is TLS with a self-signed CA the Relay mints on first start;
every `curl` below passes `--cacert "$WORK/ca/ca-cert.pem"` and authenticates with the
bearer credential minted in step 2. The MCP endpoint is **stateless** streamable HTTP
(one JSON-RPC POST per call, no session), so plain `curl` drives it; define this helper
once step 2 has set `CRED`:

```sh
mcp() {
  curl -fsS --cacert "$WORK/ca/ca-cert.pem" \
    -H "Authorization: Bearer $CRED" \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -d "$1" https://localhost:9443/mcp
}
```

Any spec-compliant MCP client (Claude Code, MCP Inspector, …) pointed at
`https://localhost:9443/mcp` with the same bearer credential works equally; the raw
`curl` form is used here because it has zero extra dependencies and shows the exact
wire truth.

---

## 1. Build & stamp verification

```sh
cd "$REPO" && make build
"$RELAY_BIN" --version
"$DAEMON_BIN" --version
```

**Expect:** both binaries build; both print a one-line build stamp in the same format,
e.g.

```
relay 0.0.9-0.dev+g<sha> (commit <sha>, built YYYY-MM-DD)
relay-daemon 0.0.9-0.dev+g<sha> (commit <sha>, built YYYY-MM-DD)
```

A dev build (no exact clean tag) reports `<core>-0.dev+g<sha>[.dirty]`; a build on a
clean, exactly-tagged commit reports the bare tag version. Both binaries accept
`--version`, `-version`, and `-V` identically. See
[docs/operations/version-stamping.md](../operations/version-stamping.md).

**Discharges:** v0.0.1 "make build produces a relay and a relay-daemon binary";
v0.0.9 "version identity on both binaries" (#249, ADR-0014).

## 2. Stand up a local Relay with the control plane enabled

Mint the control-plane credential hash (plaintext via stdin only, never argv/env of the
hasher — see
[docs/operations/control-plane-credential.md](../operations/control-plane-credential.md)):

```sh
cd "$WORK"
CRED=$(head -c 24 /dev/urandom | base64)
printf '%s' "$CRED" | "$RELAY_BIN" hash-credential > cred.hash
chmod 600 cred.hash
```

Start the Relay — node-plane gRPC and control-plane HTTPS on **separate listeners**,
blast caps set by risk class (`mutate` deliberately 1 so step 11 can trip it with a
two-Node fleet):

```sh
"$RELAY_BIN" \
  -addr 127.0.0.1:7654 -hostname localhost \
  -ca-dir "$WORK/ca" -store-path "$WORK/relay.db" \
  -control-enabled -control-addr 127.0.0.1:9443 \
  -control-credential-hash-file "$WORK/cred.hash" \
  -read-blast-cap 50 -mutate-blast-cap 1 \
  > relay.log 2>&1 &
```

```sh
grep -o 'relay listening\|control-plane listening' relay.log
curl -fsS --cacert ca/ca-cert.pem -H "Authorization: Bearer $CRED" https://localhost:9443/api/v1/ping
curl -s -o /dev/null -w '%{http_code}\n' --cacert ca/ca-cert.pem https://localhost:9443/api/v1/ping
```

**Expect:** the startup log shows `relay listening` (with `version`, `read_blast_cap`,
`mutate_blast_cap` fields) *and* `control-plane listening`; the CA appears at
`$WORK/ca/ca-cert.pem`; authenticated ping returns `{"status":"ok"}`; the same request
**without** the credential returns `401`.

**Discharges:** v0.0.6 "listener separation", "a request to either surface without the
credential is refused"; v0.0.5 blast caps configured file/flag-only (ADR-0004/0010/0012,
invariant 11 — no API can change them).

## 3. Author a Policy file (with `policy check`)

The Policy grammar is documented in
[`daemon/policy.example.toml`](../../daemon/policy.example.toml). Write this validation
Policy — chosen so every later probe is deterministic:

```sh
cat > "$WORK/policy.toml" <<'EOF'
[[operation]]
name = "system.facts"
allowed_args = []

[[operation]]
name = "file.read"
allowed_args = [["*"]]

[[operation]]
name = "service.restart"
allowed_args = [["nginx"]]

[[deny]]
name = "file.read"
args = [["/etc/shadow"]]

[raw_exec]
allow = [
    "^/usr/bin/echo .*$",
    "^/bin/sleep [0-9]+$",
]
deny = [
    "^--force$",
]
EOF
chmod 600 policy.toml
```

(The daemon's fail-closed loader requires the file owned by root or the daemon's own
euid and not group/world-writable — `chmod 600` under your own user satisfies it for a
non-root local run.)

Lint it offline, exactly as an IaC pipeline would:

```sh
"$DAEMON_BIN" policy check "$WORK/policy.toml"; echo "exit=$?"
```

**Expect:** exit 0. (Exit codes are stable: 0 valid, 1 invalid, 2 would-deny.)

**Discharges:** v0.0.4 "`policy check` rejects a malformed file … and answers
`--would-allow` consistently with the live engine" (lint half; hypotheticals in step 12).

## 4. Mint a reusable, scoped Enrollment Token

```sh
RESP=$(curl -fsS --cacert ca/ca-cert.pem -H "Authorization: Bearer $CRED" \
  -H 'Content-Type: application/json' \
  -d '{"scope":["relay:env=validate","relay:fleet=local"],"ttl_seconds":86400,"max_uses":0}' \
  https://localhost:9443/api/v1/enrollment-tokens)
echo "$RESP"
TOKEN=$(echo "$RESP" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
```

**Expect:** `201` with `id`, the plaintext `token` (shown exactly once), the `scope`
echoed back, and `expires_at`. `max_uses: 0` = unlimited — one reusable token for the
whole fleet. A non-`relay:`-prefixed scope entry is rejected (`400`) — the token's scope
*is* the set of `relay:` Labels stamped at enrollment (ADR-0006); try it if you like.

**Discharges:** v0.0.2 enrollment-token model (reusable, scoped, expiring); v0.0.6 "the
seeded admin credential mints a scoped Enrollment Token over `/api/v1`".

## 5. Enroll two relay-daemons

Each daemon gets its own state dir (identity + dedup store) and its own `node:` labels;
both share the Policy file and the pinned CA bundle:

```sh
RELAY_ADDR=https://localhost:7654 \
RELAY_ENROLLMENT_TOKEN=$TOKEN \
RELAY_CA_BUNDLE_PATH=$WORK/ca/ca-cert.pem \
RELAY_STATE_DIR=$WORK/d1 \
RELAY_POLICY_PATH=$WORK/policy.toml \
RELAY_NODE_LABELS="role=web" \
  "$DAEMON_BIN" > d1.log 2>&1 &

RELAY_ADDR=https://localhost:7654 \
RELAY_ENROLLMENT_TOKEN=$TOKEN \
RELAY_CA_BUNDLE_PATH=$WORK/ca/ca-cert.pem \
RELAY_STATE_DIR=$WORK/d2 \
RELAY_POLICY_PATH=$WORK/policy.toml \
RELAY_NODE_LABELS="role=db" \
  "$DAEMON_BIN" > d2.log 2>&1 &
```

```sh
grep -o 'policy loaded.*\|received Ping from Relay' d1.log | head -3
```

**Expect:** each log shows enrollment, `policy loaded` **with the Policy fingerprint**,
and `received Ping from Relay` (the mTLS bidi stream is up). The persisted identities
land in `$WORK/d1` / `$WORK/d2`; on any later restart the daemon reuses its identity and
does **not** re-enroll (keep `RELAY_NODE_LABELS` set on restarts — `node:` labels are
node-rooted and re-asserted in every Hello).

**Discharges:** v0.0.2 "a fresh daemon enrolls with a token, receives a cert, reconnects
over mTLS"; ADR-0005/0006.

## 6. mTLS identity checks (fail-closed probes)

**(a) No identity, no token → refuses to run.**

```sh
RELAY_ADDR=https://localhost:7654 RELAY_STATE_DIR=$WORK/empty \
  RELAY_POLICY_PATH=$WORK/policy.toml "$DAEMON_BIN"; echo "exit=$?"
```

**Expect:** immediate non-zero exit: `no enrolled identity in state dir; refusing to
connect (fail closed, no plaintext)`.

**(b) Untrusted Relay → handshake fails closed.** *(Optional / mildly destructive:
temporarily repoints daemon-2.)* Start a second Relay with a **different CA**, stop
daemon-2, and point it there:

```sh
"$RELAY_BIN" -addr 127.0.0.1:7655 -hostname localhost \
  -ca-dir "$WORK/ca2" -store-path "$WORK/relay2.db" > relay2.log 2>&1 &
kill %3   # daemon-2's job number — adjust to yours
RELAY_ADDR=https://localhost:7655 RELAY_STATE_DIR=$WORK/d2 \
  RELAY_POLICY_PATH=$WORK/policy.toml timeout 8 "$DAEMON_BIN" > d2-wrongca.log 2>&1
grep -c 'TLS handshake rejected' d2-wrongca.log
```

**Expect:** the mTLS handshake fails on every attempt (mutual distrust: the daemon's
pinned trust root and its client cert both belong to the first CA) — the daemon logs
`TLS handshake rejected … will retry` with backoff and **never** falls back to
plaintext. Kill the second Relay and restart daemon-2 against `:7654` with its original
environment (including `RELAY_NODE_LABELS="role=db"`) before continuing.

> The strict *directional* assertions — a certless daemon rejected by the Relay, and a
> wrong-CA Relay rejected by the daemon in isolation — are automated:
> `make test-integration` (`scripts/smoke-test.sh` + the `//go:build integration`
> suite). Run it if you want them re-proven locally.

**Discharges:** v0.0.2 "a daemon pointed at a Relay with the wrong CA refuses to
proceed"; invariant 6 (ADR-0005/0006).

## 7. Registry, Facts, Labels via MCP

```sh
mcp '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_nodes","arguments":{}}}'
```

**Expect:** two Nodes, each with `node_id`, `facts` (hostname/os/kernel/arch/IPs),
`last_seen`, `node_labels` (`{"role":"web"}` / `{"role":"db"}`) and `relay_labels`
(`{"env":"validate","fleet":"local"}` — stamped from the token scope) as **separate
maps, never merged** (ADR-0006), plus `policy_fingerprint` (matching the daemons'
`policy loaded` log lines — fleet-wide drift visibility, ADR-0002), `revoked: false`,
`outdated: false`.

Then, with a `node_id` from that output:

```sh
mcp '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"describe_node","arguments":{"node_id":"<node_id>"}}}'
mcp '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_operations","arguments":{}}}'
```

**Expect:** `describe_node` returns the Node's **effective Policy** as reported by the
daemon (display-only mirror: `operation_rules`, `deny_rules`, `raw_exec` allow/deny
patterns, fingerprint) — the Relay renders what the daemon reported and never evaluates
or edits it. `list_operations` lists the four Native Operations (`system.facts`,
`file.read` — `read`; `service.restart`, `pkg.install` — `mutate`) with argument
constraints and risk classes legibly described (ADR-0001/0012, #253).

**Discharges:** v0.0.2 registry acceptance ("appears in the registry with correct
labels"); v0.0.4 "the registry shows a Node's Policy fingerprint"; v0.0.6
`list_nodes`/`describe_node`/`list_operations`, "describe_node shows the Node's
effective Policy".

## 8. Policy: allow, deny (rule reported), Raw Exec gating

**(a) Allowed Operation runs** (also the Job fan-out happy path — step 10):

```sh
mcp '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"run_operation","arguments":{"selector":"relay:env=validate","operation":"system.facts"}}}'
```

**Expect:** a `job_id` and one result per Node, both `"outcome":"success"` with Facts
JSON in `stdout`.

**(b) Denied by argument constraint:**

```sh
mcp '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"run_operation","arguments":{"selector":"node:role=web","operation":"service.restart","args":{"unit":"sshd"}}}}'
```

**Expect:** `"outcome":"denied_by_policy"`, stderr naming the reason: `no allow rule
matched args ["sshd"] for operation 'service.restart' …`. Nothing executed — the
verdict is the daemon's live engine, never the Relay's (ADR-0002/0011, invariant 12).

**(c) Denied by explicit deny rule (deny-beats-allow), rule reported:**

```sh
mcp '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"run_operation","arguments":{"selector":"node:role=web","operation":"file.read","args":{"path":"/etc/shadow"}}}}'
```

**Expect:** `denied_by_policy` with `denied by explicit rule for operation 'file.read'`
— even though the allow rule is `*`.

**(d) Raw Exec regex gate — allow and deny:**

```sh
mcp '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"raw_exec","arguments":{"selector":"node:role=web","argv":["/usr/bin/echo","hello"]}}}'
mcp '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"raw_exec","arguments":{"selector":"node:role=web","argv":["/usr/bin/id"]}}}'
```

**Expect:** the first succeeds (`stdout: "hello\n"` — argv spawn, no shell); the second
is `denied_by_policy` (no allow regex matches — deny-by-default).

**Discharges:** v0.0.3 "an Operation allowed by Policy runs …; one denied returns
denied-by-policy without executing", "`service.restart` constrained … refuses `sshd`",
Raw Exec regex gating (ADR-0001/0002, invariants 1/3).

## 9. Canonicalization edges (ADR-0018 / ADR-0019)

**(a) ADR-0018 — a non-canonical path spelling of an allowed path is denied:**

```sh
mcp '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"run_operation","arguments":{"selector":"node:role=web","operation":"file.read","args":{"path":"/etc/../etc/shadow"}}}}'
```

**Expect:** `denied_by_policy` with `path argument "/etc/../etc/shadow" is not in
canonical form (ADR-0018): must be absolute with no '.', '..', '//', or trailing-slash
segment`.

**(b) ADR-0019 — the #227 shape: a denied token merged into an adjacent argv element.**
The Policy's deny is *anchored per-element* (`^--force$`); the probe smuggles it as
`"--force merged"` in a single element, which neither the raw element nor the joined
command matches:

```sh
mcp '{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"raw_exec","arguments":{"selector":"node:role=web","argv":["/usr/bin/echo","--force merged"]}}}'
```

**Expect:** `denied_by_policy` with `raw exec denied by pattern "^--force$" (matched
canonical element "--force")` — the deny fired on the **canonical element** (the joined
command re-split on whitespace), which is exactly what closes #227.

**Discharges:** v0.0.9 "the #227 reproduction is denied" (ADR-0019); ADR-0018 canonical
path matching (v0.0.8 red-team residuals).

## 10. Job fan-out via Selector with per-Node outcomes

Already exercised in 8(a) (both Nodes) vs 8(b) (`node:role=web` → one Node). One more
probe — per-Node divergence in a single Job: stop daemon-2 (`kill %3`, adjust job
number), then:

```sh
mcp '{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"run_operation","arguments":{"selector":"relay:env=validate","operation":"system.facts"}}}'
```

**Expect:** one Job, two Tasks, per-Node outcomes diverging: `success` for daemon-1 and
`unreachable` for the stopped daemon-2 — offline Nodes fail fast at dispatch, no
store-and-forward (ADR-0004). Restart daemon-2 (with its full original environment) and
confirm it reappears in `list_nodes` with a fresh `last_seen`.

**Discharges:** v0.0.5 "a Job spanning an offline Node reports `unreachable` for it and
real results for the rest"; v0.0.6 "an MCP client calls
run_operation(selector, system.facts) and gets per-Node results" (ADR-0003/0004).

## 11. Blast-cap refusal (read vs mutate caps)

The Relay was started with `-read-blast-cap 50 -mutate-blast-cap 1`. With both daemons
connected:

```sh
# read class across 2 Nodes: within the read cap — succeeds (see 8a)
# mutate class (Raw Exec is ALWAYS mutate) across 2 Nodes: exceeds the mutate cap
mcp '{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"raw_exec","arguments":{"selector":"relay:env=validate","argv":["/usr/bin/echo","hello"]}}}'
```

**Expect:** a refusal **before any Task is sent**: `blast-radius cap exceeded: selector
matched 2 nodes, exceeds the mutate-cap of 1 (risk class mutate)…` — while the same
2-Node fan-out in `read` class (step 8a) ran fine. This shows the split caps chosen by
risk class and that Raw Exec takes the mutate-cap even for a harmless command.

**Discharges:** v0.0.5 "a Selector matching more Nodes than the applicable cap is
rejected before any Task runs"; ADR-0012 split caps + Raw Exec always mutate
(invariants 5/13).

## 12. Plan mode (daemon-evaluated hypotheticals)

**(a) Plan a denied action — verdicts without execution:**

```sh
mcp '{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"run_operation","arguments":{"selector":"relay:env=validate","operation":"file.read","args":{"path":"/etc/shadow"},"plan":true}}}'
```

**Expect:** `plan.matched: 2`, a per-Node `verdict: "deny"` **with the deciding rule**,
the point-in-time advisory, an empty `results` array, and **no `job_id`** (a Plan
executes nothing — #253 result-shape contract). Then run the same call without
`plan` and confirm the real outcome matches the verdict (v0.0.4's
consistency acceptance).

**(b) Over-cap Plan reports `would_be_rejected` instead of erroring:**

```sh
mcp '{"jsonrpc":"2.0","id":14,"method":"tools/call","params":{"name":"raw_exec","arguments":{"selector":"relay:env=validate","argv":["/usr/bin/echo","x"],"plan":true}}}'
```

**Expect:** `would_be_rejected: {cap: 1, class: "mutate", matched: 2, reason:
"exceeds_cap"}` — and no dispatch.

**(c) Offline hypotheticals through the same engine (`policy check --would-allow`):**

```sh
"$DAEMON_BIN" policy check "$WORK/policy.toml" --would-allow operation file.read path=/etc/shadow; echo "exit=$?"
"$DAEMON_BIN" policy check "$WORK/policy.toml" --would-allow raw-exec -- /usr/bin/echo "--force merged"; echo "exit=$?"
```

**Expect:** both print `would-allow: DENY (deciding rule: …)` and exit 2, with the
**same deciding-rule text** the live probes produced in steps 8–9 — one evaluator, no
Relay-side reimplementation (ADR-0011, invariant 12).

**Discharges:** v0.0.4 "`PolicyQuery` verdicts match what real execution then does",
`policy check --would-allow`; v0.0.6 "run_operation(…, plan=true) returns per-Node
verdicts and executes nothing", "over-cap Plans report would-be-rejected" (ADR-0011).

## 13. At-most-once / dedup sanity across reconnect

Restart the Relay with the **same flags** as step 2 (same `-ca-dir`, same
`-store-path`), then watch the daemons:

```sh
kill %1 && sleep 1   # the Relay's job number — adjust
# ... re-run the exact step-2 relay command ...
sleep 6
mcp '{"jsonrpc":"2.0","id":15,"method":"tools/call","params":{"name":"list_nodes","arguments":{}}}'
mcp '{"jsonrpc":"2.0","id":16,"method":"tools/call","params":{"name":"get_job","arguments":{"job_id":"<job_id from step 8a>"}}}'
```

**Expect:** both daemons reconnect on their own (fresh `last_seen`, no re-enrollment —
the same `node_id`s); Jobs/Tasks survived the restart (`get_job` returns the step-8a
Job with its original per-Node results, unchanged — nothing re-ran).

> The rigorous at-most-once proof — **crash the Relay mid-Job** and show the Task is
> not re-run on restart+reconnect (v0.0.5's crash-mid-Job acceptance, ADR-0004), and
> re-sending a seen Task ID across a reconnect (v0.0.3) — is timing-dependent and
> automated: `make test-crossbinary` (TestFleetE2E, real binaries, real crash). Run it
> as part of this validation.

**Discharges:** v0.0.7 "killing and restarting the Relay: daemons reconnect, dedup
holds, no Task double-runs" (manual half); v0.0.5 "Jobs/Tasks survive a Relay restart";
v0.0.3/v0.0.5 at-most-once (automated half, invariant 4).

## 14. Cancellation of an in-flight Task, and the timeout kill

**(a) Timeout:** a Task exceeding its timeout is killed (whole process group) and
reports `timeout`:

```sh
mcp '{"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":"raw_exec","arguments":{"selector":"node:role=web","argv":["/bin/sleep","300"],"timeout_seconds":2}}}'
```

**Expect:** `"outcome":"timeout"` after ~2s, and **no `exit_code` key at all** (the
process was killed without a status — the #253 result-shape contract).

**(b) Cancellation:** `run_operation`/`raw_exec` block until terminal outcomes, so start
a long Task in the background, then cancel it by Job ID:

```sh
mcp '{"jsonrpc":"2.0","id":18,"method":"tools/call","params":{"name":"raw_exec","arguments":{"selector":"node:role=db","argv":["/bin/sleep","120"],"timeout_seconds":120}}}' > cancel_out.json &
sleep 2
JOB_ID=$(sqlite3 "file:$WORK/relay.db?mode=ro" \
  "SELECT job_id FROM jobs ORDER BY created_at DESC LIMIT 1;")
mcp "{\"jsonrpc\":\"2.0\",\"id\":19,\"method\":\"tools/call\",\"params\":{\"name\":\"cancel_job\",\"arguments\":{\"job_id\":\"$JOB_ID\"}}}"
wait; cat cancel_out.json
mcp "{\"jsonrpc\":\"2.0\",\"id\":20,\"method\":\"tools/call\",\"params\":{\"name\":\"get_job\",\"arguments\":{\"job_id\":\"$JOB_ID\"}}}"
```

> **Marked store-read:** there is currently **no surface that lists in-flight Jobs**
> (`run_operation`/`raw_exec` return the `job_id` only when they return, and the audit
> decision log line is emitted at resolution) — so the in-flight `job_id` is read from
> the Relay's store here. That is a real surface gap, noted in the roll-up list; the
> read is read-only (`mode=ro`) and does not drive anything.

**Expect:** `cancel_job` acknowledges with the Job ID; the blocked background call then
returns promptly with `"outcome":"cancelled"` (the daemon killed the Task's process
group); `get_job` re-reads the same truthful outcome. A Task that had already finished
would keep its real outcome — never a retroactive cancel.

**Discharges:** v0.0.3 timeout-kill acceptance; v0.0.4 "cancelling an in-flight Task
kills its process group and reports cancelled"; v0.0.5 Job-level cancel (ADR-0013);
v0.0.9 result-shape legibility (#253).

## 15. Freeze engage / release

```sh
curl -fsS --cacert ca/ca-cert.pem -H "Authorization: Bearer $CRED" \
  -X POST https://localhost:9443/api/v1/freeze/engage
mcp '{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"run_operation","arguments":{"selector":"node:role=web","operation":"system.facts"}}}'
mcp '{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"run_operation","arguments":{"selector":"node:role=web","operation":"system.facts","plan":true}}}'
curl -s -o /dev/null -w '%{http_code}\n' --cacert ca/ca-cert.pem \
  -H "Authorization: Bearer $CRED" -H 'Content-Type: application/json' \
  -d '{}' -X POST https://localhost:9443/api/v1/freeze/release
curl -fsS --cacert ca/ca-cert.pem -H "Authorization: Bearer $CRED" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"validation drill complete"}' \
  -X POST https://localhost:9443/api/v1/freeze/release
```

**Expect:** engage returns `{"engaged":true}` (no reason needed — engaging is cheap);
the dispatch while frozen is refused before any Task is sent (`the Relay-wide Freeze is
engaged (ADR-0013)…`); **Plans still work while frozen**; release with an empty reason
is `400` (releasing is deliberate — the reason is audited); release with a reason
returns `{"engaged":false}`. Optional probes: the Freeze persists across a Relay
restart; the local host-side lever is `SIGUSR1` (engage) / `SIGUSR2` (release, reason
from `RELAY_FREEZE_RELEASE_REASON`) on the Relay process.

**Discharges:** v0.0.5 "engaging the Freeze stops a subsequent dispatch before any Task
is sent"; v0.0.6 "the Freeze can be engaged and released over the API" (ADR-0013).

## 16. Audit-trail read-back (attribution of everything above)

Two real read paths exist today:

**(a) The decision log** — every dispatch/refusal/Plan/Freeze/cancel emits exactly one
structured `audit decision` line (attribution + routing metadata only, never args or
output):

```sh
grep 'audit decision' relay.log | head -20
```

**Expect:** lines like `audit decision kind=dispatch principal=founding-admin:admin
selector="relay:env=validate" action_kind=operation operation=system.facts
job_id=job-… matched=2 outcome_counts="success=2"`, plus `kind=refusal` (the cap and
Freeze refusals with reasons), `kind=plan`, `kind=freeze_engage`/`freeze_release`, and
`kind=job_cancel` — each attributed to the principal.

**(b) The durable store** — *marked store-read:* the v0.0.5 acceptance criterion is
explicitly about stored state ("every dispatch produces a **queryable audit record**"),
and no dedicated audit read surface exists yet (a known gap), so query the store
directly, read-only:

```sh
sqlite3 -readonly "$WORK/relay.db" \
  "SELECT kind, principal, selector, operation_name, node_id, outcome, reason
   FROM audit ORDER BY ts;"
```

**Expect:** one row per event of everything this script did, in order: `token_mint`
(with the token id, **never** the plaintext token), per-Task `dispatch` rows (success /
denied-by-policy / timeout / cancelled / unreachable outcomes), `refusal` rows (cap,
Freeze), `plan` rows, `freeze_engage`/`freeze_release` (with the release reason),
`job_cancel` — every row attributed `founding-admin:admin`. Captured output is stored
on dispatch rows (full-output retention posture: see
[docs/operations/audit-output-retention.md](../operations/audit-output-retention.md))
but never appears in the log lines.

**Discharges:** v0.0.5 "every dispatch produces a queryable audit record" +
audit-everything (principal, selector, op, result); v0.0.7 observability; v0.0.8
secret-handling posture spot-check (no token plaintext in logs or audit).

## 17. Minimum-daemon-version gate (`outdated`)

Restart the Relay (same flags as step 2) **plus** `-min-daemon-version 99.0.0`, wait
for the daemons to reconnect, then:

```sh
mcp '{"jsonrpc":"2.0","id":23,"method":"tools/call","params":{"name":"list_nodes","arguments":{}}}'
mcp '{"jsonrpc":"2.0","id":24,"method":"tools/call","params":{"name":"run_operation","arguments":{"selector":"node:role=web","operation":"system.facts"}}}'
```

**Expect:** both Nodes stay **connected** and visible but flagged `"outdated": true`
(the flag is computed against the daemons' self-reported, build-stamped versions);
dispatch to them is refused **per-Task** with `"outcome":"version_refused"` (`this
Node's relay-daemon reports a version below the Relay's configured minimum…`) — the
connection is never severed; the lever is dispatch-level only (the daemon never
self-upgrades, the Relay never pushes binaries). Plan verdicts also carry the per-Node
`outdated` flag. Restart the Relay without the flag and confirm dispatch works again.

**Discharges:** v0.0.7 "a below-minimum-version daemon connects and appears outdated …
but dispatch to it is refused per-Task"; v0.0.9 "its true version drives the outdated
gate" (ADR-0014, invariant 14).

## 18. Revocation (destructive — run last)

**(a) Node revocation drops connectivity immediately:**

```sh
# node_id of daemon-2 from list_nodes
curl -fsS --cacert ca/ca-cert.pem -H "Authorization: Bearer $CRED" \
  -H "Content-Type: application/json" -d '{"reason":"v0.0.9 validation: revoking daemon-2"}' \
  -X POST "https://localhost:9443/api/v1/nodes/<node_id>/revoke" -w '%{http_code}\n'
sleep 4 && tail -2 d2.log
mcp '{"jsonrpc":"2.0","id":25,"method":"tools/call","params":{"name":"list_nodes","arguments":{}}}'
```

**Expect:** `204`; daemon-2's live stream drops and every reconnect attempt is rejected
at the mTLS layer (`TLS handshake rejected by Relay — client cert untrusted, expired,
or revoked; will retry`); `list_nodes` shows the Node `"revoked": true`. Revocation
survives a Relay restart (the denylist is rehydrated from the store).

**(b) A revoked Enrollment Token can no longer enroll** (mint a fresh token, revoke it
unused, then attempt an enrollment with it — revoking a token also cascade-revokes any
Nodes it enrolled, which is why this probe uses a fresh token and a fresh state dir):

```sh
# mint as in step 4 → T2 / T2ID, then:
curl -fsS --cacert ca/ca-cert.pem -H "Authorization: Bearer $CRED" \
  -X DELETE "https://localhost:9443/api/v1/enrollment-tokens/$T2ID" -w '%{http_code}\n'
RELAY_ADDR=https://localhost:7654 RELAY_ENROLLMENT_TOKEN=$T2 \
  RELAY_CA_BUNDLE_PATH=$WORK/ca/ca-cert.pem RELAY_STATE_DIR=$WORK/d3 \
  RELAY_POLICY_PATH=$WORK/policy.toml timeout 6 "$DAEMON_BIN" > d3.log 2>&1
grep -i 'denied\|error' d3.log | head -2
```

**Expect:** `204` on revoke; the enrollment attempt is **denied** — no identity is
issued, nothing appears in the registry.

**Discharges:** v0.0.2 "revoking a Node immediately drops its ability to connect";
v0.0.6 "a revoked token can no longer enroll" (ADR-0006).

## 19. Structural invariants (verified by automated suites — do not skip)

These acceptance items are real but not meaningfully *manual*; run the suites as part of
this validation and record them in the sign-off:

```sh
cd "$REPO"
make test              # hermetic suites, both toolchains
make test-integration  # mTLS smoke + real-wire integration tests
make test-crossbinary  # real relay + relay-daemon fleet e2e, incl. crash-mid-Job
```

- **The Relay cannot alter a Node's Policy over the wire (v0.0.3, "verified by
  attempt"):** no Policy-write message exists in `/proto` to even attempt with;
  `relay/cmd/relay/policy_immutability_test.go` and the daemon's handling prove the
  invariant (ADR-0002, invariant 2). Manual corroboration: nothing in `list_operations`,
  `/api/v1`, or MCP touches Policy, and `describe_node` is display-only.
- **Per-Node concurrency by risk class (v0.0.4):** mutate serial / read parallel is a
  timing property; the daemon's scheduler test suite covers it.
- **Crash-mid-Job at-most-once (v0.0.5)** — `make test-crossbinary` (see step 13).
- **CI-only gates:** proto additive-only (buf breaking, v0.0.7), clippy `--all-targets`
  gate + nightly fuzz jobs (v0.0.8/v0.0.9), CI green on clean checkout (v0.0.1).
- **v0.0.8 adversarial pass:** the threat model exists at `docs/security/`; the Raw
  Exec red-team regression suite and wire fuzzers run in `make test` / nightly CI. The
  manual spot-checks are step 9's canonicalization probes.

## 20. Artifact verify-then-install path — **requires a published release**

> **Cannot be run until a `v*` tag has been pushed and its GitHub Release published**
> (no release tag exists at the time this script was written). When one exists, follow
> [docs/operations/release-artifacts.md](../operations/release-artifacts.md) verbatim:

```sh
VERSION="X.Y.Z"   # the pinned release
ARTIFACT="relay-daemon-${VERSION}-x86_64-unknown-linux-musl"
BASE="https://github.com/Felag-Engineering/gleipnir-relay/releases/download/v${VERSION}"
curl -fsSLO "${BASE}/${ARTIFACT}" && curl -fsSLO "${BASE}/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS        # BEFORE install
install -m 0755 "${ARTIFACT}" /usr/local/sbin/relay-daemon
/usr/local/sbin/relay-daemon --version               # must self-identify as ${VERSION}
```

**Expect:** the digest verifies **before** install; the installed binary reports exactly
the pinned version (the release workflow's stamped-version-equals-tag guard makes
filename, tag, and `--version` one string). Also verify the failure path: corrupt one
byte of the downloaded artifact and confirm `sha256sum --check` fails and you stop.
The full "daemon installed from a published artifact enrolls, connects, is dispatched
to, enforces Policy, and is audited across ≥2 Nodes" gate (#254) is this script's steps
5–18 executed with the installed artifact instead of the dev build — that combination
is the v0.0.9 milestone gate and the entry ticket to
[validate-v0.1.0-beta.md](validate-v0.1.0-beta.md).

**Discharges (when runnable):** v0.0.9 "pushing a v* tag publishes verified,
checksummed, self-identifying artifacts; a digest mismatch fails the documented install
path" + the #254 milestone gate (ADR-0007/0014).

---

## Sign-off

| Field | Value |
|---|---|
| Date | |
| `relay --version` output | |
| `relay-daemon --version` output | |
| Git commit validated | |
| Steps passed | |
| Steps skipped (and why) | |
| Automated suites run (`make test` / `test-integration` / `test-crossbinary`) | |
| Operator | |

Known items **not manually validatable today** (restate in the sign-off if unchanged):
step 20 (no published release yet); crash-mid-Job and concurrency-by-class (automated
only); CI-only gates; the missing audit/Job read surfaces that force the two marked
store-reads (steps 14b and 16b).
