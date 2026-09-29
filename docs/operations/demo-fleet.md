# The demo fleet

The nine-Node `demo` compose profile of the [local dev fleet](../dev-fleet.md), as a runbook:
roster, beats, fault injection and resetting between takes, and resource usage. Read
[dev-fleet.md](../dev-fleet.md) first — its **DEV-ONLY** banner, prerequisites, bring-up and MCP
connection all apply here, with more force: three times the Nodes sit behind the same committed
dev credential. This file is also the presenter's runbook for the Relay half of a stage demo
([Presenter runbook](#presenter-runbook), below) — the overall script, including Gleipnir's own
half of it, lives in [the Gleipnir-side runbook](https://github.com/Felag-Engineering/gleipnir/issues/933).
Gleipnir is the AI-agent that drives the demo: a consumer of Relay, never a part of it.

## Presenter runbook

A presenter who has never run this fleet, from cold to on stage: bring-up, the credentials
Gleipnir authenticates with, the human approver, the scripted bypass beat, the fault, and reset.

### Posture, stated once

This is containers on a laptop, not a production deployment. Every warning in
[dev-fleet.md](../dev-fleet.md)'s **DEV-ONLY** banner applies here, with more force: nine Nodes
sit behind the very same committed dev credential, the control plane is loopback-only, and every
container shares one kernel. This section makes no hardening claims. It is worth saying anyway,
because the Node's refusal in the bypass beat below is produced by the same relay-daemon Policy
engine whether it runs in a container on a laptop or on a server in a datacenter — the posture
paragraph costs nothing to state, and the refusal is real either way. One more number, stated
once: the issue that commissioned this runbook planned for about 24 Nodes; the demo profile as
built ([#452](https://github.com/Felag-Engineering/gleipnir-relay/issues/452)) is nine, and every
count below is for nine.

### From cold to ready

1. **Prerequisites.** Docker Engine with the Compose v2 plugin, `python3` (both
   `scripts/dev-fleet-mcp.sh` and `scripts/demo-fleet.sh` shell out to it), and `curl`. Add the
   `/etc/hosts` mapping for any client other than `scripts/dev-fleet-mcp.sh` (that script pins
   with `curl --resolve`, so it does not need it) — the control plane's server certificate has a
   single SAN, `relay`, and Gleipnir and Claude Code both need to dial that name to get verified
   TLS. Reuse the exact one-liner from
   [Connecting Claude Code](../dev-fleet.md#connecting-claude-code):

   ```console
   $ grep -q 'relay$' /etc/hosts || echo '127.0.0.1 relay' | sudo tee -a /etc/hosts
   ```

   Host ports `7654` and `9443` must be free: `make demo-reset` refuses if another compose
   project already publishes them.

2. **`make demo-build`.** Do it the day before, not on stage — it is the only demo-fleet target
   that builds anything, and again after any code change. It also fetches the images of the
   services that are never built (today `curlimages/curl`, for the `approver`,
   `console-admin` and `bootstrap` one-shots), only where they are missing, so a fresh Docker
   engine is left ready for `make demo-reset`, which never pulls.

3. **`make demo-reset`.** Expected closing output *(predicted — the literal `echo` lines in
   `scripts/dev-fleet-mcp.sh`'s `cmd_init` and `scripts/demo-fleet.sh`'s `cmd_reset`)*, in this
   order, after compose's own progress output:

   ```
   dev-fleet-mcp: CA cert and both credentials are in .dev-fleet/
   dev-fleet-mcp: copy-paste launch commands: .dev-fleet/start-claude.txt
   demo-fleet: reset complete — 9 Nodes healthy, 6 web Nodes serving, .dev-fleet/ refreshed with the fresh credentials this reset just minted.
   demo-fleet: the CA was regenerated, so a registered MCP client still holds the OLD bearer token AND the OLD CA (NODE_EXTRA_CA_CERTS is read only at process start). Restart it — .dev-fleet/ is already current, so there is no need to run 'make demo-creds' again first:
   demo-fleet:   claude mcp remove relay
   demo-fleet:   claude mcp add --transport http relay https://relay:9443/mcp --header "Authorization: Bearer $(cat .dev-fleet/control-credential)"
   ```

   **Failure.** The script exits non-zero with a message prefixed `demo-fleet: ` on stderr. Some
   messages name a service (a web Node not serving; the health wait lists what it is still
   waiting on); others name only the step that failed (`compose down`/`up`, the approvals check,
   `list_nodes`). Read the message: it names the step, and the service where it knows one — do
   not expect every failure to name a service.

4. **Enrollment timing from cold. Unmeasured.** No one has timed a cold `make demo-reset` at
   nine Nodes, and no number is invented here. The only bound in code is `DEMO_WAIT_SECONDS`,
   default 240s — reset fails past it, which is a timeout, not a measurement. To measure it: run
   `make demo-build` once, then `time make demo-reset` three times back to back, recording wall
   time and machine below (same style as [Resource usage](#resource-usage)):

   | measured on | date | who | `demo-build` (first run) | `demo-reset` cold wall time — run 1 | run 2 | run 3 |
   | --- | --- | --- | --- | --- | --- | --- |
   | _unmeasured_ | _unmeasured_ | _unmeasured_ | _unmeasured_ | _unmeasured_ | _unmeasured_ | _unmeasured_ |

   **Credential lifetime.** Every credential a reset mints expires 24h later — the founding
   admin's (`-ttl 24h`, `docker/mint-credential.sh`) and `dev-approver`'s (`ttl_seconds` 86400,
   `docker/mint-approver.sh`) — and the Gleipnir token minted below matches that same 86400s. So
   reset on demo day, not the night before.

5. Mint Gleipnir's credentials — [Credentials for Gleipnir (copy-paste)](#credentials-for-gleipnir-copy-paste),
   next — then run [Confirming the reset took](#confirming-the-reset-took).

### Credentials for Gleipnir (copy-paste)

**Re-run this after every reset.** `make demo-reset` runs `down -v`, which destroys the store:
the `gleipnir` machine Account, its API Token, and the CA all die with it. After running the
block below, make Gleipnir pick up the new token and the new CA. How Gleipnir reloads them
(restart, or otherwise) is Gleipnir's own runbook to document
([gleipnir#933](https://github.com/Felag-Engineering/gleipnir/issues/933)) — most clients read a
CA only at process start, so restarting it is the safe assumption *(predicted)*. A `make
demo-up` keeps the store, so the Gleipnir token survives it; only `demo-reset` requires a re-run.

The block below is one fenced shell block, run from the repo root. It runs in a subshell with
fail-fast settings, is safe to re-run (create-or-lookup), never echoes the token, and writes the
token file `0600` with no trailing newline. The shell below is literal — copy it as written:

```console
$ ( set -euo pipefail; umask 077
    find_id() {
      scripts/dev-fleet-mcp.sh api GET /api/v1/accounts \
        | python3 -c 'import json,sys; print(next((a["id"] for a in json.load(sys.stdin)["accounts"] if a["name"]=="gleipnir"), ""))'
    }
    ACCOUNT_ID=$(find_id)
    if [ -z "$ACCOUNT_ID" ]; then
      scripts/dev-fleet-mcp.sh api POST /api/v1/accounts \
        '{"name":"gleipnir","kind":"machine","role":"operator"}' >/dev/null
      ACCOUNT_ID=$(find_id)
    fi
    test -n "$ACCOUNT_ID" || { echo "no gleipnir Account id; is .dev-fleet/ current?" >&2; exit 1; }
    scripts/dev-fleet-mcp.sh api POST "/api/v1/accounts/$ACCOUNT_ID/tokens" \
      '{"name":"gleipnir-demo","ttl_seconds":86400}' \
      | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin)["token"])' \
      > .dev-fleet/gleipnir-credential.tmp
    test -s .dev-fleet/gleipnir-credential.tmp
    mv .dev-fleet/gleipnir-credential.tmp .dev-fleet/gleipnir-credential
    echo "gleipnir: Account $ACCOUNT_ID; API Token in .dev-fleet/gleipnir-credential" )
```

Expected output *(predicted)*: the one `gleipnir: Account ...` line. A python traceback here
(typically a `KeyError`) means the call it wraps was refused — re-run the same
`scripts/dev-fleet-mcp.sh api` call without the python filter to see why (most likely
`.dev-fleet/` is stale; run `make demo-creds`).

Why each guard, stated once on the page:

- `scripts/dev-fleet-mcp.sh api` exits 0 even on an HTTP error (plain `curl -sS`, no `--fail`,
  then a pretty-printer), so the guards above test the extracted values, not the exit code. A
  409 on the create call (name already taken) is harmless: the second `find_id` resolves the id
  regardless. This mirrors `docker/mint-approver.sh`'s own create-then-resolve pattern.
- Without `pipefail` and the tmp-then-`mv` step, a failed mint would leave an empty file that
  looks like a credential. With them, the real file only ever holds a token. A run that fails
  before the `mv` can leave `.dev-fleet/gleipnir-credential.tmp` behind — harmless (it is
  `0600`, inside the gitignored `.dev-fleet/`, and the next successful run overwrites it before
  renaming it), but safe to `rm -f` before re-running if you want a clean directory.
- No trailing newline, so a client that reads the file verbatim into a header does not send one.

Field names come from the code
(`relay/internal/controlplane/api/accounts.go`). The list response is an object with an
`"accounts"` array, each entry carrying `"id"`, `"name"`, `"kind"` and `"role"`. The mint
response carries `"api_token"` (redacted metadata) and `"token"` (the `glp_` plaintext).
`ttl_seconds` is required — `0` means a token that never expires, so never use `0` here. Account
`kind` is `"human"` or `"machine"`.

The role choice, stated plainly:

- **`kind: "machine"`.** The AI-agent authenticates as a machine Account (GLOSSARY). Whatever
  `requester_allowed` says, Relay refuses a machine Account's answer to its own request
  (`approval.ErrMachineSelfDecision`) unless it arrives in-band carrying a non-blank asserted
  name — the `approver` on `approve_request`, or the responder on an answered approval
  question — which is recorded as an assertion beside Gleipnir's verified identity, never as
  verified. Relay cannot tell whether a human gave that name: an AI-agent steered by prompt
  injection could call `approve_request` with a made-up name and release its own request. That
  is the accepted client-integrity assumption of in-band approval
  ([approval.md, Channel strength](../specs/approval.md#channel-strength); ADR-0029), not a
  guarantee this fleet adds. It cannot engage the Freeze (human-only).
- **`role: "operator"` is the default and the recommendation.** It is the lowest role that can
  run the demo's Operations (running an Operation needs `operator`; `authz.requiredRole`) — the
  "lowest role that does its job" rule
  [control-plane-credential.md](control-plane-credential.md) states. An operator also cannot mint
  an API Token for anyone through the Control API. See
  [The human approver](#the-human-approver) for who may decide what under the demo gate.
- **What operator can do, and what it costs.** Raw Exec is admin-only, so Gleipnir cannot
  request the Raw Exec repair of the fault — the presenter drives that one by hand (see
  [Triggering and clearing the fault](#triggering-and-clearing-the-fault)). But Gleipnir can
  discover the fault with a read (`file.read`) and repair it with a gated mutate of its own:
  `service.restart` with unit `nginx` on `node:role=web, node:env=prod` (fan-out 2, mutate
  class) parks under `demo-fleet-wide-mutates-need-a-human` — a different rule from the one
  beat (c) below exercises (`demo-raw-exec-always-needs-a-human`, which is Raw Exec-specific,
  not fan-out-specific). Because that rule is in-band, Relay sends the approval question to
  Gleipnir — a client declaring the name `gleipnir` — and Gleipnir's retry carrying an answer
  with a responder named runs the Job. That Gleipnir puts the question to a human in its own UI,
  and that the named responder is that human, is Gleipnir's behaviour, which Relay does not
  verify (see `kind: "machine"` above). On the web Nodes `service.restart`
  reaches the dev-fleet demo service through the DEV-ONLY `systemctl` shim
  ([The fixture limit, stated plainly](../dev-fleet.md#the-fixture-limit-stated-plainly)), so
  it restarts the real `httpd` on `daemon-4` and `daemon-5`: 2 × `success, exit_code: 0`, and a
  faulted `daemon-4` is serving again. Observed on a live fleet: the question asked and the
  answered retry running its Job; `service.restart` of `nginx` exiting `0` on a web Node. The
  combination on this exact Selector, and the fault clearing through it, is *(predicted)*.
  Beat (d) is unaffected: both of its Selectors are fan-out 1, so it runs with no human, and
  `operator` is enough to run it.
- **`role: "admin"` is the alternative**, and its trade-off is named rather than hidden: it lets
  Gleipnir request the Raw Exec repair itself, and a Raw Exec is decided at `admin` too — the
  floor for deciding is the floor for requesting. Account and API-Token administration are
  admin-only and not human-only (`authz.requiredControlRole`; the owner decision to narrow them
  is recorded there as open), so a machine admin can also mint API Tokens for other Accounts.
  It is not free for approvals either: under the demo gate an `admin` Gleipnir can release its
  own Raw Exec exactly as an `operator` Gleipnir can release its own Operation — an in-band
  answer carrying a name it supplied itself — so with `admin`, every Raw Exec on this fleet is
  one Gleipnir could request and release alone (see `kind: "machine"` above and
  [The human approver](#the-human-approver)). If you choose `admin`, change `"operator"` to
  `"admin"` in the create body above. **A human should confirm this choice** before a presenter
  relies on it, and the Gleipnir-side runbook
  ([gleipnir#933](https://github.com/Felag-Engineering/gleipnir/issues/933)) must agree with
  whichever role is actually used.
- A pre-existing `gleipnir` Account is reused as it is, whatever its role. To see its role, read
  `"role"` in `scripts/dev-fleet-mcp.sh api GET /api/v1/accounts`. After a reset there is none.

**Export the CA.** `.dev-fleet/ca-cert.pem` is written by `make demo-reset` (it runs
`scripts/dev-fleet-mcp.sh init`) and by `make demo-creds`. Give Gleipnir exactly three values:
the MCP URL `https://relay:9443/mcp`; the CA file (the absolute path of
`.dev-fleet/ca-cert.pem`); and the API Token in `.dev-fleet/gleipnir-credential`, sent in an
`Authorization: Bearer` header. Gleipnir's own config keys are Gleipnir's to document
([gleipnir#933](https://github.com/Felag-Engineering/gleipnir/issues/933)/[#928](https://github.com/Felag-Engineering/gleipnir/issues/928))
— they are not invented here.

Optional, needs `openssl`:

```console
$ openssl x509 -in .dev-fleet/ca-cert.pem -noout -subject -enddate -fingerprint -sha256
```

Verify the new API Token over verified TLS, mirroring the script's own `curl` flags:

```console
$ curl -sS --resolve relay:9443:127.0.0.1 --cacert .dev-fleet/ca-cert.pem \
    -H "Authorization: Bearer $(cat .dev-fleet/gleipnir-credential)" \
    https://relay:9443/api/v1/approvals
```

Expected *(predicted)*: an empty `approvals` array. Any authenticated caller may read the queue
(`handleListApprovals`). Then prove the token is not an admin's:

```console
$ curl -sS -o /dev/null -w '%{http_code}\n' --resolve relay:9443:127.0.0.1 \
    --cacert .dev-fleet/ca-cert.pem \
    -H "Authorization: Bearer $(cat .dev-fleet/gleipnir-credential)" \
    https://relay:9443/api/v1/accounts
```

Expected *(predicted)*: `403` — the floor is enforced in the capability layer
(`writeAccountError` mapping `authz.ErrUnauthorized`), not a route-specific check. An admin
token would get `200`.

Like `scripts/dev-fleet-mcp.sh`, the verify commands above put the token on `curl`'s command
line for the life of the call, where other local users of the laptop can see it. That is
acceptable on a single-user dev laptop; never do it on a shared host.

The token plaintext appears once, at mint (GLOSSARY: API Token). Never paste it anywhere but
Gleipnir's own secret input, and never copy it off the laptop.

### The human approver

**The demo fleet runs its own gate, and it is in-band.** `make demo-reset` and `make demo-up`
start the Relay on `docker/fixtures/approval-gates.demo.json`, not on the default fleet's
`approval-gates.json` ([The approval gate](../dev-fleet.md#the-approval-gate)):
`scripts/demo-fleet.sh` sets `DEV_FLEET_APPROVAL_GATE_CONFIG`, which `docker-compose.yml` hands
the Relay as `RELAY_APPROVAL_GATE_CONFIG`. A bare `docker compose --profile demo up` sets
nothing and gets the default fleet's out-of-band gate — one more reason to use the `make demo-*`
targets. Both files are baked into the relay image root-owned `0644`. No API writes either of
them: gate rules are file-loaded today, so the only way to change them is a new image and a
restart. (Invariant 11 would permit gate rules to become a runtime object, edited only by a
human with step-up and audited; they are not one yet.) Their rule names are not secret — a
parked response names the rules that fired in `matched_rules`. Two rules, matching exactly the dispatches the default
fleet's two rules match:

| Rule | Matches | Requires |
| --- | --- | --- |
| `demo-fleet-wide-mutates-need-a-human` | `mutate` class, fan-out **≥ 2** | 1 approval, `in-band`, `requester_allowed: true`, no audience, `ttl` 1h |
| `demo-raw-exec-always-needs-a-human` | every Raw Exec | 1 approval, `in-band`, `requester_allowed: true`, no audience, `ttl` 1h |

They exist so that an MCP client can be **asked** the approval question in-band, or answer with
`approve_request` — the default fleet's gate permits neither: it is out-of-band, so no question
is emitted and `approve_request` is refused as too weak a channel.

**Who may decide**, from the gate semantics in [approval-gates.md](approval-gates.md#who-may-decide):

- **No audience** means any Account whose role clears the decision floor, which is the floor
  the Action needed to be requested: `operator` for an Operation, `admin` for a Raw Exec. So
  `dev-approver` (human, admin), the founding admin (human, admin) and the Console's `admin`
  (human, admin) may each decide any request here. An `operator` Gleipnir may decide a gated
  Operation, and never a Raw Exec.
- **`requester_allowed: true`** means the requester may fill the slot. A **human** requester —
  the founding admin driving a Raw Exec by hand — may approve its own parked dispatch. A
  **machine** requester — Gleipnir — may too, provided its in-band answer carries a non-blank
  asserted name, recorded beside Gleipnir's verified identity. Relay cannot tell whether a
  human gave that name; a prompt-injected AI-agent could supply a made-up one and release its
  own request (see `kind: "machine"` above).
- **In-band is the floor, not the only way.** An in-band rule is satisfied by an in-band answer
  and equally by an out-of-band decision — a stronger channel satisfies a weaker rule.

Three ways to answer, then re-issue the original call unchanged — approving releases the Plan;
it does not itself dispatch (on the asked-in-band path the client's retry is that re-issue):

1. **Asked in-band.** A client that declares the name `gleipnir` and can be asked gets a
   Relay-authored approval question instead of `pending_approval`; its retry carrying an
   answer, with a responder named, records the decision and runs the Job. Putting the question
   to a human is the client's job, and Relay does not verify that it did. Observed on
   a live fleet, with Gleipnir on its API Token. `claude-code` is asked only on a human
   Account's OAuth session, and every other client — `scripts/dev-fleet-mcp.sh` included —
   gets `pending_approval` and asks nobody.
2. **`approve_request`**, from a client that got `pending_approval`. Observed on a live fleet
   for an unrecognised client: `pending_approval`, then `approve_request`, then the re-issued
   call ran. By hand, as the founding admin *(predicted)*:

   ```console
   $ scripts/dev-fleet-mcp.sh call approve_request \
       '{"request_id":"<request-id>","plan_hash":"<plan-hash>","approve":true,"approver":"<your name>","reason":"approved on stage"}'
   ```

   `approver` names the human who decided. It is required, recorded as asserted, and never
   verified.
3. **Out-of-band**, exactly as on the default fleet — on the Control API as `dev-approver`
   *(predicted under this gate)*:

   ```console
   $ scripts/dev-fleet-mcp.sh api-approver POST /api/v1/approvals/<request-id>/decision \
       '{"approve":true,"plan_hash":"<plan-hash>","reason":"approved on stage"}'
   ```

   or in the Console, signed in as `admin`, which mounts an approval decision route with step-up
   re-authentication. `admin` is inside this gate's empty audience, so a Console decision is
   accepted here *(predicted)*; on the default fleet's gate it is refused as not in the
   audience.

**What is structural, and what is not.** Much less than on the default fleet, deliberately: the
demo gate exists to show the in-band question, and an in-band answer is, by construction, the
requesting session's word that a human agreed. What still holds: no API changes the gate;
nobody below `admin` releases a Raw Exec; a decision binds to the plan hash, and a retry whose
Node set changed parks and asks again. What does not hold is a second person, or even a
verified first one: a human requester may approve its own request; one presenter holds every
credential in `.dev-fleet/`; and a machine Account's in-band answer needs only a non-blank
name the client supplies, so an AI-agent steered by prompt injection could call
`approve_request` with a made-up name and release its own request. That last one is the
accepted client-integrity assumption of in-band approval
([approval.md, Channel strength](../specs/approval.md#channel-strength); ADR-0029). Say so on stage rather than claim the gate is a two-person control; the
default fleet's gate is the one that demonstrates that.

`dev-approver` still exists on this fleet — the `approver` one-shot (`docker/mint-approver.sh`)
creates it, a human admin Account, on every reset, and `make demo-reset` copies its API Token
to `.dev-fleet/approver-credential`. Confirm it with
`scripts/dev-fleet-mcp.sh api GET /api/v1/accounts`, then look for `"name": "dev-approver"`
with `"kind": "human"`.

### The bypass beat, scripted exactly

Framing up front: the AI-agent is out of the loop for this beat. The presenter drives MCP by
hand, with the founding admin's credential, and asks the bastion for `/etc/shadow`. That
credential is `.dev-fleet/control-credential`: the founding-admin Account, human, role admin —
the most powerful credential this control plane issues
(`relay/internal/store/accounts.go`'s `EnsureFoundingAdmin`).

Literal command (`scripts/dev-fleet-mcp.sh call` sends `tools/call` without the Tasks
capability, so the result is a plain tool result, not a task handle):

```console
$ scripts/dev-fleet-mcp.sh call run_operation \
    '{"selector":"node:role=bastion","operation":"file.read","args":{"path":"/etc/shadow"}}' \
    | python3 -c 'import json,sys; [print(r["outcome"] + ": " + r["stderr"]) for r in json.load(sys.stdin)["result"]["structuredContent"]["results"]]'
```

The filter prints EVERY result, not just the first, so a stale second bastion would show up as a
second line rather than hiding.

Literal expected output (one line):

```
denied_by_policy: denied by explicit rule for operation 'file.read'
```

Evidence on the page:

- The Policy engine's reason string is *(tested)*: the bastion fixture's explicit deny for
  `file.read /etc/shadow` produces exactly `denied by explicit rule for operation 'file.read'`,
  asserted in `bastion_allows_exactly_the_documented_read_and_nothing_else`
  (`daemon/tests/dev_fleet_fixtures.rs`) through the policy-check path, not a dispatched Task's
  stderr. `denied_by_policy_result` (daemon dispatch) copies that same reason into stderr
  unchanged — mechanical, and not separately asserted by this test.
- The same property, on a different Operation, is *(tested)*: an admin credential is refused
  byte-identically to an operator machine Account in
  `TestRefusalLegibilityE2E_AdminBypassIsRefusedIdentically`
  (`relay/cmd/relay/refusal_legibility_e2e_test.go`). That test uses `service.restart`, not this
  `file.read` — same property, different Operation.
- `result.structuredContent` is the path `scripts/demo-fleet.sh`'s own `check_nodes_healthy`
  already parses. The per-Node fields `outcome`, `stderr` and `refusal_explanation` are the MCP
  `PerNodeResult` (`relay/internal/controlplane/mcp/wire.go`).
- The end-to-end run above — the literal command producing the literal output on a live
  nine-Node fleet — is *(predicted)*, not observed.

Why this call, recorded so nobody "improves" it into one that parks:

- `file.read` is `read` class, so neither gate rule matches
  (`demo-fleet-wide-mutates-need-a-human` is `mutate` with fan-out 2 or more;
  `demo-raw-exec-always-needs-a-human` is every Raw Exec). It dispatches straight to the Node
  with no human.
- Raw Exec on the bastion would be refused by the Node too
  (`bastion_fixture_denies_every_raw_exec`). But it parks under the Raw Exec rule first, so the
  stage would show a pending approval rather than a refusal — this obvious alternative is
  rejected for exactly that reason.
- `node:role=bastion` is fan-out 1, and the read-class blast cap (default 10000) is far above
  nine, so there is no blast-cap interaction.
- `/etc/shadow` is denied by an explicit deny rule in all three fixtures, so the fleet-wide
  variant (selector `relay:env=dev`) would print nine denial lines. It is an optional encore,
  marked *(predicted)*; only the bastion's verdict is asserted by a fixture test.

Full response, for whoever wants to see the wire — drop the python filter. A *(predicted)*
skeleton, derived from `RunOrPlanOutput`/`PerNodeResult`: a JSON-RPC 2.0 envelope, id `1`, whose
result carries `"content"` (one text item holding the same JSON) and `"structuredContent"` with
`"job_id"` and a `"results"` array. Each result carries `"node_id"` (`node-` followed by 32 hex),
`"outcome": "denied_by_policy"`, `"stdout": ""`, `"stderr"` (the deny reason),
`"stdout_truncated": false`, `"stderr_truncated": false`, `"duration_ms"`, and
`"refusal_explanation"`. There is no `"exit_code"` key — nothing executed. `job_id`, `node_id`,
`duration_ms` and key order all vary. `refusal_explanation` opens with
`capability.PolicyDenyExplanation`'s first sentence, "Refused by the Node, not by this control
plane" — quoted here only for its opening; the full constant is not reproduced, because it would
go stale.

The one-sentence framing, verbatim, for the presenter to say:

> That refusal came from a root-owned Policy file on the bastion's own disk: the Relay can read
> that file's fingerprint but has no code path to change it, so no credential this control plane
> issues, the admin's included, can talk the bastion into it.

That sentence stays inside invariant 2 and ADR-0002: it claims nothing about local root on the
laptop, which can reach the container (the posture paragraph above covers that), and it does not
call the Node a "machine" or a "host", nor widen "credential this control plane issues" to
"credential in this room".

**Pre-flight.** Run the command once before going on stage. If the filter raises `KeyError`,
run it unfiltered to see the error — an authentication error means `.dev-fleet/` is stale; run
`make demo-creds`. Immediately before the beat, run the `list_nodes` check the mutate-mixed-set
beat (c) below already asks for, in literal form:

```console
$ scripts/dev-fleet-mcp.sh call list_nodes '{"selector":"node:role=bastion"}'
```

Expect exactly one Node. A stale second bastion would print two denial lines instead of one.

### Triggering and clearing the fault

Trigger with `make demo-fault`. Expected output *(predicted, the `cmd_fault` echo)*:

```
daemon-4: dev-fleet demo service DOWN (dev-fleet-service status: exit 3)
daemon-6: dev-fleet demo service DOWN (dev-fleet-service status: exit 3)
```

Three ways to clear it:

- **On stage, by Gleipnir:** `service.restart` with unit `nginx`, one Selector per faulted
  environment — `node:role=web, node:env=prod` reaches `daemon-4` (and its healthy sibling
  `daemon-5`), `node:role=web, node:env=staging` reaches `daemon-6` (and `daemon-9`). Each is a
  fan-out-2 mutate, parks under `demo-fleet-wide-mutates-need-a-human`, and Relay sends Gleipnir
  the approval question (putting it to a human in Gleipnir's own UI is Gleipnir's behaviour,
  which Relay does not verify); the answered retry restarts the real `httpd` through the web Nodes' `systemctl`
  shim. This is the operator-level repair described under the role choice above *(predicted as
  a fault repair; see there for what was observed)*. `node:role=web` alone would reach all six
  web Nodes in one call, which is also fine: the restart is idempotent.
- **On stage, by hand:** the Raw Exec restart, parked under `demo-raw-exec-always-needs-a-human`.
  With Gleipnir at `operator` (the default), the presenter requests
  it by hand as the founding admin, using the same fleet-wide selector as beat (c) below so both
  faulted Nodes (`daemon-4`, `env=prod`; `daemon-6`, `env=staging`) clear in one call — a
  narrower Selector such as `node:role=web, node:env=prod` would only reach `daemon-4`:

  ```console
  $ scripts/dev-fleet-mcp.sh call raw_exec \
      '{"selector":"relay:env=dev","argv":["/usr/local/bin/dev-fleet-service","restart"]}'
  ```

  Then decide it by any of the three ways in [The human approver](#the-human-approver) that an
  `admin` can use — for example `approve_request` as the founding admin itself (the gate lets
  the requester decide), or the Control API as `dev-approver` — and re-issue the call unchanged
  *(predicted)*. If Gleipnir asks for Raw Exec as `operator`,
  the Relay refuses it on role before any gate or Node sees it — say so, so the presenter is not
  surprised.
- **Between takes:** `make demo-reset`.

See [The fault, and resetting between takes](#the-fault-and-resetting-between-takes) below for
discovery, repair and verification in full; this beat does not restate them.

### Confirming the reset took

`make demo-reset` already checks, by itself: every image present; `relay` and every daemon
healthy; every one-shot exited `0`; the `dev-fleet-service status` probe exits `0` on every
`role=web` Node; `GET /api/v1/approvals` is empty; and `list_nodes` reports the full compose
roster, all connected. See the numbered list in
[The fault, and resetting between takes](#the-fault-and-resetting-between-takes) below rather
than a duplicate of it here.

Independent checks for the presenter, as literal commands:

- Nine Nodes, all connected:

  ```console
  $ scripts/dev-fleet-mcp.sh call list_nodes '{"selector":"relay:env=dev"}' \
      | python3 -c 'import json,sys; n=json.load(sys.stdin)["result"]["structuredContent"]["nodes"]; print(len(n), "Nodes,", sum(1 for x in n if x.get("connected")), "connected")'
  ```

  Expected *(predicted)*: `9 Nodes, 9 connected`. It reads `result.structuredContent.nodes`, the
  same path `check_nodes_healthy` reads.
- `scripts/dev-fleet-mcp.sh api GET /api/v1/approvals`: an empty `approvals` array.
- Re-run the [Gleipnir credential block](#credentials-for-gleipnir-copy-paste), then the
  approvals curl above with the NEW token: `200` with an empty `approvals` array. Negative
  check: a token saved from before the reset must now be refused, because the store was wiped —
  expected `401` *(predicted)*. Save the old token to a scratch file outside the repo only if you
  want to run this check; otherwise skip it.
- Reload Gleipnir and any MCP client (the CA changed), then re-run
  [the bypass beat](#the-bypass-beat-scripted-exactly).

Back to back: run `make demo-reset` two or three times in a row. This has not been observed
live — see [Verification honesty](#verification-honesty) below, which already says so; record
the result there the first time someone runs it.

## The demo profile

A fleet-scale `demo` compose profile (#452): the same fleet as [dev-fleet.md](../dev-fleet.md), plus six more
daemons — `daemon-4..9` — for a total of nine Nodes with varied `node:` labels and a
third, strictly narrower Policy fixture. It exists for a stage demo, where three Nodes
do not read as a fleet and identical Policies produce no interesting refusal. It is
purely additive: every service the profile adds carries `profiles: ["demo"]`, so a
plain `docker compose up` still means exactly what it means there, and nothing in
`daemon-1..3` is touched (`demo_profile_is_additive`, `daemon/tests/dev_fleet_fixtures.rs`,
enforces this).

### Start from a clean registry

Do this first, and on its own, before anything else in this section:

```console
$ make demo-build   # first time, and again after any code change
$ make demo-reset
```

The demo fleet is its own fixed compose project, `relay-demo` — separate
images and separate volumes from the default fleet, driven entirely
through the guarded `scripts/demo-fleet.sh` (see
[The fault, and resetting between takes](#the-fault-and-resetting-between-takes)
below). It cannot run alongside the default fleet: both publish the same host
ports, `127.0.0.1:7654` / `9443`.

`make demo-reset` is `docker compose --profile demo down -v` followed by
`up -d --no-build` under the `relay-demo` project name, plus the health and
credential verification described below. It never builds — run `make
demo-build` once first (and again after any code change); a missing image is
refused up front, before anything is torn down.

Why `down -v` and not a plain `down`: `relay-data` is a **named** volume, so the
Relay's registry — and every Node in it — survives a plain `compose down`. A Node
from an earlier experiment is still in the registry, still matches Selectors, and
would make `node:role=bastion` resolve to **two** Nodes instead of one — which parks
the beat that is supposed to run straight through. `down -v` is the only thing that
clears it. The cost is real and worth stating plainly: `-v` destroys the CA and every
Node identity, so the next `up` re-enrolls the whole fleet from scratch.

`COMPOSE_PROFILES=demo make dev-fleet-up` looks like the Makefile-shaped
equivalent, but it is not: `dev-fleet-up` runs a bare `docker compose`, which
names its project after the checkout directory rather than `relay-demo` — a
project `make demo-reset` refuses on sight (see
[The fault, and resetting between takes](#the-fault-and-resetting-between-takes)).
Use `make demo-build` / `make demo-reset` instead.

Stop the demo fleet with `make demo-down` (no `-v` — Node identities and the
store survive, same as `dev-fleet-down` for the default fleet), and bring it
back with `make demo-up` (also no `-v`, no build — the matching plain
restart). `demo-up` is **not** "no credential mint": the mint one-shots have
`restart: no`, but a stopped one-shot container is started again by `up` just
like any other service, which re-runs its entrypoint and mints fresh values
into the (persisted) volume — it just does not copy them out to
`.dev-fleet/`; run `make demo-creds` after `demo-up` for that (see
[The fault, and resetting between takes](#the-fault-and-resetting-between-takes)
for what `demo-creds` does and does not do). There is no `down` you need to
remember to run before `make demo-reset`: it wipes first. Never substitute a bare
`docker compose --profile demo down` / `up` for these targets: it names its project after
the checkout directory rather than `relay-demo`. `make demo-up` brings back all nine
daemons every time precisely because the fixed project and profile are baked into the
script rather than typed at the command line.

**Cleanup — stop it and leave it down.** `make demo-reset` also wipes `relay-demo`, but
brings the fleet straight back up; it is the between-takes reset, not a cleanup. To stop
the demo fleet and wipe its volumes, run `docker compose -p relay-demo --profile demo
down -v` directly — never a bare `docker compose --profile demo down -v`, which names its
project after the checkout directory, not `relay-demo`, and leaves the demo fleet's
volumes behind uncleaned:

```console
$ docker compose -p relay-demo --profile demo down -v
$ rm -rf ./.dev-fleet
```

### The nine-Node roster

| service | hostname | `node:` labels | Policy fixture | demo service |
| --- | --- | --- | --- | --- |
| `daemon-1` | `dev-node-1` | `role=web` | `policy.web.toml` | yes (base, untouched) |
| `daemon-2` | `dev-node-2` | `role=web` | `policy.web.toml` | yes (base, untouched) |
| `daemon-3` | `dev-node-3` | `role=db` | `policy.db.toml` | no (base, untouched) |
| `daemon-4` | `dev-node-4` | `role=web, env=prod` | `policy.web.toml` | yes |
| `daemon-5` | `dev-node-5` | `role=web, env=prod` | `policy.web.toml` | yes |
| `daemon-6` | `dev-node-6` | `role=web, env=staging` | `policy.web.toml` | yes |
| `daemon-7` | `dev-node-7` | `role=db, env=prod` | `policy.db.toml` | no |
| `daemon-8` | `dev-node-8` | `role=bastion, env=prod` | `policy.bastion.toml` | no |
| `daemon-9` | `dev-node-9` | `role=web, env=staging` | `policy.web.toml` | yes |

Totals: 6 `role=web`, 2 `role=db`, 1 `role=bastion`; 4 `env=prod`, 2 `env=staging`, 3 with
no `env` label at all (the three base Nodes, deliberately unlabelled because their
blocks stay untouched). `list_nodes()` shows three distinct `policy_fingerprint`
values, one per Policy fixture — the SHA-256 of that file's raw bytes
(`daemon/src/policy.rs`'s `policy_fingerprint`), computable locally with
`sha256sum docker/fixtures/policy.{web,db,bastion}.toml` and not reproduced here
because it changes on any edit to the file, including a comment.

### What varies, and what cannot

`node:` labels vary as the table above shows. Of the Facts a Node reports
(`daemon/src/operations/system_facts.rs`), only `hostname` and `ip_addresses` can
actually differ in a single-host Docker fleet — `os`, `arch`, and `kernel` all come
from one shared kernel and one image, so every Node reports the same values for
those regardless of label. Faking them (e.g. per-Node `/etc/os-release` variants) was
rejected for the same reason the base fleet refuses a `systemctl` that reports success
without doing anything: a dev fleet that lies about what it is is worse than one that is
legibly limited. (The web Nodes' `systemctl` shim is not that: it restarts a real service
and reports only what that service's own probe observed —
[The fixture limit, stated plainly](../dev-fleet.md#the-fixture-limit-stated-plainly).)

`node:env=prod` / `node:env=staging` above are **Node-authored** labels (set by
`RELAY_NODE_LABELS` in the compose environment, and forgeable by a compromised Node),
while `relay:env=dev` is **Relay-authored** at enrollment. They are different
namespaces on purpose (invariant 7), and `list_nodes()` always returns them as
separate maps — never merged — so you can always tell which one you are looking at.
(`tag:` selectors are not mentioned here: they are refused at parse today, a known
gap tracked separately.)

### Selector cardinalities

| Selector | Nodes |
| --- | --- |
| `relay:env=dev` | 9 |
| `node:role=web` | 6 |
| `node:role=db` | 2 |
| `node:role=bastion` | 1 |
| `node:env=prod` | 4 |
| `node:env=staging` | 2 |
| `node:role=web, node:env=staging` | 2 |
| `node:role=db, node:env=prod` | 1 |

The three base Nodes carry no `node:env` label at all, on purpose — they predate this
profile and their blocks are untouched.

### Verification honesty

**The outcomes below are predicted, not observed.** Every `denied_by_policy` verdict is
underwritten by a hermetic test against the daemon's own evaluator
(`daemon/tests/dev_fleet_fixtures.rs`); every `success` and every `failure` depends on
`busybox httpd` and `dev-fleet-service` actually running in nine containers, which no
test in this repository can prove and which nobody has yet stood up at n=9. **Run the
beats once before presenting them, and correct this section with what you actually
saw.** Each beat below is marked *(tested)* for the half a hermetic test covers, and
*(predicted)* for the half that requires the real fleet.

Observed since, by hand on a live demo fleet (2026-09-29), and nothing more: under the
in-band demo gate, a client named `gleipnir` on an API Token was asked the approval question
and its answered retry ran the Job; an unrecognised client got `pending_approval`, answered
with `approve_request`, re-issued, and ran; and `service.restart` of `nginx` on a web Node,
through the `systemctl` shim, exited `0`. The beats below were not re-run under that gate.

### The four beats

**a. Fleet read, all success.**

```
run_operation(selector="relay:env=dev", operation="file.read", args={"path":"/etc/os-release"})
```

→ 9 × `success` — the allow verdict is tested on all three fixtures
(`all_three_policy_files_lint_clean_with_the_template_pack`,
`bastion_allows_exactly_the_documented_read_and_nothing_else`); the nine-Node result is
*(predicted)*. No approval: `read`-class.

**b. Mixed read set, no approval at all.**

```
run_operation(selector="relay:env=dev", operation="file.read", args={"path":"/var/lib/dev-fleet-service/state"})
```

→ 6 × `success` (the web Nodes) *(predicted)*, 2 × `failure` (the db Nodes never had the
file) *(predicted)*, 1 × `denied_by_policy` (the bastion, exact-path allow only)
*(tested, `bastion_allows_exactly_the_documented_read_and_nothing_else`)*.

**c. The mutate mixed set — the issue's acceptance criterion.**

**On stage, immediately before this beat, run `list_nodes(selector="node:role=bastion")`
and `list_nodes(selector="relay:env=dev")`.** This is the only instrument that reads the
**real registry** rather than the compose file. If the first returns anything but one
Node, or the second anything but nine, stop and run `make demo-reset`
— a stale Node changes the fan-out and the beat will not land.

Then:

```
raw_exec(selector="relay:env=dev", argv=["/usr/local/bin/dev-fleet-service","restart"])
```

→ parks under `demo-raw-exec-always-needs-a-human` with a `request_id` and a
`plan_hash` — the gate rule matches every Raw Exec regardless of fan-out, as written
in the fixture, though nobody has run this specific fan-out to watch it happen.
Approve it any way [The human approver](#the-human-approver) allows an `admin` — here as
`dev-approver`, on the Control API:

```console
$ scripts/dev-fleet-mcp.sh api-approver POST /api/v1/approvals/<request_id>/decision \
    '{"approve":true,"plan_hash":"<plan_hash>","reason":"repair the dev-fleet demo service"}'
```

then re-issue the same call unchanged → **6 × `success, exit_code: 0`** *(predicted)*
and **3 × `denied_by_policy`** *(tested — `daemon-3` and `daemon-7` by the existing
`raw_exec_verdicts_match_the_web_db_split`; `daemon-8` by
`bastion_fixture_denies_every_raw_exec`, both in
`daemon/tests/dev_fleet_fixtures.rs`)*. Preflight the same argv with `plan=true` first
for 6 allow / 3 deny and no parking.

**d. The straight-through (unparked) mutate at n=9.** Two Selectors, both fan-out 1:

```
run_operation(selector="node:role=db, node:env=prod", operation="service.restart", args={"unit":"nginx"})
```

→ dispatched with no human, terminates `failure` with
`stderr="spawn systemctl: No such file or directory"` and no `exit_code` (the
documented busybox limit from [The fixture limit, stated plainly](../dev-fleet.md#the-fixture-limit-stated-plainly),
not a defect: the `systemctl` shim is installed only on the web Nodes, and a db Node runs no
demo service for it to restart) *(predicted; the shim's absence on a `role=db` Node was
observed in the image)*; and

```
run_operation(selector="node:role=bastion", operation="service.restart", args={"unit":"nginx"})
```

→ dispatched with no human — the gate's fan-out-1 behavior, untested here,
same as the first command above *(predicted)* — and refused by the Node:
1 × `denied_by_policy` *(tested, `bastion_allows_exactly_the_documented_read_and_nothing_else`)*.

There is no successful straight-through `service.restart` at n=9: it succeeds only on the web
Nodes, and no `node:` Selector in this roster reaches a single web Node (see the repair path
under [The fault, and resetting between takes](#the-fault-and-resetting-between-takes)), so a
`service.restart` Selected by label that can succeed is fan-out 2 or more and parks.

### The threshold, stated on the page

`min_fan_out: 2` is **unchanged**. At nine Nodes almost every interesting fan-out
crosses it and parks — that is the correct lesson to draw, not a bug: raising the
threshold to keep a straight-through beat at n=9 would mean a four-Node mutate running
with no human, which is strictly weaker and teaches the audience the opposite of the
point. In particular `node:role=db`, which runs straight through in the three-Node default
fleet, is **two** Nodes here and parks — `min_fan_out: 2` is a floor. The straight-through path stays reachable through the two fan-out-1 Selectors
in beat (d) above. Every Raw Exec parks at any fan-out under a separate rule
(`demo-raw-exec-always-needs-a-human`), and that rule is not retuned either.

### The fault, and resetting between takes

`make demo-fault` kills the real `busybox httpd` (#389) on a subset of `role=web`
Nodes, out of band — through `docker compose exec`, never through the Relay
(there is no "break" verb anywhere in the control path; see
[Why `start|restart|status` and not `stop`](../dev-fleet.md#why-startrestartstatus-and-not-stop)).
The default targets are `daemon-4` (`dev-node-4`, `env=prod`) and `daemon-6`
(`dev-node-6`, `env=staging`) — one of each environment, and neither is on the
["drop first" list](#resource-usage) if the roster is ever trimmed. Override with
`DEMO_FAULT_NODES`, e.g. `make demo-fault DEMO_FAULT_NODES="daemon-2 daemon-9"`
— the Makefile passes it through as a real environment variable rather than
splicing it into the recipe text, and the script splits it on whitespace and
validates every token against the derived web roster (below) before any
`exec` into a container, so a value carrying a shell metacharacter is
refused, not executed.
Every target must be a `role=web` Node — anything else is refused before any
`exec` into a container, since faulting a Node that runs no demo service
would report a condition that was never there. (This refusal runs after the
project guard, and after one read-only `docker compose config` call that
derives the web/daemon rosters from the compose file — it is not before the
script touches Docker at all.) The kill is idempotent: running it again on an
already-down Node reaches the same DOWN report immediately, so it is safe to
run more than once with no reset in between.

**What is true after the fault.** `httpd` is really killed (found by `pidof`,
not the pidfile, so a stale pidfile cannot redirect the kill), and
`dev-fleet-service status` on that Node genuinely reports `state=down` (exit
`3`) — `make demo-fault` verifies this itself, by polling that same probe,
before it prints anything. Nothing is written anywhere to stage the condition.

**Discovery — read path, no approval.** Fan `file.read` of `/proc/net/tcp`
across the web Nodes:

```
run_operation(selector="node:role=web", operation="file.read", args={"path":"/proc/net/tcp"})
```

Read-class, unparked — the wildcard `file.read` allow in `policy.web.toml`
covers this path like any other (proven hermetically by
`web_policy_allows_reading_the_socket_table`,
`daemon/tests/dev_fleet_fixtures.rs`). Look for a row whose **local address is
`0100007F:1F90` (127.0.0.1:8080) AND whose state is `0A` (`TCP_LISTEN`)** —
present on a serving Node, absent on a faulted one. Do not key off the port
`1F90` alone: a recently-closed connection leaves a `TIME_WAIT` row (state
`06`) at that same local address for up to ~60s, and that row is not evidence
the service is up. `/var/lib/dev-fleet-service/state` is deliberately never
rewritten to say "down" (see [The real service](../dev-fleet.md#the-real-service)), so it is
**not** the discovery signal — it is the *repair* proof, below.

**Repair — mutate path.** There is no `node:` Selector that reaches a single
web Node in this roster. `node:role=web` alone reaches all six. Of the two
`role`+`env` combinations that actually exist, each matches exactly two Nodes
(`daemon-4`/`daemon-5` on `env=prod`, `daemon-6`/`daemon-9` on `env=staging`)
— `daemon-1` and `daemon-2` carry no `env` label at all (see
[The nine-Node roster](#the-nine-node-roster)), so they cannot be reached by
a `role`+`env` combination either, only by the even less selective
`node:role=web`. So either repair below reaches the faulted Node and its
healthy sibling both. That is harmless: `dev-fleet-service restart` is
idempotent, and restarting an already-serving instance still ends in
`state=running`.

```
raw_exec(selector="node:role=web, node:env=prod", argv=["/usr/local/bin/dev-fleet-service","restart"])
```

matches `daemon-4` (faulted) and `daemon-5` (healthy); swap `env=prod` for
`env=staging` to reach `daemon-6` (faulted) and `daemon-9` (healthy) instead.
Every Raw Exec parks under `demo-raw-exec-always-needs-a-human` regardless of
fan-out; approve it by any way [The human approver](#the-human-approver) allows an
`admin` — `dev-approver` on the Control API, exactly as in
[Approving a parked dispatch](../dev-fleet.md#approving-a-parked-dispatch), still works —
then re-issue the same call unchanged.

The operator-level repair is the Native Operation over the same Selector:

```
run_operation(selector="node:role=web, node:env=prod", operation="service.restart", args={"unit":"nginx"})
```

On the web Nodes `systemctl` is the DEV-ONLY shim
([The fixture limit, stated plainly](../dev-fleet.md#the-fixture-limit-stated-plainly)), so
this runs `dev-fleet-service restart`. It is a fan-out-2 mutate, parks under
`demo-fleet-wide-mutates-need-a-human`, and can be approved in-band by the client that asked (with an asserted responder
name Relay records and does not verify)
for it; approved, it returns 2 × `success, exit_code: 0` and the faulted Node serves again
*(predicted)*. `svc.status` and `svc.restart` become the natural read/mutate pair for this
once #626 makes the Template pack dispatchable.

**Independent verification.** `file.read` of
`/var/lib/dev-fleet-service/state` on the repaired Node shows a new `pid` and
`started_epoch` (see [The real service](../dev-fleet.md#the-real-service)), and re-running
the `/proc/net/tcp` discovery read shows the `0100007F:1F90 ... 0A` row is
back.

**`make demo-reset`** is the reliable way back to the starting state between
takes — fault cleared, Jobs/approvals/audit/registry cleared (the store lives
on `relay-data`, wiped by `down -v`), the CA and every credential fresh, and
every Node healthy — and, unlike a bare `docker compose --profile demo down -v`
/ `up`, it never builds (a missing image is refused up front — run
`make demo-build` once, first) and it verifies rather than assumes:

1. Every image `docker compose config --images` names must already exist,
   checked before anything is torn down.
2. `down -v --remove-orphans` then `up -d --no-build --pull never`.
3. Waits for `relay` and every daemon to report `healthy`, and every one-shot
   (`credential`, `approver`, `console-admin`, `console-password`, `bootstrap`)
   to have exited `0`.
4. Probes `dev-fleet-service status` on every `role=web` Node — the fault, if
   any, is cleared by the fresh `up`, but this step confirms it with the same
   live probe the fault check uses, rather than assuming a fresh container
   means a serving one.
5. **Mints** fresh credentials: step 2's `down -v` / `up` recreates the
   `credential`/`approver`/`console-admin`/`console-password` one-shots from
   nothing, which is what actually mints (`docker/mint-credential.sh` runs
   again on every container that starts fresh). This step then **copies**
   them out to `.dev-fleet/` (`scripts/dev-fleet-mcp.sh init` — a
   `docker compose cp` / `run --no-deps` read, nothing more) and checks, live,
   that `GET /api/v1/approvals` comes back empty and that `list_nodes()` over
   MCP reports every Node connected — there is no `GET /api/v1/nodes` list
   route on the Control API, only `GET /api/v1/nodes/{node_id}`, so `list_nodes`
   is the only surface that sees the whole registry.

**The CA is regenerated on every reset, so a registered MCP client is left
holding a stale bearer token and a stale CA it can no longer verify against**
(`NODE_EXTRA_CA_CERTS` is read only at process start). `.dev-fleet/` is
already current — step 5 above just refreshed it — so the fix is only to
restart the client: `claude mcp remove relay` / `claude mcp add ...` as in
[Connecting Claude Code](../dev-fleet.md#connecting-claude-code). `make demo-reset`'s
closing summary says this every time. **Do not follow
`.dev-fleet/start-claude.txt`'s own `make dev-fleet-creds` line** — `.dev-fleet/`
is shared between the default fleet and the demo fleet, and `dev-fleet-creds`
targets the directory-named default project, not `relay-demo`. `make demo-creds`
is the demo fleet's equivalent, and it is only needed after `demo-up`: unlike
`demo-reset`, `demo-up` does not copy anything out on its own, even though its
`up` (see [Survive `down` / `up`](../dev-fleet.md#survive-down--up)) causes the same
one-shots to re-mint into the volume. `demo-creds` itself mints nothing — it
is a pure copy, safe to run any number of times.

**The refusal.** `scripts/demo-fleet.sh` (every one of `demo-build`,
`demo-reset`, `demo-fault`, `demo-up`, `demo-down`, `demo-creds`) refuses
unless the target is exactly the `relay-demo` compose project on a local
Docker engine, and it does so before any Docker call **except two read-only
checks**: the current docker context's endpoint (always made, to confirm it
is a local engine), and — only once that passes — a `docker ps` that confirms
no *other* checkout already owns the `relay-demo` project (this repo lives in
many git worktrees, and `relay-demo` is one project name per Docker engine).
A `COMPOSE_PROJECT_NAME` set to anything else — including set-but-empty — or
a non-local `DOCKER_HOST` are refused with **no** Docker call at all, because
they are decided from the environment alone. Once past that guard, `demo-reset`
and `demo-up` separately refuse — before either touches a volume or a
container, via one more read-only `docker ps` — if host port `7654` or `9443`
is already published by some other compose project. `demo-reset` refuses once
more, via a read-only `docker compose config --format json`, if any volume it
is about to `down -v` does not resolve to a `relay-demo_`-prefixed name — the
defense against a future `name:`/`external:` override on a volume in
`docker-compose.yml` quietly pointing `-p relay-demo` at a volume this
checkout does not own. `make test-demo-fleet` (`scripts/demo-fleet-test.sh`,
in `make verify` and CI) proves every refusal against a stubbed `docker`,
never a real engine.

A checkout directory literally named `relay-demo` would give the *default*
(non-demo) fleet's bare `docker compose up` that same project name — an
unlikely collision, but one more reason to prefer `make demo-build` /
`make demo-reset` over typing `docker compose` by hand under this profile.

**Verification honesty.** The `/proc/net/tcp` discovery signal is *(predicted)*
from `web_policy_allows_reading_the_socket_table`
(`daemon/tests/dev_fleet_fixtures.rs`) — the daemon's own Policy engine agrees
the read is allowed, but no automated test here starts a real `busybox httpd`
or reads its real socket table. "Reset survives back to back, repeatedly" has
**not been observed live at all** — `scripts/demo-fleet-test.sh`'s hermetic
guard proof only proves the refusal logic against a stubbed `docker`; it says
nothing about whether a real `down -v` / `up` / wait / probe cycle actually
succeeds once, let alone repeatedly. Run the fault → discover → repair →
verify sequence, and `make demo-reset` two or three times back to back,
before presenting, and correct this paragraph with what you actually saw.

### Resource usage

**PENDING MEASUREMENT (#452, AC 4).** No number below has been measured — there is no
Docker daemon available in this repository's build environment, only the `docker`
binary — and none should be invented or assumed. Whoever next has a machine with
Docker Engine + Compose v2 should run the procedure below and fill this table in the
same change that adjusts the roster, if adjustment turns out to be needed.

**Procedure:**

1. `docker compose down -v`, then `docker compose --profile demo up --build -d`; wait
   until `docker compose ps` shows all nine daemons `healthy`; let it settle 60s.
2. **Idle:** three samples 10s apart of
   `docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"`.
   Record total memory, the `relay` container, and one representative web / db /
   bastion daemon.
3. **Fan-out:** sample the same command while running
   `run_operation(selector="relay:env=dev", operation="system.facts")` in a tight loop,
   and once more during the approved `raw_exec` restart across all nine. Record the peak.
4. Record the machine (CPU, RAM, OS, Docker version) and the date beside the table —
   numbers without the machine are noise.
5. **If nine does not sit comfortably, drop `daemon-9` first, then `daemon-5`.**
   `daemon-9` and `daemon-6` are both `role=web, env=staging` — dropping both would
   take `node:role=web, node:env=staging` to zero while this section still publishes
   it, so the second drop must be `daemon-5` (`role=web, env=prod`), not `daemon-6`.
   Dropping `daemon-9` then `daemon-5` keeps every Selector in the cardinality table
   above at 1 or more. Update, in the same change: this roster table and the compose
   service + `daemonN-state` volume being dropped, the Selector cardinalities table and
   every beat that says "9 ×" / "6 ×", and `daemon/tests/dev_fleet_fixtures.rs`'s
   `ROSTER` and `a_single_node_selector_survives_at_nine_nodes`.

| measured on | date | who | idle memory (total) | idle memory (`relay`) | idle memory (1 daemon) | fan-out peak memory | idle CPU | fan-out peak CPU |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ |
