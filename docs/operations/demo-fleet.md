# The demo fleet

The nine-Node demo fleet, `deploy/demo/`, beside the [local test fleet](../dev-fleet.md), as a
runbook:
roster, beats, fault injection, resetting between takes, and resource usage. Read
[dev-fleet.md](../dev-fleet.md) first: its **DEV-ONLY** banner, prerequisites, bring-up and MCP
connection all apply here, with more force, since three times the Nodes sit behind the same
committed dev credential. This file is also the presenter's runbook for the Relay half of a
stage demo ([Presenter runbook](#presenter-runbook)); Gleipnir's half lives in Gleipnir's own
presenter runbook, which is not published here. Gleipnir is the AI-agent that drives the demo:
a consumer of Relay, never a part of it.

## Presenter runbook

From cold to on stage: bring-up, Gleipnir's credentials, the human approver, the scripted
bypass beat, the fault, and reset; and, opt-in,
[signing Claude Code in as a human over OAuth](#signing-in-as-a-human-over-oauth).

### Posture, stated once

This is containers on a laptop, not a production deployment. Nine Nodes sit behind the same
committed default Console password, the control plane is loopback-only, and every container
shares one kernel. This section makes no hardening claims. The Node's refusal in the bypass
beat is still real: it comes from the same relay-daemon Policy engine that runs on a server.

### From cold to ready

1. **Prerequisites.** Docker Engine with the Compose v2 plugin, `python3`
   (`scripts/dev-fleet-mcp.sh` uses it), and `curl`. Any client other than
   `scripts/dev-fleet-mcp.sh` (which pins with `curl --resolve`) needs the `/etc/hosts`
   mapping: the control plane's certificate has a single SAN, `relay`, and Gleipnir and Claude
   Code must dial that name for verified TLS. The one-liner from
   [Connecting Claude Code](../dev-fleet.md#connecting-claude-code):

   ```console
   $ grep -q 'relay$' /etc/hosts || echo '127.0.0.1 relay' | sudo tee -a /etc/hosts
   ```

   Host ports `7654` and `9443` must be free, or `make demo-reset` fails at bind. The test
   fleet publishes the same two, so the demo targets refuse while `relay-test` has containers
   (run `make dev-fleet-down` first), and they refuse a `relay-demo` fleet started from another
   checkout.

2. **`make demo-build`.** Run it the day before, not on stage, and again after any code
   change. It is the only demo target that builds: the relay, `init` and daemon images, plus a
   pre-pull of the OAuth overlay's images where missing, so `make demo-reset`, which never
   pulls, works on a fresh engine.

3. **`make demo-reset`.** Expected closing output *(predicted — re-observe; the literal `echo`
   lines in `scripts/dev-fleet-mcp.sh`'s `cmd_init` and the `demo-reset` recipe)*, after
   compose's own progress output:

   ```
   dev-fleet-mcp: CA cert and both credentials are in .dev-fleet/
   dev-fleet-mcp: copy-paste launch commands: .dev-fleet/start-claude.txt
   demo-reset: reset complete — init exited 0, every service is healthy, .dev-fleet/ holds the fresh credentials.
   demo-reset: the CA was regenerated, so a registered MCP client still holds the OLD bearer token AND the OLD CA (NODE_EXTRA_CA_CERTS is read only at process start). Restart it — .dev-fleet/ is already current, so there is no need to run 'make demo-creds' again first:
   demo-reset:   claude mcp remove relay
   demo-reset:   claude mcp add --transport http relay https://relay:9443/mcp --header "Authorization: Bearer $(cat .dev-fleet/control-credential)"
   ```

   **Failure.** The failing command exits non-zero and make stops there. If `init` failed, no
   daemon started: `docker compose -p relay-demo logs init`.

4. **Enrollment timing from cold. Unmeasured.** The only bound in code is
   `DEMO_WAIT_SECONDS` (default 240s), a timeout, not a measurement. To measure: run
   `make demo-build` once, then `time make demo-reset` three times back to back, and record
   the results here:

   | measured on | date | who | `demo-build` (first run) | `demo-reset` cold wall time — run 1 | run 2 | run 3 |
   | --- | --- | --- | --- | --- | --- | --- |
   | _unmeasured_ | _unmeasured_ | _unmeasured_ | _unmeasured_ | _unmeasured_ | _unmeasured_ | _unmeasured_ |

   **Credential lifetime.** Every credential a reset mints expires after 24h: the first
   admin's (`relay init --ttl 24h`) and `dev-approver`'s (`ttl_seconds` 86400), both in
   `docker/dev-fleet-init.sh`, and the Gleipnir token below. Reset on demo day, not the night
   before.

5. Mint Gleipnir's credentials ([next](#credentials-for-gleipnir-copy-paste)), then run
   [Confirming the reset took](#confirming-the-reset-took).

### Credentials for Gleipnir (copy-paste)

**One machine Account per named AI-agent.** The demo's AI-agent is `auto-incident-response`
and gets a machine Account of that name, so its own name is the **verified** actor on every
audit row it causes, rather than a shared `gleipnir` Account. A second AI-agent gets its own
Account and token: re-run the block below with another name in `AGENT=`.

**The Account name is not the client name.** The MCP client must still **declare its client
name as `gleipnir`** in `clientInfo`, because the Relay asks the approval question in-band only
of a client name it recognises (AP-78): `gleipnir` on any session, `claude-code` only on a human
Account's OAuth session; anything else gets `pending_approval` and asks nobody. On an API Token
session, which this is, the answered retry must carry the responder assertion
`io.gleipnir/responder`, with `gate` `permission` and a `username` (AP-64), or the answer is
refused. The demo's approver there is `test_user`: **asserted**, recorded beside the verified
`auto-incident-response`, never verified (see `kind: "machine"` below).

Observed on 2026-09-29, with the block below run as written: a client declaring `gleipnir` on
the `auto-incident-response` token was asked in-band for `service.restart` of `nginx` on
`node:role=web`, and its retry naming responder `test_user` ran the Job, 6 × `success`. Read
back: `requested_by` is `auto-incident-response`; the one decision is by
`auto-incident-response`, `human: false`, channel `in-band`; the store records `test_user` only
as the asserted `on_behalf_of` (the audit row's `asserted_on_behalf_of`), beside the verified
`auto-incident-response` with method `api_token`.

**Re-run this after every reset.** `make demo-reset` runs `down -v`, which destroys the store:
the Account, its token and the CA go with it. Then make Gleipnir pick up the new token and CA;
how is Gleipnir's runbook to document, but most clients read a CA only at process start, so
restart it *(predicted)*. `make demo-up` keeps the store, so the token survives it.

Run this block from the repo root. It runs in a fail-fast subshell, is safe to re-run
(create-or-lookup), never echoes the token, and writes the token file `0600` with no trailing
newline. Copy it as written:

```console
$ ( AGENT=auto-incident-response
    set -euo pipefail; umask 077
    case "$AGENT" in ''|*[!A-Za-z0-9._-]*) echo "AGENT must be an Account name" >&2; exit 1 ;; esac
    export AGENT
    find_id() {
      scripts/dev-fleet-mcp.sh api GET /api/v1/accounts \
        | python3 -c 'import json,os,sys; print(next((a["id"] for a in json.load(sys.stdin)["accounts"] if a["name"]==os.environ["AGENT"]), ""))'
    }
    ACCOUNT_ID=$(find_id)
    if [ -z "$ACCOUNT_ID" ]; then
      scripts/dev-fleet-mcp.sh api POST /api/v1/accounts \
        "{\"name\":\"$AGENT\",\"kind\":\"machine\",\"role\":\"operator\"}" >/dev/null
      ACCOUNT_ID=$(find_id)
    fi
    test -n "$ACCOUNT_ID" || { echo "no $AGENT Account id; is .dev-fleet/ current?" >&2; exit 1; }
    scripts/dev-fleet-mcp.sh api POST "/api/v1/accounts/$ACCOUNT_ID/tokens" \
      "{\"name\":\"$AGENT-demo\",\"ttl_seconds\":86400}" \
      | python3 -c 'import json,sys; sys.stdout.write(json.load(sys.stdin)["token"])' \
      > ".dev-fleet/$AGENT-credential.tmp"
    test -s ".dev-fleet/$AGENT-credential.tmp"
    mv ".dev-fleet/$AGENT-credential.tmp" ".dev-fleet/$AGENT-credential"
    echo "$AGENT: Account $ACCOUNT_ID; API Token in .dev-fleet/$AGENT-credential" )
```

Expected output (observed 2026-09-29; the id differs per reset):
`auto-incident-response: Account acct-…; API Token in .dev-fleet/auto-incident-response-credential`.
A python traceback (typically `KeyError`) means the wrapped call was refused: re-run that
`scripts/dev-fleet-mcp.sh api` call without the filter to see why. Most likely `.dev-fleet/` is
stale; run `make demo-creds`.

Why each guard:

- `scripts/dev-fleet-mcp.sh api` exits 0 even on an HTTP error (`curl -sS`, no `--fail`), so the
  guards test the extracted values. A 409 on create (name taken) is harmless: the second
  `find_id` resolves the id, as `docker/dev-fleet-init.sh` does.
- `pipefail` and tmp-then-`mv` keep a failed mint from leaving an empty file that looks like a
  credential. A failed run can leave `.dev-fleet/<agent>-credential.tmp` (`0600`, gitignored,
  overwritten next time); `rm -f` it if you want.
- No trailing newline, so a client reading the file into a header sends none.
- The `case` refuses an `AGENT` outside the Account-name alphabet, so it can only ever be a
  plain name in a path or JSON body.

Field names are from `relay/internal/controlplane/api/accounts.go`. `ttl_seconds` is
required, and `0` means never expires, so never use `0` here.

The role choice:

- **`kind: "machine"`.** The AI-agent authenticates as a machine Account (GLOSSARY). Whatever
  `requester_allowed` says, Relay refuses a machine Account's answer to its own request
  (`approval.ErrMachineSelfDecision`) unless it arrives in-band with a non-blank asserted name
  (the `approver` on `approve_request`, or the responder on an answered approval question),
  recorded as an assertion beside the verified Account, never as verified. Relay cannot tell
  whether a human gave that name: a prompt-injected AI-agent could call `approve_request` with
  a made-up name and release its own request. That is the accepted client-integrity assumption
  of in-band approval ([approval.md, Channel strength](../specs/approval.md#channel-strength);
  ADR-0029), not a guarantee this fleet adds. A machine Account cannot engage the Freeze
  (human-only).
- **`role: "operator"` is the default and the recommendation**: the lowest role that runs the
  demo's Operations (`authz.requiredRole`), per the "lowest role that does its job" rule in
  [control-plane-credential.md](control-plane-credential.md). An operator cannot mint an API
  Token for anyone. See [The human approver](#the-human-approver) for who may decide what.
- **What operator can do.** Raw Exec is admin-only, so the presenter drives the Raw Exec repair
  by hand ([Triggering and clearing the fault](#triggering-and-clearing-the-fault)). Gleipnir
  can discover the fault with `file.read` and repair it with a gated mutate of its own:
  `service.restart` with unit `nginx` on `node:role=web, node:env=prod` (fan-out 2, mutate)
  parks under `demo-fleet-wide-mutates-need-a-human`, a different rule from beat (c)'s
  `demo-raw-exec-always-needs-a-human`. That rule is in-band, so Relay asks Gleipnir (client
  name `gleipnir`, on the `auto-incident-response` token), and its retry with a responder named
  (`test_user`) runs the Job. Whether Gleipnir puts the question to a human, and whether the
  named responder is that human, Relay does not verify. On the web Nodes `service.restart`
  goes through the DEV-ONLY `systemctl` shim
  ([The fixture limit, stated plainly](../dev-fleet.md#the-fixture-limit-stated-plainly)) and
  restarts the real `httpd` on `daemon-4` and `daemon-5`: 2 × `success, exit_code: 0`, and a
  faulted `daemon-4` serves again. Observed on a live fleet: the question asked and the answered
  retry running its Job; `service.restart` of `nginx` exiting `0` on a web Node. The
  combination on this exact Selector, and the fault clearing through it, is *(predicted)*.
  Beat (d) is unaffected: both its Selectors are fan-out 1, so it runs with no human.
- **`role: "admin"` is the alternative.** It lets the AI-agent request the Raw Exec repair
  itself; a Raw Exec is decided at `admin` too, since the floor for deciding is the floor for
  requesting. Account and API-Token administration are admin-only but not human-only
  (`authz.requiredControlRole`; narrowing them is an open owner decision recorded there), so a
  machine admin can mint API Tokens for other Accounts. Under the demo gate an `admin`
  AI-agent could also release its own Raw Exec with a name it supplied, so every Raw Exec on
  this fleet becomes one it could request and release alone. To choose it, change `"operator"`
  to `"admin"` in the create body. **A human should confirm this choice** before a presenter
  relies on it, and Gleipnir's presenter runbook must agree with the role actually used.
- A pre-existing Account of the `AGENT` name is reused whatever its role; read `"role"` in
  `scripts/dev-fleet-mcp.sh api GET /api/v1/accounts`. After a reset there is none.

**Export the CA.** `make demo-reset` and `make demo-creds` write `.dev-fleet/ca-cert.pem`. Give
Gleipnir three values: the MCP URL `https://relay:9443/mcp`; the absolute path of
`.dev-fleet/ca-cert.pem`; and the token in `.dev-fleet/auto-incident-response-credential`, sent
as `Authorization: Bearer`. It must also declare the client name `gleipnir` and name the
responder (`test_user`) on an answered approval. Gleipnir's config keys are Gleipnir's to
document.

Optional, needs `openssl`:

```console
$ openssl x509 -in .dev-fleet/ca-cert.pem -noout -subject -enddate -fingerprint -sha256
```

Verify the new token over verified TLS:

```console
$ curl -sS --resolve relay:9443:127.0.0.1 --cacert .dev-fleet/ca-cert.pem \
    -H "Authorization: Bearer $(cat .dev-fleet/auto-incident-response-credential)" \
    https://relay:9443/api/v1/approvals
```

Expected *(predicted)*: an empty `approvals` array; any authenticated caller may read the
queue (`handleListApprovals`). Then prove the token is not an admin's:

```console
$ curl -sS -o /dev/null -w '%{http_code}\n' --resolve relay:9443:127.0.0.1 \
    --cacert .dev-fleet/ca-cert.pem \
    -H "Authorization: Bearer $(cat .dev-fleet/auto-incident-response-credential)" \
    https://relay:9443/api/v1/accounts
```

Expected *(predicted)*: `403`, from the capability layer (`writeAccountError` mapping
`authz.ErrUnauthorized`). An admin token gets `200`.

These commands put the token on `curl`'s command line, visible to other local users while it
runs. Acceptable on a single-user laptop; never on a shared host. The plaintext appears once,
at mint (GLOSSARY: API Token): paste it only into Gleipnir's secret input, and never copy it
off the laptop.

### The human approver

**The demo fleet runs its own gate, and it is in-band.** `make demo-reset` and `make demo-up`
start the Relay on `deploy/demo/approval-gates.json`, not the test fleet's out-of-band gate
([The approval gate](../dev-fleet.md#the-approval-gate)). The `relay-config` one-shot stages
the folder's `relay.toml` and `approval-gates.json` onto the read-only config volume, and
`relay.toml`'s `approval.gate_rules_path` names the gate at `/etc/relay/approval-gates.json`,
so any `up` of `deploy/demo/docker-compose.yml` gets this gate. The gate file is staged
root-owned `0644`. No API writes it: changing a rule is an edit in `deploy/demo/` and another
`up`, which re-stages the folder and restarts the Relay. (Invariant 11 would allow gate
rules to become a runtime object, edited only by a human with step-up and audited; they are
not one.) Rule names are not secret: a parked response lists them in `matched_rules`. The two
rules match exactly what the test fleet's two match:

| Rule | Matches | Requires |
| --- | --- | --- |
| `demo-fleet-wide-mutates-need-a-human` | `mutate` class, fan-out **≥ 2** | 1 approval, `in-band`, `requester_allowed: true`, no audience, `ttl` 1h |
| `demo-raw-exec-always-needs-a-human` | every Raw Exec | 1 approval, `in-band`, `requester_allowed: true`, no audience, `ttl` 1h |

They let an MCP client be **asked** the approval question in-band, or answer with
`approve_request`. The test fleet's out-of-band gate permits neither: no question is
emitted, and `approve_request` is refused as too weak a channel.

**Who may decide** ([approval-gates.md](approval-gates.md#who-may-decide)):

- **No audience** means any Account whose role clears the decision floor, which is the floor
  for requesting: `operator` for an Operation, `admin` for a Raw Exec. So `dev-approver`
  (human, admin) and the founding admin (human, admin) may decide any request here, on the
  Control API. `auto-incident-response` (operator) may decide a gated Operation, never a Raw
  Exec; so may `demo-user`, the OAuth fleet's human operator.
- **`requester_allowed: true`** means the requester may fill the slot. A **human** requester,
  such as the founding admin driving a Raw Exec by hand, may approve its own dispatch. A
  **machine** requester may too, if its in-band answer carries a non-blank asserted name;
  Relay cannot tell whether a human gave it (see `kind: "machine"` above).
- **In-band is the floor, not the only way.** An out-of-band decision also satisfies an in-band
  rule.

Three ways to answer. Approving releases the request but does not dispatch: re-issue the original
call unchanged (on the asked-in-band path, the client's retry is that re-issue).

1. **Asked in-band.** A client declaring the name `gleipnir` gets a Relay-authored approval
   question instead of `pending_approval`; its retry with an answer and a responder records
   the decision and runs the Job. Putting the question to a human is the client's job, and
   Relay does not verify it. Observed on a live fleet with a `gleipnir` client on the
   `auto-incident-response` token. `claude-code` is asked only on a human Account's OAuth
   session; every other client, `scripts/dev-fleet-mcp.sh` included, gets `pending_approval`.
2. **`approve_request`**, from a client that got `pending_approval`. Observed on a live fleet
   for an unrecognised client: `pending_approval`, then `approve_request`, then the re-issued
   call ran. By hand, as the founding admin *(predicted)*:

   ```console
   $ scripts/dev-fleet-mcp.sh call approve_request \
       '{"request_id":"<request-id>","plan_hash":"<plan-hash>","approve":true,"approver":"<your name>","reason":"approved on stage"}'
   ```

   `approver` names the human who decided: required, recorded as asserted, never verified.
3. **Out-of-band**, as on the test fleet: the Control API as `dev-approver` *(predicted
   under this gate)*:

   ```console
   $ scripts/dev-fleet-mcp.sh api-approver POST /api/v1/approvals/<request-id>/decision \
       '{"approve":true,"plan_hash":"<plan-hash>","reason":"approved on stage"}'
   ```

   The Console has no approval surface (ADR-0044).

**What is structural, and what is not.** Much less than on the test fleet, deliberately: an
in-band answer is, by construction, the requesting session's word that a human agreed. What
holds: no API changes the gate; nobody below `admin` releases a Raw Exec; a decision binds to
the plan hash, and a retry whose Node set changed parks and asks again. What does not hold is
a second person, or even a verified first one: a human requester may approve its own request;
one presenter holds every credential in `.dev-fleet/`; and a machine Account's in-band answer
needs only a name the client supplies (the accepted client-integrity assumption,
[approval.md, Channel strength](../specs/approval.md#channel-strength); ADR-0029). Say so on
stage rather than call this a two-person control; the test fleet's gate demonstrates that.

`dev-approver` still exists here: the `init` one-shot (`docker/dev-fleet-init.sh`) creates it,
a human admin, on every reset, and `make demo-reset` copies its token to
`.dev-fleet/approver-credential`. Confirm with `scripts/dev-fleet-mcp.sh api GET /api/v1/accounts`:
look for `"name": "dev-approver"` with `"kind": "human"`.

### The bypass beat, scripted exactly

The AI-agent is out of the loop for this beat. The presenter drives MCP by hand with the first
admin's credential, `.dev-fleet/control-credential` (the human `admin` Account,
`CONSOLE_ADMIN_NAME`, that `relay init` created: the most powerful credential this control
plane issues), and asks the bastion for `/etc/shadow`.

Literal command (`scripts/dev-fleet-mcp.sh call` sends `tools/call`, so the result is a plain tool result):

```console
$ scripts/dev-fleet-mcp.sh call run_operation \
    '{"selector":"node:role=bastion","operation":"file.read","args":{"path":"/etc/shadow"},"wait_seconds":60}' \
    | python3 -c 'import json,sys; [print(r["outcome"] + ": " + r["stderr"]) for r in json.load(sys.stdin)["result"]["structuredContent"]["results"]]'
```

The filter prints every result, so a stale second bastion shows as a second line.

Literal expected output (one line):

```
denied_by_policy: denied by explicit rule for operation 'file.read'
```

Evidence:

- The reason string is *(tested)*: the bastion fixture's explicit deny for
  `file.read /etc/shadow` produces exactly `denied by explicit rule for operation 'file.read'`
  in `bastion_allows_exactly_the_documented_read_and_nothing_else`
  (`daemon/tests/dev_fleet_fixtures.rs`), through the policy-check path rather than a
  dispatched Task's stderr. `denied_by_policy_result` (daemon dispatch) copies that reason into
  stderr unchanged; that copy is not separately asserted.
- The same property on another Operation is *(tested)*: an admin credential is refused
  byte-identically to an operator machine Account in
  `TestRefusalLegibilityE2E_AdminBypassIsRefusedIdentically`
  (`relay/cmd/relay/refusal_legibility_e2e_test.go`), using `service.restart`.
- `result.structuredContent` is the path the `list_nodes` check below reads. The per-Node
  fields `outcome`, `stderr` and `refusal_explanation` are the MCP `PerNodeResult`
  (`relay/internal/controlplane/mcp/wire.go`).
- The literal command producing the literal output on a live nine-Node fleet is
  *(predicted)*, not observed.

Why this call, so nobody "improves" it into one that parks:

- `file.read` is `read` class, so neither gate rule matches, and it dispatches with no human.
- Raw Exec on the bastion would also be refused by the Node
  (`bastion_fixture_denies_every_raw_exec`), but it parks under the Raw Exec rule first, so the
  stage would show a pending approval instead of a refusal.
- `node:role=bastion` is fan-out 1, far under the read-class blast cap (default 10000).
- `/etc/shadow` is explicitly denied in all three fixtures, so the fleet-wide variant (selector
  `tag:env=dev`) prints nine denial lines: an optional encore, *(predicted)*; only the
  bastion's verdict is asserted by a fixture test.

For the full response, drop the python filter. Its shape, *(predicted)* from
`RunOrPlanOutput`/`PerNodeResult`: `"structuredContent"` holds `"job_id"` and a `"results"`
array; each result has `"outcome": "denied_by_policy"`, `"stderr"` (the deny reason), empty
`"stdout"`, and a `"refusal_explanation"` opening "Refused by the Node, not by this control
plane" (`capability.PolicyDenyExplanation`). There is no `"exit_code"`: nothing executed.

The framing, verbatim, for the presenter to say:

> That refusal came from a root-owned Policy file on the bastion's own disk: the Relay can read
> that file's fingerprint but has no code path to change it, so no credential this control plane
> issues, the admin's included, can talk the bastion into it.

It stays inside invariant 2 and ADR-0002: it claims nothing about local root on the laptop,
does not call the Node a "machine" or a "host", and does not widen "credential this control
plane issues" to "credential in this room".

**Pre-flight.** Run the command once before going on stage. If the filter raises `KeyError`,
run it unfiltered; an authentication error means `.dev-fleet/` is stale (`make demo-creds`).
Immediately before the beat:

```console
$ scripts/dev-fleet-mcp.sh call list_nodes '{"selector":"node:role=bastion"}'
```

Expect exactly one Node.

### Triggering and clearing the fault

Trigger with `make demo-fault`. Expected output *(predicted, the `demo-fault` recipe's echo)*:

```
daemon-4: dev-fleet demo service DOWN (dev-fleet-service status: exit 3)
daemon-6: dev-fleet demo service DOWN (dev-fleet-service status: exit 3)
```

Three ways to clear it:

- **On stage, by Gleipnir:** `service.restart` with unit `nginx`, one Selector per faulted
  environment: `node:role=web, node:env=prod` reaches `daemon-4` (and healthy `daemon-5`),
  `node:role=web, node:env=staging` reaches `daemon-6` (and `daemon-9`). Each is a fan-out-2
  mutate that parks under `demo-fleet-wide-mutates-need-a-human`; Relay asks Gleipnir, and the
  answered retry restarts the real `httpd` through the web Nodes' `systemctl` shim. This is the
  operator-level repair described under the role choice above *(predicted as a fault repair;
  see there for what was observed)*. `node:role=web` alone reaches all six web Nodes in one
  call, which is also fine: the restart is idempotent.
- **On stage, by hand:** the Raw Exec restart, parked under
  `demo-raw-exec-always-needs-a-human`. With the AI-agent at `operator`, the presenter
  requests it as the founding admin, with the fleet-wide selector so both faulted Nodes clear
  in one call (`node:role=web, node:env=prod` would reach only `daemon-4`):

  ```console
  $ scripts/dev-fleet-mcp.sh call raw_exec \
      '{"selector":"tag:env=dev","argv":["/usr/local/bin/dev-fleet-service","restart"]}'
  ```

  Decide it by any of the ways in [The human approver](#the-human-approver) open to an `admin`
  (for example `approve_request` as the founding admin, or the Control API as `dev-approver`)
  and re-issue the call unchanged *(predicted)*. If the AI-agent asks for Raw Exec on its
  `operator` Account, the Relay refuses it on role before any gate or Node sees it.
- **Between takes:** `make demo-reset`.

Discovery, repair and verification in full are in
[The fault, and resetting between takes](#the-fault-and-resetting-between-takes).

### Confirming the reset took

`make demo-reset` checks every image is present, `relay` and every daemon are healthy, and
every one-shot exited `0`. It does **not** probe `dev-fleet-service status`, read
`GET /api/v1/approvals` or call `list_nodes` (the daemon healthcheck leaves the demo service
out). Run these yourself:

- Nine Nodes, all connected:

  ```console
  $ scripts/dev-fleet-mcp.sh call list_nodes '{"selector":"tag:env=dev"}' \
      | python3 -c 'import json,sys; n=json.load(sys.stdin)["result"]["structuredContent"]["nodes"]; print(len(n), "Nodes,", sum(1 for x in n if x.get("connected")), "connected")'
  ```

  Expected *(predicted)*: `9 Nodes, 9 connected`.
- `scripts/dev-fleet-mcp.sh api GET /api/v1/approvals`: an empty `approvals` array.
- Re-run the [AI-agent credential block](#credentials-for-gleipnir-copy-paste), then the
  approvals curl above with the new token: `200` and an empty array. Optional negative check:
  a token saved from before the reset (keep it in a scratch file outside the repo) must now be
  refused, `401` *(predicted)*.
- Restart Gleipnir and any MCP client (the CA changed), then re-run
  [the bypass beat](#the-bypass-beat-scripted-exactly).

Back to back: run `make demo-reset` two or three times in a row. Not yet observed live; record
the result under [Verification honesty](#verification-honesty).

### Signing in as a human over OAuth

**Opt-in.** `make demo-reset-oauth` and `make demo-up-oauth` layer `deploy/demo/oauth.yml`
on top: a DEV-ONLY Keycloak identity provider, and the Relay's OAuth resource-server half
turned on (ADR-0024;
[Human sessions](control-plane-credential.md#human-sessions-oauth-21-through-your-idp)). Claude
Code then signs in through a browser and reaches `/mcp` as the human Account `demo-user` (kind
`human`, role `operator`) instead of on a shared API Token. On that session, an answer to an
approval question given in Claude Code's UI is recorded as that human's **verified** decision
([approval.md](../specs/approval.md), AP-78 and AP-79). The plain targets bring up the plain
fleet, but `make demo-down`, `make demo-logs` and every reset's wipe also name
`deploy/demo/oauth.yml`, so a leftover IdP goes down too; even the plain targets therefore
need that file to parse, and a recent enough Compose (see Bring-up). Read
[What an OAuth session proves](#what-an-oauth-session-proves-and-what-it-does-not) before
saying anything about it on stage.

Every name below is fixed in `deploy/demo/oauth.yml` or its realm fixture,
`deploy/demo/keycloak/relay-demo-realm.json`:

| What | Value |
| --- | --- |
| Issuer | `http://127.0.0.1:8180/realms/relay-demo` |
| Audience (the MCP URL clients dial) | `https://relay:9443/mcp` |
| Claim naming the Account | `preferred_username` |
| Client for Claude Code | `relay-demo-claude-code` — public (no secret), PKCE `S256`, one redirect URI: `http://localhost:33418/callback` |
| The human | `demo-user`, password `dev-only-demo-user` — **DEV-ONLY**, committed like every other credential in this fleet |
| The negative control | `no-relay-account`, password `dev-only-no-relay-account` — **DEV-ONLY**, and deliberately given **no** Relay Account: signing in as it must be refused |
| Lifetimes | access token 12h; sign-in session 12h idle, 24h maximum — so a refresh cannot land mid-demo. **DEV-ONLY: do not copy these into a real realm** |
| Transport | `sslRequired: none` and plain HTTP on loopback. **DEV-ONLY: do not copy** |
| Administrator | **None.** No Keycloak admin exists, by design — see [Who can impersonate whom](#who-can-impersonate-whom) |

Two differences from the plain fleet, both deliberate:

- **No new `/etc/hosts` line.** The issuer must be one URL, byte for byte, for the browser,
  Claude Code on the host, and the Relay inside the fleet. Claude Code 2.1.284 refuses to send
  credentials to a plain-HTTP token endpoint unless the host is exactly `localhost`,
  `127.0.0.1` or `::1` (read from its bundled MCP SDK, and confirmed by the sign-in below), and
  any other name would need a hosts entry (`idp.localhost` resolves neither on stock Debian nor
  in Node). So the issuer is `127.0.0.1:8180`, and the Relay and Keycloak share one network
  namespace owned by a container that does nothing else (`relay-netns`), so `127.0.0.1:8180`
  inside the Relay is Keycloak. `relay-netns` carries the network alias `relay` and publishes
  `7654`, `9443` and `8180`, so other services reach the Relay as before. The existing
  `127.0.0.1 relay` line is the only hosts entry either mode needs.
- **The Account claim is `preferred_username`, not the default `email`.** An Account name is
  `[A-Za-z0-9._-]` only, so an email address cannot name one. `preferred_username` is the realm
  username, which users cannot edit.

#### Bring-up

1. **Prerequisites.** Everything in [From cold to ready](#from-cold-to-ready), including the
   `127.0.0.1 relay` line; host port `8180` free as well as `7654` and `9443`; **Docker Compose
   v2.18.0 or later**, because the overlay uses the `!reset` tag, first shipped in the
   compose-go that v2.18.0 pins (compose-spec/compose-go#380; this runbook was run on v5.1.4
   only). Since `make demo-down` and `make demo-reset` read the overlay too, an older Compose
   breaks the plain targets as well.
2. **`make demo-build`**, as for the plain fleet. Its pull names the overlay, so it also fetches
   Keycloak (pinned by digest) and the namespace holder's image. Observed on 2026-09-29: with
   the Keycloak image deleted, `make demo-build` pulled it by digest and
   `make demo-reset-oauth` then started. Without it, `make demo-reset-oauth` stops at its image
   precheck, before touching a volume, naming the missing image.
3. **`make demo-reset-oauth`.** The Relay starts only once Keycloak is healthy, because it
   fetches the issuer's discovery document once at boot and would not start without it. `init`
   also creates `demo-user` (the overlay sets `OAUTH_ACCOUNT_NAME`) through `/api/v1/accounts`,
   as it creates `dev-approver`. Observed on 2026-09-29 (4 CPUs, 8 GB, images present): 76s
   wall (timed before #893), the Relay booting first time with no restart. The closing output
   *(predicted — re-observe)*:

   ```
   demo-reset: reset complete — init exited 0, every service is healthy, .dev-fleet/ holds the fresh credentials.
   demo-reset: the CA was regenerated, so a registered MCP client still holds the OLD bearer token AND the OLD CA (NODE_EXTRA_CA_CERTS is read only at process start). Restart it — .dev-fleet/ is already current, so there is no need to run 'make demo-creds' again first:
   demo-reset:   claude mcp remove relay
   demo-reset:   claude mcp add --transport http --client-id relay-demo-claude-code --callback-port 33418 relay https://relay:9443/mcp
   demo-reset: then start Claude Code with NODE_EXTRA_CA_CERTS="$PWD/.dev-fleet/ca-cert.pem", run /mcp, pick relay, Authenticate, and sign in as demo-user / dev-only-demo-user (DEV-ONLY).
   ```

4. [Credentials for Gleipnir](#credentials-for-gleipnir-copy-paste) as usual; the overlay does
   not touch API Tokens.

Keycloak uses about 490 MiB of memory at idle (one `docker stats` sample, same machine); the
Relay and daemons are unchanged.

#### Signing Claude Code in

From the repo root:

```console
$ claude mcp remove relay     # only if a bearer-token `relay` is already registered
$ claude mcp add --transport http --client-id relay-demo-claude-code --callback-port 33418 relay https://relay:9443/mcp
$ NODE_EXTRA_CA_CERTS="$PWD/.dev-fleet/ca-cert.pem" claude
```

No `--client-secret` (the client is public) and no `--header`. `NODE_EXTRA_CA_CERTS` is for the
Relay's CA only; the IdP is plain HTTP on loopback. In Claude Code: `/mcp`, pick `relay`, choose
to authenticate. A browser opens Keycloak's sign-in page at `127.0.0.1:8180`; sign in as
`demo-user` / `dev-only-demo-user`; the page then reads "Authentication successful. You can
close this tab and return to Claude Code.", and `/mcp` shows `relay` connected.

Observed on 2026-09-29 with Claude Code 2.1.284, driven without a person (isolated config
directory, its `mcp_authenticate` control request, headless Chrome for the login): the `401`
led it to the metadata document and on to Keycloak; its authorization URL carried
`client_id=relay-demo-claude-code`, `redirect_uri=http://localhost:33418/callback`,
`resource=https://relay:9443/mcp` and no `scope`; it exchanged the code at the plain-HTTP token
endpoint and `relay` became `connected`; a `list_nodes` call on that session is in the audit
trail as `demo-user`, method `oauth`. After a `make demo-reset-oauth` it dropped the dead token
itself and reported the server as needing authentication; signing in again reconnected it. The
command above writes exactly the server entry that run used. **Not observed:** the interactive
`/mcp` menu's wording, and the browser opening by itself rather than Claude Code printing the
URL *(predicted)*.

Independent checks from the repo root (both observed):

```console
$ curl -sS --cacert .dev-fleet/ca-cert.pem https://relay:9443/.well-known/oauth-protected-resource
{"resource":"https://relay:9443/mcp","authorization_servers":["http://127.0.0.1:8180/realms/relay-demo"],"bearer_methods_supported":["header"],"resource_name":"Relay control plane"}
$ curl -sS -o /dev/null -D - --cacert .dev-fleet/ca-cert.pem -X POST https://relay:9443/mcp | grep -i www-authenticate
www-authenticate: Bearer resource_metadata="https://relay:9443/.well-known/oauth-protected-resource"
```

On the plain fleet the first returns `404` and the second a `401` with a bare
`WWW-Authenticate: Bearer` and no `resource_metadata` (a Relay with no issuer advertises no
flow): a quick way to tell which mode is up *(predicted from the Relay's code; the OAuth half is
observed)*.

**The Console and OAuth run together.** The Console is on in both modes, as
`deploy/demo/relay.toml` and `relay.oauth.toml` set it. An unauthenticated request off the
Console (`/mcp` and `/api/v1` included) gets the `401` challenge above, while a browser on
`/console/` goes to the Console's own sign-in, where `admin` signs in as on the plain fleet.
The founding admin's, `dev-approver`'s and `auto-incident-response`'s tokens work as before.
Observed on 2026-09-29 with OAuth on: unauthenticated `POST /mcp` got the challenge,
`GET /console/` a `303` to `/console/login`, `admin` signed in, and both approval stories (the
AI-agent's with responder `test_user`, and `demo-user`'s on the OAuth session) ran their Jobs
as described here.

#### Between takes

- **`make demo-down`, then `make demo-up-oauth`**: Keycloak's database has its own volume, so
  signing keys and sessions survive, and a signed-in Claude Code stays signed in. Observed: the
  same access token was accepted after the round trip, and a fresh Claude Code on the same
  config came up `connected` without signing in.
- **`make demo-reset-oauth`** wipes that volume with the rest: new signing keys, new sessions,
  a new Relay CA. Restart Claude Code with `NODE_EXTRA_CA_CERTS` and authenticate again from
  `/mcp`; it discards the dead token itself and shows `relay` as needing authentication
  (observed; the menu wording is *(predicted)*).
- **Switching modes** needs `make demo-down` first: `make demo-up` refuses over an OAuth fleet,
  and `make demo-up-oauth` over a plain one. `make demo-reset` and `make demo-reset-oauth`
  switch on their own. `make demo-down`, `make demo-creds` and `make demo-fault` work in either
  mode.

#### Who can impersonate whom

**Whoever administers the identity provider can impersonate any Relay Account, machine or
human, admin included.** Sign-in maps a claim to an Account *name* and checks only that the
Account exists and is enabled; it does not restrict sign-in by Account kind. ADR-0024's rule
that the Relay never creates an Account from a token stops the IdP *minting* Accounts, not
naming an existing one: a realm user called `admin` would sign in as the fleet's first admin.

So this IdP has **no administrator.** The overlay sets no `KC_BOOTSTRAP_ADMIN_*`, so the master
realm has no user, and the demo realm is imported from the fixture at start. Keycloak offers to
create a first administrator only to a request on its own loopback: here the namespace it
shares with the Relay, never another container and never the host (the published port arrives
from the Docker bridge gateway). Keycloak's management port (`9000`) is not opened: health and
metrics are off, and the healthcheck reads the realm's discovery document. Observed on
2026-09-29 from `daemon-4`'s network namespace (a curl container joined to it, since the daemon
image has no HTTP client):

| From a daemon's position | Answer |
| --- | --- |
| `http://relay:8180/` | `200`, Keycloak's welcome page saying "Local access required" to create an administrator, with no form |
| `POST http://relay:8180/` (create-admin form fields) | `400` |
| master-realm password grant as `admin` / `dev-only-keycloak-admin` (the credential this overlay used to set) | `400 invalid_grant` |
| `http://relay:8180/admin/realms/relay-demo/users`, no token | `401` |
| `http://relay:9000/…` | connection refused |
| `http://relay:8180/realms/relay-demo/…` (sign-in and token endpoints) | served |

From the host the welcome page also says "Local access required", and the admin API answers
`401`.

**The residual reach: any container on the fleet network, so a compromised Node or a Raw Exec
Task, can sign in as `demo-user`.** The shared namespace puts Keycloak's sign-in and token
endpoints on `relay:8180`, and `demo-user`'s password is committed. Observed: from `daemon-4`'s
namespace, a scripted authorization-code + PKCE sign-in got a token the Relay accepted
(`tools/list` → `200`). That reaches what `demo-user` can do (role `operator`) and no further,
since no one can add a realm user. Binding Keycloak to `127.0.0.1` would close `8180` to the
host as well (observed on a scratch Keycloak: a published port does not reach a listener bound
to container loopback), so it stays open, and this is why the overlay is DEV-ONLY.

#### What an OAuth session proves, and what it does not

- **It proves whose session made the call.** The Relay verified, offline against the IdP's
  keys, a token from this issuer for this audience, naming an existing, enabled Account: here
  `demo-user`, created human by `init` (which refuses to continue if that Account is not human,
  enabled and `operator`). Sign-in is not restricted by Account kind, so an IdP username equal
  to a machine or admin Account's name signs in as that Account; kind matters only when an
  answer is weighed (AP-79). The audit trail records the session with method `oauth` and no API
  Token id. Observed for a `list_nodes` read on a real authorization-code + PKCE token:
  `account_name=demo-user`, `account_role=operator`, `auth_method=oauth`, `token_id` empty. A
  real token for the same user from another client of the realm, with no Relay audience, was
  refused `401`; so was a real token for `no-relay-account` (both observed).
- **On this fleet, a verified answer proves nothing about who decided.** `demo-user`'s password
  is committed, and the AI-agent under test can read it and has a shell on the host, so it can
  script the sign-in itself. A verified OAuth answer here demonstrates the mechanism only.
- **It does not prove a person read the question.** Anything holding `demo-user`'s token
  answers as `demo-user`, and a Claude Code **hook** can answer an approval question with nobody
  present. Relay cannot tell that from a person ([approval.md](../specs/approval.md), the
  OAuth-session entry under accepted risks). A rule that needs evidence a person decided is an
  `out-of-band` rule.
- **The request is still the model's.** On this session `demo-user` is also the requester of
  whatever Claude Code runs; the calls are model-generated and agent-grade (ADR-0027). Its
  answer meets the same refusals as any in-band decision by `demo-user`: it never satisfies a
  rule that excludes the requester, or an `out-of-band` rule (AP-79, AP-13).
- **The OAuth fleet runs the demo gate**, as the plain demo targets do
  ([The human approver](#the-human-approver)). Under it `demo-user` (human, `operator`) may
  answer its own request for an Operation. It cannot release a Raw Exec, whose decision floor is
  `admin`, and cannot even request one (observed: `raw_exec` →
  `Raw Exec requires role "admin", has "operator"`).

  Observed on 2026-09-29 on the wire, with a scripted client declaring `claude-code` and form
  elicitation, on a real authorization-code + PKCE token for `demo-user`:
  `run_operation service.restart unit=nginx` on `node:role=web` returned `input_required`, with
  one form question keyed by the request id and a `requestState`; the retry answering `accept`,
  with **no** responder assertion, ran the Job, 6 × `success`. On the Control API the request
  is `approved` with one decision by `demo-user`, `human: true`, channel `in-band`; in the store
  that decision has no `on_behalf_of` (AP-79: nothing in the asserted lane). Answering
  `decline` instead, on `node:role=web, node:env=staging`, left the request `denied`, with no
  Job and no dispatch. The same call declaring `claude-code` on the founding admin's API Token
  was not asked: `pending_approval` (AP-78).

  **Real Claude Code, headless** (observed, Claude Code 2.1.284, driven through its SDK control
  protocol with no model turn): it receives the question, hands it to its host as an
  `elicitation` control request, and waits. Unanswered, the tool call hung until killed after
  120s, leaving the request `pending`. Answered `cancel`, which a client with nobody present may
  send, the Relay replied `answer_refused` ("approver is required …") and left the request
  `pending`, `0 of 1`, with no decision, so it can still be answered another way. A later call
  on an already-pending request of the same plan got `pending_approval` instead of being asked
  again (observed once). The interactive dialog with a person at it is *(predicted)*.

## The demo profile

`deploy/demo/docker-compose.yml` is the [dev-fleet.md](../dev-fleet.md) test fleet plus six
daemons, `daemon-4..9`: nine Nodes with varied `node:` labels and a third, strictly narrower
Policy fixture. Three Nodes do not read as a fleet on stage, and identical Policies produce no
interesting refusal. It has no profiles: every `up` of the file is all nine. Its Relay, its
one-shots and `daemon-1..3` are the test fleet's, service for service (enforced by
`test_fleet_is_the_demo_fleets_first_three_nodes`, `daemon/tests/dev_fleet_fixtures.rs`); its
`relay.toml` and gate are its own.

### Start from a clean registry

Do this first, on its own:

```console
$ make demo-build   # first time, and again after any code change
$ make demo-reset
```

The demo fleet is project `relay-demo`, the test fleet `relay-test`. They publish the same host
ports, so they cannot run at once: the demo targets refuse while `relay-test` has containers.
The targets also refuse a fleet another checkout owns.

`make demo-reset` = owner check → image check → `down -v` → `up -d` (`init` runs to
completion) → health wait → copy credentials to `.dev-fleet/`. It never builds; a missing image
is refused before anything is torn down.

Why `down -v`: `relay-data` is a **named** volume, so the registry survives a plain `down`. A
Node from an earlier experiment would still match Selectors and make `node:role=bastion`
resolve to **two** Nodes, which parks the beat that should run straight through. `-v` also
destroys the CA and every Node identity, so the fleet re-enrolls from scratch.

Stop the demo fleet with `make demo-down` (no `-v`: identities and the store survive) and bring
it back with `make demo-up` (no `-v`, no build). `demo-up` still re-mints credentials: `init`
has `restart: no`, but `up` starts a stopped one-shot again, which mints fresh values into the
persisted volume without copying them out; run `make demo-creds` after `demo-up`. There is no
`down` to run before `make demo-reset`: it wipes first. `make demo-up` always brings back all
nine daemons, because the file holds nine. `make demo-logs` follows the fleet's logs.

**Cleanup: stop it and leave it down.** `make demo-reset` brings the fleet straight back up. To
stop it and wipe its volumes, run this from the checkout root, naming both files (the OAuth
overlay is named so a leftover IdP goes too, as with `make demo-down`):

```console
$ docker compose -p relay-demo -f deploy/demo/docker-compose.yml -f deploy/demo/oauth.yml \
    down -v
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

Totals: 6 `role=web`, 2 `role=db`, 1 `role=bastion`; 4 `env=prod`, 2 `env=staging`, and the
three base Nodes with no `env` label. `list_nodes()` shows three distinct `policy_fingerprint`
values, one per fixture: the SHA-256 of the file's raw bytes (`policy_fingerprint` in
`daemon/crates/relay-policy/src/lib.rs`). Compute them with
`sha256sum docker/fixtures/policy.{web,db,bastion}.toml`; they change on any edit, comments
included.

### What varies, and what cannot

`node:` labels vary as above. Of the Facts a Node reports (relay-ops
`operations::system_facts`), only `hostname` and `ip_addresses` can differ in a single-host
Docker fleet; `os`, `arch` and `kernel` come from one kernel and one image. Faking them was
rejected, as the base fleet rejects a `systemctl` that reports success without doing anything:
a dev fleet that lies about itself is worse than one that is legibly limited. (The web Nodes'
`systemctl` shim restarts a real service and reports only what its probe observed;
[The fixture limit, stated plainly](../dev-fleet.md#the-fixture-limit-stated-plainly).)

`node:env=prod` and `node:env=staging` are **Node-authored** (set by `RELAY_NODE_LABELS` in the
compose environment, and forgeable by a compromised Node), while `tag:env=dev` is a **tag**,
written at enrollment from the Enrollment Token's initial tags as the minting Account's act, and
a compromised Node cannot write it. They are separate namespaces (invariant 7), and
`list_nodes()` always returns them as separate maps. (`tag:` labels are the third map,
`tag_labels`, written only by a human Account; the demo fleet's tags are the initial tags.)

### Selector cardinalities

| Selector | Nodes |
| --- | --- |
| `tag:env=dev` | 9 |
| `node:role=web` | 6 |
| `node:role=db` | 2 |
| `node:role=bastion` | 1 |
| `node:env=prod` | 4 |
| `node:env=staging` | 2 |
| `node:role=web, node:env=staging` | 2 |
| `node:role=db, node:env=prod` | 1 |

### Verification honesty

**The outcomes below are predicted, not observed.** Every `denied_by_policy` verdict is
underwritten by a hermetic test against the daemon's evaluator
(`daemon/tests/dev_fleet_fixtures.rs`); every `success` and `failure` depends on `busybox
httpd` and `dev-fleet-service` running in nine containers, which no test proves and nobody has
yet stood up at n=9. **Run the beats once before presenting, and correct this section with what
you saw.** Each beat is marked *(tested)* for the half a hermetic test covers and *(predicted)*
for the half that needs the real fleet.

Observed by hand on a live demo fleet (2026-09-29), and nothing more: under the in-band demo
gate, a `gleipnir` client on an API Token was asked the approval question and its answered
retry ran the Job; an unrecognised client got `pending_approval`, answered with
`approve_request`, re-issued, and ran; and `service.restart` of `nginx` on a web Node, through
the `systemctl` shim, exited `0`. The beats below were not re-run under that gate.

### The four beats

**a. Fleet read, all success.**

```
run_operation(selector="tag:env=dev", operation="file.read", args={"path":"/etc/os-release"})
```

→ 9 × `success`. The allow verdict is tested on all three fixtures
(`all_three_policy_files_lint_clean_with_the_template_pack`,
`bastion_allows_exactly_the_documented_read_and_nothing_else`); the nine-Node result is
*(predicted)*. No approval: `read` class.

**b. Mixed read set, no approval at all.**

```
run_operation(selector="tag:env=dev", operation="file.read", args={"path":"/var/lib/dev-fleet-service/state"})
```

→ 6 × `success` (the web Nodes) *(predicted)*, 2 × `failure` (the db Nodes have no such file)
*(predicted)*, 1 × `denied_by_policy` (the bastion, exact-path allow only)
*(tested, `bastion_allows_exactly_the_documented_read_and_nothing_else`)*.

**c. The mutate mixed set.**

**On stage, immediately before this beat, run `list_nodes(selector="node:role=bastion")` and
`list_nodes(selector="tag:env=dev")`.** Only these read the **real registry** rather than the
compose file. If the first returns anything but one Node, or the second anything but nine,
stop and run `make demo-reset`: a stale Node changes the fan-out.

Then:

```
raw_exec(selector="tag:env=dev", argv=["/usr/local/bin/dev-fleet-service","restart"])
```

→ parks under `demo-raw-exec-always-needs-a-human` with a `request_id` and a `plan_hash` (the
rule matches every Raw Exec at any fan-out, as the fixture is written; nobody has watched this
fan-out park). Approve it any way [The human approver](#the-human-approver) allows an `admin`,
here as `dev-approver` on the Control API:

```console
$ scripts/dev-fleet-mcp.sh api-approver POST /api/v1/approvals/<request_id>/decision \
    '{"approve":true,"plan_hash":"<plan_hash>","reason":"repair the dev-fleet demo service"}'
```

then re-issue the same call unchanged (with `wait_seconds`, or poll `get_job` until
`job_status` is `complete`) → **6 × `success, exit_code: 0`** *(predicted)* and
**3 × `denied_by_policy`** *(tested — `daemon-3` and `daemon-7` by
`raw_exec_verdicts_match_the_web_db_split`; `daemon-8` by
`bastion_fixture_denies_every_raw_exec`, both in `daemon/tests/dev_fleet_fixtures.rs`)*.
Preflight the same argv with `plan=true` first for 6 allow / 3 deny and no parking.

**d. The straight-through (unparked) mutate at n=9.** Two Selectors, both fan-out 1:

```
run_operation(selector="node:role=db, node:env=prod", operation="service.restart", args={"unit":"nginx"})
```

→ dispatched with no human; terminates `failure` with
`stderr="spawn systemctl: No such file or directory"` and no `exit_code`. This is the
documented busybox limit ([The fixture limit, stated plainly](../dev-fleet.md#the-fixture-limit-stated-plainly)),
not a defect: the `systemctl` shim is only on the web Nodes, and a db Node runs no demo service
*(predicted; the shim's absence on a `role=db` Node was observed in the image)*; and

```
run_operation(selector="node:role=bastion", operation="service.restart", args={"unit":"nginx"})
```

→ dispatched with no human (the gate's fan-out-1 behaviour, untested here, *(predicted)*) and
refused by the Node: 1 × `denied_by_policy`
*(tested, `bastion_allows_exactly_the_documented_read_and_nothing_else`)*.

There is no successful straight-through `service.restart` at n=9: it succeeds only on web
Nodes, and no `node:` Selector here reaches a single web Node, so any that can succeed is
fan-out 2 or more and parks.

### The threshold, stated on the page

`min_fan_out: 2` is **unchanged**. At nine Nodes almost every interesting fan-out crosses it
and parks, which is the right lesson: raising it to keep a straight-through beat would let a
four-Node mutate run with no human. `node:role=db`, straight-through on the three-Node test
fleet, is **two** Nodes here and parks. The straight-through path stays reachable through beat
(d)'s two fan-out-1 Selectors. Every Raw Exec parks at any fan-out under
`demo-raw-exec-always-needs-a-human`, which is not retuned either.

### The fault, and resetting between takes

`make demo-fault` kills the real `busybox httpd` on a subset of `role=web` Nodes, out of band,
through `docker compose exec` and never through the Relay (there is no "break" verb in the
control path; see
[Why `start|restart|status` and not `stop`](../dev-fleet.md#why-startrestartstatus-and-not-stop)).
The default targets are `daemon-4` (`dev-node-4`, `env=prod`) and `daemon-6` (`dev-node-6`,
`env=staging`): one per environment, neither on the ["drop first" list](#resource-usage).
Override with `DEMO_FAULT_NODES`, e.g. `make demo-fault DEMO_FAULT_NODES="daemon-2 daemon-9"`.
The value reaches the recipe as an environment variable, is split on whitespace with globbing
off, and every token is checked against the fixed list of `role=web` services before any
`exec`, so a shell metacharacter is refused, not executed, and so is a Node that runs no demo
service. The kill is idempotent and safe to repeat without a reset.

**What is true after the fault.** `httpd` is really killed (found by `pidof`, not the pidfile,
so a stale pidfile cannot redirect the kill), and `dev-fleet-service status` on that Node
reports `state=down` (exit `3`); `make demo-fault` polls that probe before printing. Nothing is
written to stage the condition.

**Discovery: read path, no approval.** Fan `file.read` of `/proc/net/tcp` across the web
Nodes:

```
run_operation(selector="node:role=web", operation="file.read", args={"path":"/proc/net/tcp"})
```

Read class, unparked; the wildcard `file.read` allow in `policy.web.toml` covers this path
(`web_policy_allows_reading_the_socket_table`, `daemon/tests/dev_fleet_fixtures.rs`). Look for a
row whose **local address is `0100007F:1F90` (127.0.0.1:8080) AND whose state is `0A`
(`TCP_LISTEN`)**: present on a serving Node, absent on a faulted one. Do not key off port `1F90`
alone: a recently closed connection leaves a `TIME_WAIT` row (state `06`) at that address for
up to ~60s. `/var/lib/dev-fleet-service/state` is never rewritten to say "down"
([The real service](../dev-fleet.md#the-real-service)), so it is the *repair* proof, not the
discovery signal.

**Repair: mutate path.** No `node:` Selector reaches a single web Node. `node:role=web` reaches
all six; each existing `role`+`env` combination reaches two (`daemon-4`/`daemon-5` on
`env=prod`, `daemon-6`/`daemon-9` on `env=staging`); `daemon-1` and `daemon-2` have no `env`
label ([The nine-Node roster](#the-nine-node-roster)). So either repair reaches the faulted Node
and a healthy sibling, which is harmless: `dev-fleet-service restart` is idempotent.

```
raw_exec(selector="node:role=web, node:env=prod", argv=["/usr/local/bin/dev-fleet-service","restart"])
```

matches `daemon-4` (faulted) and `daemon-5` (healthy); use `env=staging` for `daemon-6`
(faulted) and `daemon-9` (healthy). It parks under `demo-raw-exec-always-needs-a-human`; approve
it any way [The human approver](#the-human-approver) allows an `admin` (`dev-approver` on the
Control API, as in [Approving a parked dispatch](../dev-fleet.md#approving-a-parked-dispatch),
still works), then re-issue the same call unchanged.

The operator-level repair is the Native Operation over the same Selector:

```
run_operation(selector="node:role=web, node:env=prod", operation="service.restart", args={"unit":"nginx"})
```

On the web Nodes `systemctl` is the DEV-ONLY shim
([The fixture limit, stated plainly](../dev-fleet.md#the-fixture-limit-stated-plainly)), so this
runs `dev-fleet-service restart`. A fan-out-2 mutate, it parks under
`demo-fleet-wide-mutates-need-a-human` and can be approved in-band by the client that asked
(with an asserted responder name Relay records and does not verify); approved, it returns
2 × `success, exit_code: 0` and the faulted Node serves again *(predicted)*. `svc.status` and
`svc.restart` from the demo Template pack are the typed read/mutate pair for the same beat,
dispatchable by name (ADR-0042).

**Independent verification.** `file.read` of `/var/lib/dev-fleet-service/state` on the
repaired Node shows a new `pid` and `started_epoch`
([The real service](../dev-fleet.md#the-real-service)), and the `/proc/net/tcp` discovery read
shows the `0100007F:1F90 ... 0A` row again.

**`make demo-reset`** is the reliable way back to the starting state: fault cleared,
Jobs/approvals/audit/registry cleared (the store is on `relay-data`, wiped by `down -v`), the
CA and every credential fresh, every Node healthy. Unlike a bare
`docker compose -f deploy/demo/docker-compose.yml down -v` / `up`, it never builds (run
`make demo-build` first) and it verifies rather than assumes:

1. The ownership check: no `relay-demo` container may belong to another checkout.
2. Every image `docker compose config --images` names must already exist, checked before
   anything is torn down.
3. `down -v --remove-orphans`.
4. `up -d --no-build --pull never`: `init` runs to completion (minting the credentials and the
   Enrollment Token), and the daemons start only once it has exited `0`.
5. Waits (`--wait`) until `relay` and every daemon are healthy.
6. `scripts/dev-fleet-mcp.sh init` **copies** the fresh credentials to `.dev-fleet/` (a
   `docker compose cp` out of the exited `init` container, nothing more).

**The CA is regenerated on every reset, so a registered MCP client holds a stale bearer token
and a stale CA** (`NODE_EXTRA_CA_CERTS` is read only at process start). `.dev-fleet/` is
already current after step 6, so just restart the client: `claude mcp remove relay` /
`claude mcp add ...` as in [Connecting Claude Code](../dev-fleet.md#connecting-claude-code);
the reset's closing summary says so. `make demo-creds` is needed only after `demo-up`, which
re-mints into the volume (see [Survive `down` / `up`](../dev-fleet.md#survive-down--up)) but
copies nothing out. `demo-creds` mints nothing; it is a pure copy, safe to run any number of
times.

**The refusal.** The targets refuse a `relay-demo` fleet started from another checkout
(compared by physical path), an `up` in the other OAuth mode, and a non-local engine
(`DOCKER_HOST` or the docker context), before any `docker compose` call.

**Verification honesty.** The `/proc/net/tcp` signal is *(predicted)* from
`web_policy_allows_reading_the_socket_table` (`daemon/tests/dev_fleet_fixtures.rs`): the Policy
engine allows the read, but no test starts a real `busybox httpd` or reads its socket table.
"Reset survives back to back" has **not been observed live**: the recipes have been checked
statically (`docker compose config`, `make -n`, and `make test-dev-fleet-make`, which runs the
guards and `demo-fault` against a stub docker), and a real `down -v` / `up` / fault cycle has
not been run since #893. Before presenting, run fault → discover → repair → verify and
`make demo-reset` two or three times back to back, and correct this paragraph with what you saw.

### Resource usage

**PENDING MEASUREMENT (#452, AC 4).** No number here has been measured, and none should be
invented. Whoever next has Docker Engine + Compose v2 should run this procedure and fill in the
table, in the same change that adjusts the roster if that turns out to be needed.

**Procedure:**

1. `docker compose -f deploy/demo/docker-compose.yml down -v`, then
   `docker compose -f deploy/demo/docker-compose.yml up --build -d`; wait until
   `docker compose -f deploy/demo/docker-compose.yml ps` shows all nine daemons `healthy`; let it
   settle 60s.
2. **Idle:** three samples 10s apart of
   `docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"`. Record
   total memory, the `relay` container, and one representative web / db / bastion daemon.
3. **Fan-out:** sample the same command while running
   `run_operation(selector="tag:env=dev", operation="system.facts")` in a tight loop, and
   once more during the approved `raw_exec` restart across all nine. Record the peak.
4. Record the machine (CPU, RAM, OS, Docker version) and the date beside the table.
5. **If nine does not sit comfortably, drop `daemon-9` first, then `daemon-5`.** `daemon-9` and
   `daemon-6` are both `role=web, env=staging`, so dropping both would take
   `node:role=web, node:env=staging` to zero; dropping `daemon-9` then `daemon-5` keeps every
   Selector in the cardinality table at 1 or more. In the same change, update this roster
   table and the compose service + `daemonN-state` volume being dropped, the Selector
   cardinalities table and every beat that says "9 ×" / "6 ×", and
   `daemon/tests/dev_fleet_fixtures.rs`'s `ROSTER` and
   `a_single_node_selector_survives_at_nine_nodes`.

| measured on | date | who | idle memory (total) | idle memory (`relay`) | idle memory (1 daemon) | fan-out peak memory | idle CPU | fan-out peak CPU |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ | _pending_ |
