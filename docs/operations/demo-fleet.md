# The demo fleet

The nine-Node `demo` compose profile of the [local dev fleet](../dev-fleet.md), as a runbook:
roster, beats, fault injection and resetting between takes, and resource usage. Read
[dev-fleet.md](../dev-fleet.md) first — its **DEV-ONLY** banner, prerequisites, bring-up and MCP
connection all apply here, with more force: three times the Nodes sit behind the same committed
dev credential. This file is also the presenter's runbook for the Relay half of a stage demo
([Presenter runbook](#presenter-runbook), below) — the overall script, including Gleipnir's own
half of it, lives in Gleipnir's own presenter runbook, which is maintained with Gleipnir and not
published here.
Gleipnir is the AI-agent that drives the demo: a consumer of Relay, never a part of it.

## Presenter runbook

A presenter who has never run this fleet, from cold to on stage: bring-up, the credentials
Gleipnir authenticates with, the human approver, the scripted bypass beat, the fault, and reset — and, opt-in,
[signing Claude Code in as a human over OAuth](#signing-in-as-a-human-over-oauth).

### Posture, stated once

This is containers on a laptop, not a production deployment. Every warning in
[dev-fleet.md](../dev-fleet.md)'s **DEV-ONLY** banner applies here, with more force: nine Nodes
sit behind the very same committed default Console password, the control plane is loopback-only, and every
container shares one kernel. This section makes no hardening claims. It is worth saying anyway,
because the Node's refusal in the bypass beat below is produced by the same relay-daemon Policy
engine whether it runs in a container on a laptop or on a server in a datacenter — the posture
paragraph costs nothing to state, and the refusal is real either way. One more number, stated
once: the issue that commissioned this runbook planned for about 24 Nodes; the demo profile as
built ([#452](https://github.com/Felag-Engineering/relay/issues/452)) is nine, and every
count below is for nine.

### From cold to ready

1. **Prerequisites.** Docker Engine with the Compose v2 plugin, `python3` (`scripts/dev-fleet-mcp.sh`
   shells out to it), and `curl`. Add the
   `/etc/hosts` mapping for any client other than `scripts/dev-fleet-mcp.sh` (that script pins
   with `curl --resolve`, so it does not need it) — the control plane's server certificate has a
   single SAN, `relay`, and Gleipnir and Claude Code both need to dial that name to get verified
   TLS. Reuse the exact one-liner from
   [Connecting Claude Code](../dev-fleet.md#connecting-claude-code):

   ```console
   $ grep -q 'relay$' /etc/hosts || echo '127.0.0.1 relay' | sudo tee -a /etc/hosts
   ```

   Host ports `7654` and `9443` must be free: `make demo-reset` fails at bind if anything else
   holds them. The make targets refuse a `relay-demo` fleet started from another checkout.

2. **`make demo-build`.** Do it the day before, not on stage — it is the only demo-fleet target
   that builds anything, and again after any code change. It builds the relay, `init` and
   daemon images, and pre-pulls only the OAuth overlay's images, only where they are missing, so
   a fresh Docker engine is left ready for `make demo-reset`, which never pulls.

3. **`make demo-reset`.** Expected closing output *(predicted — re-observe; the literal `echo` lines in
   `scripts/dev-fleet-mcp.sh`'s `cmd_init` and the `demo-reset` recipe)*, in this
   order, after compose's own progress output:

   ```
   dev-fleet-mcp: CA cert and both credentials are in .dev-fleet/
   dev-fleet-mcp: copy-paste launch commands: .dev-fleet/start-claude.txt
   demo-reset: reset complete — init exited 0, every service is healthy, .dev-fleet/ holds the fresh credentials.
   demo-reset: the CA was regenerated, so a registered MCP client still holds the OLD bearer token AND the OLD CA (NODE_EXTRA_CA_CERTS is read only at process start). Restart it — .dev-fleet/ is already current, so there is no need to run 'make demo-creds' again first:
   demo-reset:   claude mcp remove relay
   demo-reset:   claude mcp add --transport http relay https://relay:9443/mcp --header "Authorization: Bearer $(cat .dev-fleet/control-credential)"
   ```

   **Failure.** The failing command exits non-zero and make stops on that line; if `init`
   failed, no daemon started — `docker compose -p relay-demo logs init`.

4. **Enrollment timing from cold. Unmeasured.** No one has timed a cold `make demo-reset` at
   nine Nodes, and no number is invented here. The only bound in code is `DEMO_WAIT_SECONDS`,
   default 240s — reset fails past it, which is a timeout, not a measurement. To measure it: run
   `make demo-build` once, then `time make demo-reset` three times back to back, recording wall
   time and machine below (same style as [Resource usage](#resource-usage)):

   | measured on | date | who | `demo-build` (first run) | `demo-reset` cold wall time — run 1 | run 2 | run 3 |
   | --- | --- | --- | --- | --- | --- | --- |
   | _unmeasured_ | _unmeasured_ | _unmeasured_ | _unmeasured_ | _unmeasured_ | _unmeasured_ | _unmeasured_ |

   **Credential lifetime.** Every credential a reset mints expires 24h later — the founding
   admin's (`-ttl 24h`) and `dev-approver`'s (`ttl_seconds` 86400), both in
   `docker/dev-fleet-init.sh` — and the Gleipnir token minted below matches that same 86400s. So
   reset on demo day, not the night before.

5. Mint Gleipnir's credentials — [Credentials for Gleipnir (copy-paste)](#credentials-for-gleipnir-copy-paste),
   next — then run [Confirming the reset took](#confirming-the-reset-took).

### Credentials for Gleipnir (copy-paste)

**One machine Account per named AI-agent.** The demo's agent is `auto-incident-response`, and
it gets a machine Account of that name, so the AI-agent's own name is the **verified** actor on
every audit row it causes — not a shared `gleipnir` Account that every AI-agent would hide behind.
A second AI-agent gets its own Account and its own API Token: re-run the block below with another
name in `AGENT=` on its first line. That is the only edit.

**The Account name is not the client name.** The Account is the AI-agent's and its name is free to
choose. But the MCP client must still **declare its client name as `gleipnir`** in the request's
`clientInfo`, because the Relay asks the approval question in-band only of a client name it
recognises (AP-78): `gleipnir` on any session, `claude-code` only on an OAuth session of a human
Account; anything else gets `pending_approval` and asks nobody. And on an API Token session —
which this is — the answered retry must carry the responder assertion `io.gleipnir/responder`,
with `gate` `permission` and a `username` (AP-64); without it the answer is refused. The
approver the demo names there is `test_user`. That username is **asserted**, recorded beside the
verified `auto-incident-response`, never verified (see `kind: "machine"` below).

Observed on 2026-09-29, with the block below run as written: a client declaring `gleipnir` on
the `auto-incident-response` token was asked in-band for `service.restart` of `nginx` on
`node:role=web`, and its retry naming responder `test_user` ran the Job, 6 × `success`. Read back:
the request's `requested_by` is `auto-incident-response`; its one decision is by
`auto-incident-response`, `human: false`, channel `in-band`; and the store records `test_user` only
as the decision's asserted `on_behalf_of` (the audit row's `asserted_on_behalf_of`), beside the
verified `auto-incident-response` with method `api_token`.

**Re-run this after every reset.** `make demo-reset` runs `down -v`, which destroys the store:
the AI-agent's machine Account, its API Token, and the CA all die with it. After running the
block below, make Gleipnir pick up the new token and the new CA. How Gleipnir reloads them
(restart, or otherwise) is Gleipnir's own runbook to document — most clients read a
CA only at process start, so restarting it is the safe assumption *(predicted)*. A `make
demo-up` keeps the store, so the Gleipnir token survives it; only `demo-reset` requires a re-run.

The block below is one fenced shell block, run from the repo root. It runs in a subshell with
fail-fast settings, is safe to re-run (create-or-lookup), never echoes the token, and writes the
token file `0600` with no trailing newline. The shell below is literal — copy it as written:

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

Expected output (observed 2026-09-29, the id differs per reset): the one line
`auto-incident-response: Account acct-…; API Token in .dev-fleet/auto-incident-response-credential`. A python traceback here
(typically a `KeyError`) means the call it wraps was refused — re-run the same
`scripts/dev-fleet-mcp.sh api` call without the python filter to see why (most likely
`.dev-fleet/` is stale; run `make demo-creds`).

Why each guard, stated once on the page:

- `scripts/dev-fleet-mcp.sh api` exits 0 even on an HTTP error (plain `curl -sS`, no `--fail`,
  then a pretty-printer), so the guards above test the extracted values, not the exit code. A
  409 on the create call (name already taken) is harmless: the second `find_id` resolves the id
  regardless. This mirrors `docker/dev-fleet-init.sh`'s own create-then-resolve pattern.
- Without `pipefail` and the tmp-then-`mv` step, a failed mint would leave an empty file that
  looks like a credential. With them, the real file only ever holds a token. A run that fails
  before the `mv` can leave `.dev-fleet/<agent>-credential.tmp` behind — harmless (it is
  `0600`, inside the gitignored `.dev-fleet/`, and the next successful run overwrites it before
  renaming it), but safe to `rm -f` before re-running if you want a clean directory.
- No trailing newline, so a client that reads the file verbatim into a header does not send one.
- The `case` refuses an `AGENT` outside the Account-name alphabet before anything runs, so the
  name can never reach a file path or a JSON body as anything but a plain name.

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
  question — which is recorded as an assertion beside the AI-agent's verified Account
  (`auto-incident-response`), never as verified. Relay cannot tell whether a human gave that name: an AI-agent steered by prompt
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
- **What operator can do, and what it costs.** Raw Exec is admin-only, so the AI-agent's
  `operator` Account cannot request the Raw Exec repair of the fault — the presenter drives that one by hand (see
  [Triggering and clearing the fault](#triggering-and-clearing-the-fault)). But Gleipnir can
  discover the fault with a read (`file.read`) and repair it with a gated mutate of its own:
  `service.restart` with unit `nginx` on `node:role=web, node:env=prod` (fan-out 2, mutate
  class) parks under `demo-fleet-wide-mutates-need-a-human` — a different rule from the one
  beat (c) below exercises (`demo-raw-exec-always-needs-a-human`, which is Raw Exec-specific,
  not fan-out-specific). Because that rule is in-band, Relay sends the approval question to
  Gleipnir — a client declaring the name `gleipnir`, on the `auto-incident-response` Account's
  token — and its retry carrying an answer with a responder named (`test_user`) runs the Job. That Gleipnir puts the question to a human in its own UI,
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
  the AI-agent request the Raw Exec repair itself, and a Raw Exec is decided at `admin` too — the
  floor for deciding is the floor for requesting. Account and API-Token administration are
  admin-only and not human-only (`authz.requiredControlRole`; the owner decision to narrow them
  is recorded there as open), so a machine admin can also mint API Tokens for other Accounts.
  It is not free for approvals either: under the demo gate an `admin` AI-agent Account can release
  its own Raw Exec exactly as an `operator` one can release its own Operation — an in-band
  answer carrying a name it supplied itself — so with `admin`, every Raw Exec on this fleet is
  one the AI-agent could request and release alone (see `kind: "machine"` above and
  [The human approver](#the-human-approver)). If you choose `admin`, change `"operator"` to
  `"admin"` in the create body above. **A human should confirm this choice** before a presenter
  relies on it, and Gleipnir's own presenter runbook must agree with whichever role is actually
  used.
- A pre-existing Account of the `AGENT` name is reused as it is, whatever its role. To see its role, read
  `"role"` in `scripts/dev-fleet-mcp.sh api GET /api/v1/accounts`. After a reset there is none.

**Export the CA.** `.dev-fleet/ca-cert.pem` is written by `make demo-reset` (it runs
`scripts/dev-fleet-mcp.sh init`) and by `make demo-creds`. Give Gleipnir exactly three values:
the MCP URL `https://relay:9443/mcp`; the CA file (the absolute path of
`.dev-fleet/ca-cert.pem`); and the API Token in `.dev-fleet/auto-incident-response-credential`,
sent in an `Authorization: Bearer` header — plus the two things the block cannot set: declare
the client name `gleipnir`, and name the responder (`test_user`) on an answered approval. Gleipnir's own config keys are Gleipnir's to document
— they are not invented here.

Optional, needs `openssl`:

```console
$ openssl x509 -in .dev-fleet/ca-cert.pem -noout -subject -enddate -fingerprint -sha256
```

Verify the new API Token over verified TLS, mirroring the script's own `curl` flags:

```console
$ curl -sS --resolve relay:9443:127.0.0.1 --cacert .dev-fleet/ca-cert.pem \
    -H "Authorization: Bearer $(cat .dev-fleet/auto-incident-response-credential)" \
    https://relay:9443/api/v1/approvals
```

Expected *(predicted)*: an empty `approvals` array. Any authenticated caller may read the queue
(`handleListApprovals`). Then prove the token is not an admin's:

```console
$ curl -sS -o /dev/null -w '%{http_code}\n' --resolve relay:9443:127.0.0.1 \
    --cacert .dev-fleet/ca-cert.pem \
    -H "Authorization: Bearer $(cat .dev-fleet/auto-incident-response-credential)" \
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
the `make demo-*` targets set `DEV_FLEET_APPROVAL_GATE_CONFIG`, which `docker-compose.demo.yml` hands
the Relay as `RELAY_APPROVAL_GATE_CONFIG`. A bare `docker compose -f docker-compose.demo.yml --profile demo up` sets
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
  (human, admin) may each decide any request here. The AI-agent's `operator` Account
  (`auto-incident-response`) may decide a gated Operation, and never a Raw Exec; so may
  `demo-user`, the OAuth fleet's human operator.
- **`requester_allowed: true`** means the requester may fill the slot. A **human** requester —
  the founding admin driving a Raw Exec by hand — may approve its own parked dispatch. A
  **machine** requester — the AI-agent's Account, `auto-incident-response` — may too, provided its
  in-band answer carries a non-blank asserted name, recorded beside that verified Account. Relay cannot tell whether a
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
   a live fleet, with a client declaring `gleipnir` on the `auto-incident-response` Account's API
   Token. `claude-code` is asked only on a human
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

`dev-approver` still exists on this fleet — the `init` one-shot (`docker/dev-fleet-init.sh`)
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
    '{"selector":"node:role=bastion","operation":"file.read","args":{"path":"/etc/shadow"},"wait_seconds":60}' \
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
- `result.structuredContent` is the path the `list_nodes` check below
  reads. The per-Node fields `outcome`, `stderr` and `refusal_explanation` are the MCP
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
  With the AI-agent's Account at `operator` (the default), the presenter requests
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
  *(predicted)*. If the AI-agent asks for Raw Exec on its `operator` Account,
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

  Expected *(predicted)*: `9 Nodes, 9 connected`. It reads `result.structuredContent.nodes`.
- `scripts/dev-fleet-mcp.sh api GET /api/v1/approvals`: an empty `approvals` array.
- Re-run the [AI-agent credential block](#credentials-for-gleipnir-copy-paste), then the
  approvals curl above with the NEW token: `200` with an empty `approvals` array. Negative
  check: a token saved from before the reset must now be refused, because the store was wiped —
  expected `401` *(predicted)*. Save the old token to a scratch file outside the repo only if you
  want to run this check; otherwise skip it.
- Reload Gleipnir and any MCP client (the CA changed), then re-run
  [the bypass beat](#the-bypass-beat-scripted-exactly).

Back to back: run `make demo-reset` two or three times in a row. This has not been observed
live — see [Verification honesty](#verification-honesty) below, which already says so; record
the result there the first time someone runs it.

### Signing in as a human over OAuth

**Opt-in, and off unless you ask for it.** `make demo-reset` and `make demo-up` bring up exactly
the fleet described everywhere else on this page — but `make demo-down` and every reset's wipe
now name `docker-compose.oauth.yml` too, so that an IdP left from an earlier OAuth run goes down
with the rest. So even the plain targets now need that file to parse, and a Compose new enough
for it (see Prerequisites below). `make demo-reset-oauth` and
`make demo-up-oauth` layer `docker-compose.oauth.yml` on top: a DEV-ONLY Keycloak identity
provider, and the Relay's OAuth resource-server half turned on (ADR-0024;
[Human sessions](control-plane-credential.md#human-sessions-oauth-21-through-your-idp)). With
it, Claude Code signs in through a browser as the realm's human user and reaches `/mcp` on
that human's own Account, `demo-user` (kind `human`, role `operator`), instead of on a shared
API Token. That is the session on which an answer to an approval question, given in Claude
Code's own UI, is recorded as that human's **verified** decision
([approval.md](../specs/approval.md), AP-78 and AP-79). What it does and does not prove is at
the end of this section — read it before saying anything about it on stage.

Every name below is fixed in `docker-compose.oauth.yml` or its realm fixture,
`docker/fixtures/keycloak/relay-demo-realm.json`:

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

Two things differ from the plain fleet, each on purpose:

- **No new `/etc/hosts` line.** The issuer must be one URL, byte for byte, for the browser, for
  Claude Code on the host, and for the Relay inside the fleet. Claude Code 2.1.284 refuses to
  send credentials to a plain-HTTP token endpoint unless the host is exactly `localhost`,
  `127.0.0.1` or `::1` (read from its bundled MCP SDK, then confirmed by the sign-in below
  succeeding), and any other name would also need a hosts entry — `idp.localhost` does not
  resolve on a stock Debian host, nor in Node. So the issuer is `127.0.0.1:8180`, and the Relay
  and Keycloak share one network namespace, owned by a container that does nothing else
  (`relay-netns`), so that `127.0.0.1:8180` inside the Relay is Keycloak. `relay-netns` carries
  the network alias `relay` and publishes `7654`, `9443` and `8180`, so every other service
  still reaches the Relay exactly as before. The existing `127.0.0.1 relay` line is the only
  hosts entry either mode needs.
- **The Account claim is `preferred_username`, not the default `email`.** An Account name is
  `[A-Za-z0-9._-]` only, so an email address can never name one. `preferred_username` is the
  realm username, which the realm does not let a user edit.

#### Bring-up

1. **Prerequisites.** Everything in [From cold to ready](#from-cold-to-ready), including the
   `127.0.0.1 relay` hosts line; host port `8180` free as well as `7654` and `9443`; **Docker
   Compose v2.18.0 or later** — the overlay uses the `!reset` tag, which first shipped in the
   compose-go that v2.18.0 pins (compose-spec/compose-go#380; this runbook was run on v5.1.4
   only), and since `make demo-down` and `make demo-reset` read the overlay too, an older Compose
   breaks the plain targets as well.
2. **`make demo-build`**, as for the plain fleet. Its pull names the overlay too, so it also
   fetches the IdP's image (Keycloak, pinned by digest) and the namespace holder's — whichever
   fleet you bring up next. Observed on 2026-09-29: with the Keycloak image deleted locally,
   `make demo-build` pulled it by digest and `make demo-reset-oauth` then started. Without it,
   `make demo-reset-oauth` stops at its image precheck, before touching a volume, naming the
   missing image.
3. **`make demo-reset-oauth`.** The Relay starts only once Keycloak is healthy — it fetches the
   issuer's discovery document once, at boot, and would not start without it — and the
   `init` also creates `demo-user` (the overlay sets `OAUTH_ACCOUNT_NAME`) through
   `/api/v1/accounts`, the way `dev-approver` is created. Observed on 2026-09-29 (4 CPUs, 8 GB, images already present):
   76s wall (pre-#893 timing), the Relay booting first time with no restart. The closing output *(predicted — re-observe)*:

   ```
   demo-reset: reset complete — init exited 0, every service is healthy, .dev-fleet/ holds the fresh credentials.
   demo-reset: the CA was regenerated, so a registered MCP client still holds the OLD bearer token AND the OLD CA (NODE_EXTRA_CA_CERTS is read only at process start). Restart it — .dev-fleet/ is already current, so there is no need to run 'make demo-creds' again first:
   demo-reset:   claude mcp remove relay
   demo-reset:   claude mcp add --transport http --client-id relay-demo-claude-code --callback-port 33418 relay https://relay:9443/mcp
   demo-reset: then start Claude Code with NODE_EXTRA_CA_CERTS="$PWD/.dev-fleet/ca-cert.pem", run /mcp, pick relay, Authenticate, and sign in as demo-user / dev-only-demo-user (DEV-ONLY).
   ```

4. [Credentials for Gleipnir](#credentials-for-gleipnir-copy-paste) as usual — API Tokens are
   untouched by the overlay.

Keycloak costs about 490 MiB of memory at idle (one `docker stats` sample, same machine); the
Relay and daemons are unchanged.

#### Signing Claude Code in

From the repo root:

```console
$ claude mcp remove relay     # only if a bearer-token `relay` is already registered
$ claude mcp add --transport http --client-id relay-demo-claude-code --callback-port 33418 relay https://relay:9443/mcp
$ NODE_EXTRA_CA_CERTS="$PWD/.dev-fleet/ca-cert.pem" claude
```

No `--client-secret` (the client is public) and no `--header`. `NODE_EXTRA_CA_CERTS` is for the
Relay's CA only; the IdP is plain HTTP on loopback. Then, in Claude Code: `/mcp`, pick `relay`,
choose to authenticate. A browser opens Keycloak's sign-in page at `127.0.0.1:8180`; sign in as
`demo-user` / `dev-only-demo-user`; the page then reads "Authentication successful. You
can close this tab and return to Claude Code.", and `/mcp` shows `relay` connected.

Observed on 2026-09-29 with Claude Code 2.1.284 — driven without a person, through an isolated
config directory, its `mcp_authenticate` control request, and headless Chrome for the login:
the `401` led it to the metadata document and on to Keycloak; its authorization URL carried
`client_id=relay-demo-claude-code`, `redirect_uri=http://localhost:33418/callback`,
`resource=https://relay:9443/mcp` and no `scope`; after the login it exchanged the code at the
plain-HTTP token endpoint, and its status for `relay` became `connected`; a `list_nodes` call
it then made on that session is in the audit trail as `demo-user`, method `oauth`. After a
`make demo-reset-oauth` it dropped the dead token by itself and reported the server as needing
authentication again, and signing in again reconnected it. The command above
writes exactly the server entry that run used (also checked against an isolated config). **Not
observed:** the interactive `/mcp` menu's wording, and the browser opening by itself rather than
Claude Code printing the URL *(predicted)*.

Independent checks, as literal commands from the repo root (both observed):

```console
$ curl -sS --cacert .dev-fleet/ca-cert.pem https://relay:9443/.well-known/oauth-protected-resource
{"resource":"https://relay:9443/mcp","authorization_servers":["http://127.0.0.1:8180/realms/relay-demo"],"bearer_methods_supported":["header"],"resource_name":"Relay control plane"}
$ curl -sS -o /dev/null -D - --cacert .dev-fleet/ca-cert.pem -X POST https://relay:9443/mcp | grep -i www-authenticate
www-authenticate: Bearer resource_metadata="https://relay:9443/.well-known/oauth-protected-resource"
```

On the plain fleet the first returns `404` and the second a `401` with a bare
`WWW-Authenticate: Bearer` and no `resource_metadata` (a Relay with no issuer advertises no
flow) — both correct there, and a quick way to tell which mode is up *(predicted from the
Relay's code; the OAuth half is observed)*.

**The Console and OAuth run together.** The Console is on in both modes, exactly as
`docker-compose.demo.yml` sets it: an unauthenticated request off the Console — `/mcp` and `/api/v1`
included — gets the `401` challenge above, while a browser on `/console/` is still sent to the
Console's own sign-in, where `admin` signs in as on the plain fleet. The founding admin's,
`dev-approver`'s and `auto-incident-response`'s API Tokens work exactly as before. Observed on
2026-09-29 with the Console mounted and OAuth on: `POST /mcp` unauthenticated got the `401`
challenge above, `GET /console/` a `303` to `/console/login`, `admin` signed in; a
`demo-user` authorization-code + PKCE sign-in was accepted for `list_nodes`; Claude Code (isolated
config) went from needing authentication to `connected` through the sign-in above; and both
approval stories — the AI-agent's with responder `test_user`, and `demo-user`'s on the OAuth session —
ran their Jobs and read back as described in this section.

#### Between takes

- **`make demo-down`, then `make demo-up-oauth`**: Keycloak's database is on its own volume, so
  its signing keys and sessions survive, and a signed-in Claude Code stays signed in — the same
  access token was accepted after the round trip, and a fresh Claude Code on the same config
  came up `connected` without signing in again (observed).
- **`make demo-reset-oauth`** wipes that volume with every other: new signing keys, new sessions,
  and a new Relay CA. Restart Claude Code with `NODE_EXTRA_CA_CERTS` and authenticate again from
  `/mcp`: it discards the dead token itself and shows `relay` as needing authentication
  (observed; the menu wording is *(predicted)*).
- **Switching modes** needs `make demo-down` first: `make demo-up` refuses over a fleet brought
  up with OAuth, and `make demo-up-oauth` over one brought up without. `make demo-reset` and
  `make demo-reset-oauth` switch either way on their own. `make demo-down`, `make demo-creds` and
  `make demo-fault` work in either mode.

#### Who can impersonate whom

**Whoever administers the identity provider can impersonate any Relay Account, machine or human,
admin included.** Sign-in maps a claim to an Account *name* and checks only that the Account
exists and is enabled; it does not restrict OAuth sign-in by Account kind. ADR-0024's rule that
the Relay never creates an Account from a token stops the IdP from *minting* Accounts — it does
not stop it naming an existing one. A realm user called `founding-admin` would sign in as the
founding admin.

So this IdP has **no administrator.** The overlay sets no `KC_BOOTSTRAP_ADMIN_*`, so Keycloak's
master realm has no user, and the realm is imported from the fixture at start, which needs none.
Keycloak offers to create a first administrator only to a request arriving on its own loopback —
here the namespace it shares with the Relay, never another container and never the host (the
published port arrives from the Docker bridge gateway). Keycloak's management port (`9000`) is
not opened at all: health and metrics are off, and the healthcheck reads the realm's discovery
document instead. Observed on 2026-09-29, from `daemon-4`'s own network namespace (a curl
container joined to it, since the daemon image ships no HTTP client):

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

**The residual reach, stated plainly: any container on the fleet network — a daemon, so a
compromised Node or a Raw Exec Task — can sign in as `demo-user`.** Sharing a namespace puts
Keycloak's sign-in and token endpoints on the Relay's address, `relay:8180`, and
`demo-user`'s password is committed. Observed: from `daemon-4`'s network namespace, a
scripted authorization-code + PKCE sign-in against `relay:8180` with the committed password got a
token, and the Relay accepted it (`tools/list` → `200`). That reaches what `demo-user` can
do — role `operator` — and no further, because no one can add a realm user. Binding Keycloak to
`127.0.0.1` would close `8180` to the fleet, but to the host as well: observed on a scratch
Keycloak, a published port does not reach a listener bound to container loopback. So it is left
open, and this is why the overlay is DEV-ONLY.

#### What an OAuth session proves, and what it does not

- **It proves whose session made the call.** The Relay verified, offline against the IdP's keys,
  a token issued by this issuer for this audience, naming an existing, enabled Account — here
  `demo-user`, created human by the `init` one-shot (which also refuses to go on if
  that Account is not human, not enabled, or not `operator`). The Relay does **not** restrict
  OAuth sign-in by Account kind, so an identity-provider username equal to a machine or admin
  Account's name signs in as that Account; kind matters only later, when an answer is weighed
  (AP-79). The audit trail records the session as that Account with method `oauth` and no API
  Token id — observed for a `list_nodes` read on a token from a real authorization-code + PKCE
  sign-in: `account_name=demo-user`, `account_role=operator`, `auth_method=oauth`,
  `token_id` empty. A real token for the same user from another client of the same realm,
  carrying no Relay audience, was refused `401`; so was a real token for `no-relay-account`, the
  realm user with no Account (both observed).
- **On this fleet, a verified answer proves nothing about who decided.** `demo-user`'s
  password is committed, and the AI-agent under test can read it — and it also has a shell on the
  host, so it can script the sign-in itself, as the observation above shows any container can.
  A verified OAuth answer here demonstrates the mechanism only.
- **It does not prove a person read the question.** Anything holding `demo-user`'s token
  answers as `demo-user`, and a configured Claude Code **hook** can answer an approval
  question with nobody present — Relay cannot tell that from a person, so the verified lane can
  name a human who never saw the request ([approval.md](../specs/approval.md), the
  OAuth-session entry under accepted risks). A rule that needs evidence a person decided is an
  `out-of-band` rule.
- **The request is still the model's.** On this session `demo-user` is also the requester of
  whatever Claude Code runs: the calls are model-generated and stay agent-grade (ADR-0027). An
  answer on it meets the same refusals as any in-band decision by `demo-user`, so it never
  satisfies a rule that excludes the requester, and never an `out-of-band` rule (AP-79, AP-13).
- **The OAuth fleet runs the demo gate, exactly as the plain demo fleet does.**
  `make demo-reset-oauth` / `demo-up-oauth` set the in-band demo gate
  ([The human approver](#the-human-approver)), as the plain demo targets do. Under it
  `demo-user` — human, `operator`, and the gate has `requester_allowed: true` and no
  audience — may answer its own request for an Operation. It cannot release a Raw Exec: the
  decision floor for a Raw Exec is `admin`, and `demo-user` cannot even request one
  (observed: `raw_exec` → `Raw Exec requires role "admin", has "operator"`).

  Observed on 2026-09-29 on the wire, with a scripted client declaring `claude-code` and form
  elicitation, on a real authorization-code + PKCE token for `demo-user`:
  `run_operation service.restart unit=nginx` on `node:role=web` came back `input_required`,
  with one form question keyed by the request id and a `requestState`; the retry answering
  `accept`, with **no** responder assertion, ran the Job, 6 × `success`. Read back on the
  Control API, the request is `approved` with one decision by `demo-user`, `human: true`,
  channel `in-band`; in the store that decision has no `on_behalf_of` (AP-79: nothing written
  to the asserted lane). Answering `decline` instead, on `node:role=web, node:env=staging`,
  left the request `denied`, no Job and no dispatch. The same call declaring `claude-code` on
  the founding admin's API Token was not asked: `pending_approval` (AP-78).

  **Real Claude Code, headless** (observed, Claude Code 2.1.284, driven through its SDK control
  protocol with no model turn, since the isolated config is signed in to relay but not to a
  model): it receives the question and hands it to its host as an `elicitation` control request,
  then waits. Unanswered, the tool call hung until it was killed after 120s, leaving the
  request `pending`. Answered `cancel` — what a client with nobody present may send — the
  Relay replied `answer_refused` ("approver is required …") and left the request `pending`,
  `0 of 1`, with no decision recorded, so it can still be answered another way. A later call
  on an already-pending request of the same plan got `pending_approval` instead of being asked
  again (observed once). The interactive dialog itself, with a person at it, is *(predicted)*.

## The demo profile

A fleet-scale `demo` compose profile (#452): the same fleet as [dev-fleet.md](../dev-fleet.md), plus six more
daemons — `daemon-4..9` — for a total of nine Nodes with varied `node:` labels and a
third, strictly narrower Policy fixture. It exists for a stage demo, where three Nodes
do not read as a fleet and identical Policies produce no interesting refusal. It is
purely additive: every service the profile adds carries `profiles: ["demo"]`, so a
plain `docker compose -f docker-compose.demo.yml up` still means exactly what it means there, and nothing in
`daemon-1..3` is touched (`demo_profile_is_additive`, `daemon/tests/dev_fleet_fixtures.rs`,
enforces this).

### Start from a clean registry

Do this first, and on its own, before anything else in this section:

```console
$ make demo-build   # first time, and again after any code change
$ make demo-reset
```

One project, `relay-demo`, shared with the default fleet; the two cannot run at once. The
targets refuse a fleet another checkout owns.

`make demo-reset` = owner check → image check → `down -v` → `up -d` (`init` runs to
completion) → health wait → `make demo-creds`. It never builds — run `make demo-build` once
first (and again after any code change); a missing image is refused up front, before anything
is torn down.

Why `down -v` and not a plain `down`: `relay-data` is a **named** volume, so the
Relay's registry — and every Node in it — survives a plain `compose down`. A Node
from an earlier experiment is still in the registry, still matches Selectors, and
would make `node:role=bastion` resolve to **two** Nodes instead of one — which parks
the beat that is supposed to run straight through. `down -v` is the only thing that
clears it. The cost is real and worth stating plainly: `-v` destroys the CA and every
Node identity, so the next `up` re-enrolls the whole fleet from scratch.

`COMPOSE_PROFILES=demo make dev-fleet-up` reaches the same project but builds, and starts the
Relay on the default (out-of-band) gate; use `make demo-*`.

Stop the demo fleet with `make demo-down` (no `-v` — Node identities and the
store survive, same as `dev-fleet-down` for the default fleet), and bring it
back with `make demo-up` (also no `-v`, no build — the matching plain
restart). `demo-up` is **not** "no credential mint": `init` has
`restart: no`, but a stopped one-shot container is started again by `up` just
like any other service, which re-runs its entrypoint and mints fresh values
into the (persisted) volume — it just does not copy them out to
`.dev-fleet/`; run `make demo-creds` after `demo-up` for that (see
[The fault, and resetting between takes](#the-fault-and-resetting-between-takes)
for what `demo-creds` does and does not do). There is no `down` you need to
remember to run before `make demo-reset`: it wipes first. `make demo-up` brings back all nine
daemons every time precisely because the fixed project and profile are baked into the
Makefile rather than typed at the command line.

**Cleanup — stop it and leave it down.** `make demo-reset` also wipes `relay-demo`, but
brings the fleet straight back up; it is the between-takes reset, not a cleanup. To stop
the demo fleet and wipe its volumes, run `docker compose -p relay-demo` with both of its files
and `--profile demo down -v` directly, from the checkout root. Name both files: the repository root has no
`docker-compose.yml`, so without `-f` Compose finds none (or a parent directory's); the OAuth overlay is named so that an IdP left from an `--oauth` run goes too,
as `make demo-down` does:

```console
$ docker compose -p relay-demo -f docker-compose.demo.yml -f docker-compose.oauth.yml \
    --profile demo down -v
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
(`daemon/crates/relay-policy/src/lib.rs`'s `policy_fingerprint`), computable locally with
`sha256sum docker/fixtures/policy.{web,db,bastion}.toml` and not reproduced here
because it changes on any edit to the file, including a comment.

### What varies, and what cannot

`node:` labels vary as the table above shows. Of the Facts a Node reports
(relay-ops `operations::system_facts`), only `hostname` and `ip_addresses` can
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
in-band demo gate, a client named `gleipnir` on an API Token (then a shared `gleipnir` machine
Account; now the AI-agent's own, `auto-incident-response`) was asked the approval question
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

then re-issue the same call unchanged (with `wait_seconds`, or poll `get_job` until
`job_status` is `complete`) → **6 × `success, exit_code: 0`** *(predicted)*
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
splicing it into the recipe text, and the recipe splits it on whitespace, with
globbing off, and validates every token against the Makefile's fixed list of
`role=web` services before any
`exec` into a container, so a value carrying a shell metacharacter is
refused, not executed.
Every target must be a `role=web` Node — anything else is refused before any
`exec` into a container, since faulting a Node that runs no demo service
would report a condition that was never there. The kill is idempotent: running it again on an
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
*(predicted)*. `svc.status` and `svc.restart` from the demo Template pack are the typed
read/mutate pair for the same beat, dispatchable by name since ADR-0042 (#626).

**Independent verification.** `file.read` of
`/var/lib/dev-fleet-service/state` on the repaired Node shows a new `pid` and
`started_epoch` (see [The real service](../dev-fleet.md#the-real-service)), and re-running
the `/proc/net/tcp` discovery read shows the `0100007F:1F90 ... 0A` row is
back.

**`make demo-reset`** is the reliable way back to the starting state between
takes — fault cleared, Jobs/approvals/audit/registry cleared (the store lives
on `relay-data`, wiped by `down -v`), the CA and every credential fresh, and
every Node healthy — and, unlike a bare `docker compose -f docker-compose.demo.yml --profile demo down -v`
/ `up`, it never builds (a missing image is refused up front — run
`make demo-build` once, first) and it verifies rather than assumes:

1. The ownership check: no `relay-demo` container may belong to another checkout.
2. Every image `docker compose config --images` names must already exist,
   checked before anything is torn down.
3. `down -v --remove-orphans`.
4. `up -d --no-build --pull never`: `init` runs to completion (it mints the credentials and
   the Enrollment Token), and the daemons start only once it has exited `0`.
5. Waits (`--wait`) until `relay` and every daemon are healthy.
6. `scripts/dev-fleet-mcp.sh init` **copies** the freshly minted credentials out to
   `.dev-fleet/` (a `docker compose cp` read out of the exited `init` container, nothing more).

**The CA is regenerated on every reset, so a registered MCP client is left
holding a stale bearer token and a stale CA it can no longer verify against**
(`NODE_EXTRA_CA_CERTS` is read only at process start). `.dev-fleet/` is
already current — step 6 above just refreshed it — so the fix is only to
restart the client: `claude mcp remove relay` / `claude mcp add ...` as in
[Connecting Claude Code](../dev-fleet.md#connecting-claude-code). `make demo-reset`'s
closing summary says this every time. `make demo-creds` is only needed after `demo-up`: unlike
`demo-reset`, `demo-up` does not copy anything out on its own, even though its
`up` (see [Survive `down` / `up`](../dev-fleet.md#survive-down--up)) causes the same
`init` to re-mint into the volume. `demo-creds` itself mints nothing — it
is a pure copy, safe to run any number of times.

**The refusal.** The targets refuse a `relay-demo` fleet started from another checkout
(compared by physical path), and refuse an `up` in the other OAuth mode. They also refuse a
non-local engine (`DOCKER_HOST` or the docker context), before any `docker compose` call.

**Verification honesty.** The `/proc/net/tcp` discovery signal is *(predicted)*
from `web_policy_allows_reading_the_socket_table`
(`daemon/tests/dev_fleet_fixtures.rs`) — the daemon's own Policy engine agrees
the read is allowed, but no automated test here starts a real `busybox httpd`
or reads its real socket table. "Reset survives back to back, repeatedly" has
**not been observed live at all** — the Makefile recipes have been checked statically
(`docker compose config`, `make -n`, and `make test-dev-fleet-make`, which runs the
guards and `demo-fault` against a stub docker); a real `down -v` / `up` / fault cycle
has not been run since #893. Run the fault → discover → repair →
verify sequence, and `make demo-reset` two or three times back to back,
before presenting, and correct this paragraph with what you actually saw.

### Resource usage

**PENDING MEASUREMENT (#452, AC 4).** No number below has been measured — there is no
Docker daemon available in this repository's build environment, only the `docker`
binary — and none should be invented or assumed. Whoever next has a machine with
Docker Engine + Compose v2 should run the procedure below and fill this table in the
same change that adjusts the roster, if adjustment turns out to be needed.

**Procedure:**

1. `docker compose -f docker-compose.demo.yml down -v`, then `docker compose -f docker-compose.demo.yml --profile demo up --build -d`;
   wait until `docker compose -f docker-compose.demo.yml ps` shows all nine daemons `healthy`; let it settle 60s.
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
