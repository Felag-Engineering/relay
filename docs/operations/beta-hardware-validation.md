# Real-hardware validation — `v0.1.0-beta` (Vertical Slice)

The runbook for proving the vertical slice **on real machines**. It is the one validation
this project cannot automate, which is why it survived the retirement of the per-milestone
manual scripts: everything else those scripts covered is discharged by `make verify`,
`make test-integration`, `make test-crossbinary` and the dev fleet, and by the proof tables in
[`docs/specs/`](../specs/). Real service managers, real package managers, real file ownership
and real network paths are not.

**Prerequisites:** the automated gates pass on the commit under test, the dev fleet comes up
(`docs/dev-fleet.md`), and a `v0.1.0-beta` release is published.

This milestone's acceptance is deliberately about **real machines**: *"Stand up a
Relay, enroll ≥3 Nodes via a reusable token, drive a Selector-targeted Operation from
an MCP client, and read the audit trail — on real machines"*, and *"documented,
repeatable setup from a clean environment"*. This script therefore doubles as the
runbook the owner executes on real hardware. Everything in it is
**real-infrastructure-only** unless marked otherwise — none of it is discharged by a
laptop run.

### What you need

- **A published `v0.1.0-beta` GitHub Release** (`relay-…-x86_64-unknown-linux-gnu`,
  `relay-daemon-…-x86_64-unknown-linux-musl`, `SHA256SUMS` — see
  [docs/operations/release-artifacts.md](../operations/release-artifacts.md)).
- **1 Relay host + ≥3 Nodes**: real (physical or cloud) x86_64 Linux machines, network
  paths from every Node to the Relay's node-plane port, and from the operator
  workstation to the control-plane port. Fresh machines — "clean environment" is part
  of the acceptance.
- **Config management** the operator actually uses (Ansible or equivalent, over SSH):
  bulk enrollment and Policy distribution must flow through it, not through hand-run
  shells on each Node (ADR-0002/0014).
- **A real MCP client** (e.g. Claude Code or another off-the-shelf MCP harness) on the
  operator workstation — this milestone's acceptance names an MCP *client*, not raw
  `curl`.
- **This milestone's docs deliverables**, which do not exist yet at the time this
  script was written and are written *as part of* v0.1.0-beta: the install/run docs
  for daemon and Relay, the example Policy file + enrollment workflow (incl. bulk
  enrollment), the IaC upgrade workflow, the policy-as-code workflow doc, the CA &
  disaster-posture doc, and the `LICENSE` (BSL). Steps below reference them; if a
  referenced doc is missing, the step **fails** — the docs are acceptance-bearing.

Record hostnames/IPs, the release version, and the config-management repo commit in the
sign-off table.

---

## 1. Install the Relay from published artifacts (Relay host)

On the Relay host, follow the verify-then-install sequence of
[release-artifacts.md](release-artifacts.md) for the **relay** binary (glibc build) — the
same verify-then-install sequence [relay-install.md](relay-install.md) documents:

```sh
VERSION="0.1.0-beta"
ARTIFACT="relay-${VERSION}-x86_64-unknown-linux-gnu"
BASE="https://github.com/Felag-Engineering/relay/releases/download/v${VERSION}"
curl -fsSLO "${BASE}/${ARTIFACT}" && curl -fsSLO "${BASE}/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS
sudo install -m 0755 "${ARTIFACT}" /usr/local/bin/relay
relay --version
```

Then stand the Relay up **by following the v0.1.0-beta install/run docs only** (not
this script, not memory): the founding admin's API Token minted with
`relay bootstrap-token -store-path <path>` (there is no credential-hash file since
ADR-0023), `-control-enabled`, separate node-plane/control-plane listeners, `-hostname`
set to the DNS name the Nodes and the workstation will dial (the server-cert SAN),
production-shaped blast caps, and `-min-daemon-version ${VERSION}` — the release is
exact, so the gate is truthful (the `-0.dev` numeric marker sorts dev builds below it).

**Expect:** `relay --version` reports exactly `0.1.0-beta`; startup log shows both
listeners; `/api/v1/ping` answers with the credential and `401`s without, from the
**workstation** (i.e. across the real network, against the Relay's CA cert).

**Discharges:** v0.1.0-beta "stand up a Relay … on real machines"; v0.0.9 #254 carried
onto real hardware (ADR-0007/0014).

## 2. Policy-as-code: author, lint, distribute via config management

In the operator's IaC repo (not on the Nodes): commit the Node Policy file (start from
the documented example Policy), lint it in the pipeline with the **daemon binary's**
offline checker, then distribute it with config management as a root-owned `0600` file
at `/etc/relay-daemon/policy.toml` on every Node:

```sh
relay-daemon policy check policy.toml            # exit 0 gates the pipeline
relay-daemon policy check policy.toml --would-allow operation file.read path=/etc/shadow
# then: ansible-playbook … (or equivalent) to place the file on all Nodes
```

**Expect:** lint passes in the pipeline; the file lands root-owned and
non-group/world-writable on every Node; **at no point does Policy travel over the
Relay's wire** (ADR-0002, invariant 2). After step 4, every Node's
`policy_fingerprint` in the registry is identical — string-compare against the locally
computed one to confirm the rollout landed everywhere.

**Discharges:** v0.1.0-beta "Policy-as-code workflow documented" (validated by
following it); ADR-0002/0011.

## 3. Bulk enrollment via config management (≥3 Nodes)

Mint **one** reusable, scoped Enrollment Token over `/api/v1` (see
[enrollment.md](enrollment.md) — `relay:`-scoped, TTL-bounded; e.g. `{"scope":["relay:env=beta","relay:fleet=metal"],
"ttl_seconds":86400,"max_uses":0}`). Then, following the documented bulk-enrollment
workflow, have config management:

1. verify-then-install the **daemon** artifact on every Node
   ([relay-daemon-install.md](relay-daemon-install.md), musl build, digest checked before
   install);
2. place the Relay's **public** CA cert and the daemon's environment
   (`RELAY_ADDR`, `RELAY_ENROLLMENT_TOKEN`, `RELAY_CA_BUNDLE_PATH`,
   `RELAY_STATE_DIR`, `RELAY_POLICY_PATH`, `RELAY_NODE_LABELS` — per-Node values, e.g.
   `role=web` / `role=db` / `role=cache`) via the packaged systemd unit
   (`daemon/packaging/relay-daemon.service`,
   [daemon-privilege-posture.md](../operations/daemon-privilege-posture.md));
3. start/enable the service on all ≥3 Nodes in one playbook run — **no manual step on
   any Node**.

**Expect:** all Nodes enroll with the **same** token, appear in the registry with the
token's `relay:` labels stamped and their own `node:` labels, correct Facts, live
`last_seen`, `outdated: false` (their stamped version equals the gate), and the
identical Policy fingerprint from step 2. The Enrollment Token plaintext exists only in
the CM vault; it never appears in the Relay's logs or audit.

**Discharges:** v0.1.0-beta "enroll ≥3 Nodes via a reusable token", "example enrollment
workflow (incl. bulk enrollment via config management)" (ADR-0006).

## 4. Selector-targeted Operation from a real MCP client

Configure the real MCP client on the workstation against
`https://<relay-host>:9443/mcp` (bearer credential; trust the Relay's CA cert). From
the client, in order:

1. `list_nodes` — all ≥3 Nodes, labels in separate `node:`/`relay:` maps;
2. `describe_node` on one Node — the effective Policy mirror;
3. `list_operations` — the vocabulary with risk classes;
4. `run_operation(selector="node:role=web", operation="system.facts")` — hits **only**
   the matching subset (the call returns `job_id` at persist; pass `wait_seconds`, or poll
   `get_job` until `job_status` is `complete`, to see the per-Node results);
5. `run_operation(selector="relay:env=beta", operation="system.facts")` — fans out to
   all ≥3 with per-Node results (again with `wait_seconds`, or by polling `get_job`);
6. the same as (5) with `plan=true` first, verdicts matching the completed outcomes of the
   subsequent real run;
7. one deliberate Policy denial (e.g. `service.restart` of a non-allowed unit) —
   `denied_by_policy` with the rule, per Node.

**Expect:** per-Node results and verdicts matching what
[`docs/specs/execution.md`](../specs/execution.md) and
[`docs/specs/policy-preflight.md`](../specs/policy-preflight.md) describe, now across real machines and a
real client. This step is also the vocabulary-legibility
spot check (ADR-0001/0003): the client should be able to choose Operations and
arguments from the tool descriptions alone, without trial-and-error.

**Discharges:** v0.1.0-beta "drive a Selector-targeted Operation from an MCP client";
ADR-0003.

## 5. Audit read-back

On the Relay host: the `audit decision` log lines for everything step 4 did, attributed to the control-plane principal; and (marked store-read — still
no dedicated audit read surface) the durable rows in the Relay's store, including the
per-Node dispatch rows across all ≥3 Nodes.

**Expect:** the full "who did what to which Node" trail of step 4, ordered and
attributed.

**Discharges:** v0.1.0-beta "…and read the audit trail — on real machines" (ADR-0004).

## 6. IaC upgrade workflow (version pin change)

Following the documented IaC upgrade workflow: bump the pinned daemon version in config
management (when only one release exists, a rehearsal of the same pin is acceptable —
document which), roll it out, and confirm the fleet converges: registry shows the new
self-reported version on every Node; with `-min-daemon-version` at the new pin, a
deliberately held-back Node shows `outdated: true` and is refused per-Task
(`version_refused`) until upgraded.

**Expect:** upgrades flow **only** through config management — the Relay never pushes
a binary; its only lever is the dispatch gate (invariant 14, ADR-0014).

**Discharges:** v0.1.0-beta "IaC upgrade workflow consuming the CD artifacts".

## 7. CA & disaster posture (documented; drill optional/destructive)

Verify the CA posture doc against the running Relay host: CA key location, root-only
permissions, backup procedure. **Optional destructive drill** (end of validation, or on
a scratch fleet): simulate CA loss — stand up a fresh CA, and recover by re-running the
enrollment playbook (step 3) against it; the fleet re-enrolls and is drivable again.

**Discharges:** v0.1.0-beta "CA & disaster posture documented" ("burn it down" recovery
is re-running the enrollment playbook against a fresh CA).

## 8. Docs-followability sign-off ("documented well enough for a stranger")

A person who has **not** worked on Relay executes steps 1–5 from a clean environment
using **only** the published docs (install/run docs, example Policy, enrollment
workflow) — no help from this script's authors beyond pointing at the docs. Every
place they got stuck or improvised is a docs bug: file it, fix it, and re-run the
affected step. Also confirm the release deliverables are present: `LICENSE` (BSL, with
its parameters set) is in the tagged release.

**Expect:** a stranger reaches "≥3 Nodes enrolled, Selector-targeted Operation run from
an MCP client, audit read back" without insider knowledge.

**Discharges:** v0.1.0-beta "documented, repeatable setup from a clean environment";
the LICENSE deliverable.

---

## Sign-off

| Field | Value |
|---|---|
| Date | |
| Release validated (`relay --version` / `relay-daemon --version`) | |
| Relay host / Node hostnames (≥3) | |
| Config-management repo + commit | |
| MCP client used | |
| Automated gates green on commit | |
| Steps passed | |
| Steps skipped (and why) | |
| Docs-followability run by (the "stranger") | |
| Operator | |
