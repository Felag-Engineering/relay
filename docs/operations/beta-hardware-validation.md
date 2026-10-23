# Real-hardware validation

The runbook for proving a release **on real machines**. It is the one validation this
project cannot automate: `make verify`, `make test-integration`, `make test-crossbinary`, the
dev fleet and the proof tables in [`docs/specs/`](../specs/) cover the rest, but not real
service managers, package managers, file ownership and network paths.

**Prerequisites:** the automated gates pass on the commit under test, the dev fleet comes up
(`docs/dev-fleet.md`), and the release under test is published. No run is recorded yet; the
first is for the first release, 0.1.0.

What it proves is about **real machines**: stand up a Relay, join ≥3 Nodes with one Enrollment
Token, drive a Selector-targeted Operation from an MCP client, and read the audit trail, from a
clean environment, following only the published docs. The owner executes this runbook on real
hardware. Every step is **real-infrastructure-only**
unless marked otherwise; a laptop run discharges none of it.

### What you need

- **A published GitHub Release** of the version under test (the Relay and relay-daemon
  artifacts and packages, `SHA256SUMS`; see [release-artifacts.md](release-artifacts.md)).
- **1 Relay host + ≥3 Nodes**: real (physical or cloud) x86_64 Linux machines, with network
  paths from every Node to the Relay's node-plane port and from the operator workstation to the
  control-plane port. Fresh machines: "clean environment" is part of the acceptance.
- **Config management** the operator actually uses (Ansible or equivalent, over SSH). Bulk
  joining and Policy distribution must flow through it, or through an SSH loop from the
  operator's machine, not through hand-run shells on each Node (ADR-0002, ADR-0014,
  ADR-0048).
- **A real MCP client** (e.g. Claude Code or another off-the-shelf MCP harness) on the
  operator workstation. The acceptance names an MCP *client*, not raw `curl`.
- **The published docs** the steps reference: the daemon and Relay install docs, the example
  Policy file and the joining workflow (one Node and a fleet), the IaC upgrade workflow, the
  policy-as-code workflow, the CA and disaster-posture doc, and the `LICENSE` (BSL). The docs
  are acceptance-bearing: if a referenced doc is missing, the step **fails**.

Record hostnames/IPs, the release version, and the config-management repo commit in the
sign-off table.

---

## 1. Install the Relay from published artifacts (Relay host)

On the Relay host, install the Relay from the published release with the verify-then-install
sequence of [release-artifacts.md](release-artifacts.md), as
[relay-install.md](relay-install.md) documents, and check `relay --version`.

Then stand the Relay up **by following the install docs only** (not this runbook, not memory).
In `relay.toml`: `control_plane.enabled = true`, separate node-plane and control-plane
listeners, `tls.hostname` set to the DNS name the Nodes and the workstation will dial (the
server-cert SAN), production-shaped blast caps, and `reach.min_daemon_version` set to
the version under test. The release is exact, so the gate is truthful (the `-0.dev` marker sorts dev
builds below it). Once the Relay has started, create the first admin and its API Token with
`sudo -u relay relay init --admin <name>`.

**Expect:** `relay --version` reports exactly the version under test; the startup log shows both
listeners; `/api/v1/ping` answers with the credential and `401`s without it, from the
**workstation** (across the real network, against the Relay's CA cert).

**Proves:** a Relay stands up on real machines from published artifacts (ADR-0007,
ADR-0014).

## 2. Policy-as-code: author, lint, distribute via config management

In the operator's IaC repo (not on the Nodes): commit the Node Policy file (start from the
documented example), lint it in the pipeline with the **daemon binary's** offline checker,
then distribute it with config management as a root-owned `0600` file at
`/etc/relay-daemon/policy.toml` on every Node:

```sh
relay-daemon policy check policy.toml            # exit 0 gates the pipeline
relay-daemon policy check policy.toml --would-allow operation file.read path=/etc/shadow
# then: ansible-playbook … (or equivalent) to place the file on all Nodes
```

**Expect:** lint passes in the pipeline; the file lands root-owned and not group/world-writable
on every Node; **Policy never travels over the Relay's wire** (ADR-0002, invariant 2). After
step 4, every Node's `policy_fingerprint` in the registry is identical; string-compare it with
the locally computed one to confirm the rollout landed everywhere.

**Proves:** the Policy-as-code workflow is documented well enough to follow (ADR-0002,
ADR-0011).

## 3. Join ≥3 Nodes with one Enrollment Token

Mint **one** Enrollment Token for the number of Nodes you are joining, naming an initial tag
such as `tag:env=beta` ([enrollment.md](enrollment.md); ADR-0048, ADR-0050). Then, following
the documented joining workflow:

1. verify-then-install the **relay-daemon** package on every Node
   ([relay-daemon-install.md](relay-daemon-install.md)), with per-Node `node:` labels in its
   environment file (e.g. `role=web` / `role=db` / `role=cache`) and the packaged systemd unit
   ([daemon-privilege-posture.md](daemon-privilege-posture.md));
2. join every Node with `sudo relay-daemon join`, the join string fed from the operator's side:
   an SSH loop piping it from the operator's machine, or the Ansible role the release ships
   passing it from the vault on standard input. The join string is never written to a Node's
   disk, environment file or command line (ADR-0048);
3. do it for all ≥3 Nodes in one run, with **no manual step on any Node**.

**Expect:** all Nodes join with the **same** token and appear in the registry with
`relay:node-id`, the token's initial tags and their own `node:` labels, correct Facts, live
`last_seen`, `outdated: false` (their stamped version equals the gate), and the identical
Policy fingerprint from step 2. The join string exists only on the operator's side; it never
appears in the Relay's logs or audit, or in a file on any Node.

**Proves:** a fleet joins with one token through the documented workflow (ADR-0006,
ADR-0048).

## 4. Selector-targeted Operation from a real MCP client

Configure the MCP client on the workstation against `https://<relay-host>:9443/mcp` (bearer
credential; trust the Relay's CA cert). From the client, in order:

1. `list_nodes` — all ≥3 Nodes, labels in separate maps per namespace;
2. `describe_node` on one Node — the effective Policy mirror;
3. `list_operations` — the vocabulary with risk classes;
4. `run_operation(selector="node:role=web", operation="system.facts")` — hits **only** the
   matching subset (the call returns `job_id` at persist; pass `wait_seconds`, or poll
   `get_job` until `job_status` is `complete`, to see the per-Node results);
5. `run_operation(selector="tag:env=beta", operation="system.facts")` — fans out to all ≥3
   with per-Node results (again with `wait_seconds`, or by polling `get_job`);
6. the same as (5) with `plan=true` first, verdicts matching the completed outcomes of the
   subsequent real run;
7. one deliberate Policy denial (e.g. `service.restart` of a non-allowed unit) —
   `denied_by_policy` with the rule, per Node.

**Expect:** per-Node results and verdicts matching
[`docs/specs/execution.md`](../specs/execution.md) and
[`docs/specs/policy-preflight.md`](../specs/policy-preflight.md), across real machines and a
real client. This is also the vocabulary-legibility spot check (ADR-0001/0003): the client
should choose Operations and arguments from the tool descriptions alone, without
trial-and-error.

**Proves:** a Selector-targeted Operation runs from a real MCP client (ADR-0003).

## 5. Audit read-back

On the Relay host: the `audit decision` log lines for everything step 4 did, attributed to the
control-plane principal; and (marked store-read: there is no dedicated audit read surface) the
durable rows in the Relay's store, including the per-Node dispatch rows across all ≥3 Nodes.

**Expect:** the full "who did what to which Node" trail of step 4, ordered and attributed.

**Proves:** the audit trail reads back on real machines (ADR-0004).

## 6. IaC upgrade workflow (version pin change)

Following the documented IaC upgrade workflow, bump the pinned daemon version in config
management (when only one release exists, a rehearsal of the same pin is acceptable; record
which), roll it out, and confirm the fleet converges: the registry shows the new self-reported
version on every Node, and with `reach.min_daemon_version` at the new pin, a deliberately
held-back Node shows `outdated: true` and is refused per Task (`version_refused`) until
upgraded.

**Expect:** upgrades flow **only** through config management. The Relay never pushes a binary;
its only lever is the dispatch gate (invariant 14, ADR-0014).

**Proves:** the IaC upgrade workflow consumes the release artifacts.

## 7. CA & disaster posture (documented; drill optional/destructive)

Check the CA posture doc against the running Relay host: CA key location, root-only
permissions, backup procedure. **Optional destructive drill** (at the end of validation, or on
a scratch fleet): simulate CA loss by standing up a fresh CA, and recover by re-running the
joining workflow (step 3) against it; the fleet re-joins and is drivable again.

**Proves:** the CA and disaster posture is documented ("burn it down" recovery is re-running
the joining workflow against a fresh CA).

## 8. Docs-followability sign-off ("documented well enough for a stranger")

A person who has **not** worked on Relay executes steps 1–5 from a clean environment using
**only** the published docs (install/run docs, example Policy, joining workflow), with no
help beyond being pointed at the docs. Every place they got stuck or improvised is a docs bug:
file it, fix it, and re-run the affected step. Also confirm `LICENSE` (BSL, with its parameters
set) is in the tagged release.

**Expect:** a stranger reaches "≥3 Nodes joined, Selector-targeted Operation run from an MCP
client, audit read back" without insider knowledge.

**Proves:** a documented, repeatable setup from a clean environment, and the LICENSE.

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
