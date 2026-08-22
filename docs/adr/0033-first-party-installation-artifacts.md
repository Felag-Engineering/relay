# First-party installation artifacts

"As automated as possible" pulls hard toward `curl -sfL https://get.relay.sh | sh`. It is
what k3s does, what Docker does, what almost everything does, and it is the single
fastest path from a bare host to a running service.

It is also the exact thing this product argues against. Every install document here makes
verify-then-install a principle with the digest check happening *before* the binary is
executed (`release-artifacts.md`, `relay-install.md:18-29`,
`relay-daemon-install.md:24-34`), and the pitch is architectural distrust of the operator.
A pipe-to-shell onboarding contradicts the thesis at the first touchpoint a customer ever
sees, and it does so in the one product category where the contradiction is the story.

## Decision

**1. No `curl | sh`. The installer ships inside the release, beside `SHA256SUMS`.**

The sequence stays download → verify → run. This costs the operator two lines and buys the
property the product is sold on. The installer is an artifact under the same verification
contract as the binaries, not an out-of-band script fetched from a URL that could serve
anything to anyone.

**2. `relay-install.sh` covers the Relay host**: service account, binary, hardened unit
from `relay/packaging/`, `/etc/relay/relay.env`, then `relay init` (ADR-0030). It prints
the CA fingerprint — one number, per ADR-0031 — the Console URL, the admin token, the join
string, and the enrollment playbook.

**3. The daemon gets OS packages before the Relay does.**

This inverts the intuitive order and is the highest-leverage choice here. The Relay is one
host, touched once — a script is sufficient forever. The daemon is every host in the
fleet, and one package collapses four per-Node steps (binary, unit, directories, Policy)
into one artifact on every one of them. If only one OS package is ever built, it is the
daemon's.

Note what this is *not*, until decision 6 changes: with no hosted repository it is
`download → verify → dpkg -i`, not `apt install`. The collapse is four steps into one
**artifact**, not into one **command**. That is a smaller win than the repository version
and still the largest available one, because the artifact is what config management
handles and the extra command is a line in a role either way.

**4. The daemon package installs `policy.default.toml` to `/etc/relay-daemon/policy.toml`
as a conffile** (`dpkg` conffile / rpm `%config(noreplace)`).

This closes the cold-start hole where a Node enrolls, connects, heartbeats, reports
healthy, and denies every Task because no Policy file exists. The Node now comes up
read-only per ADR-0022, which is the intended "eyes before hands" posture instead of an
accident.

The `noreplace` half is not packaging hygiene, it is a security requirement: **an upgrade
that silently restored the shipped default over an operator's edited Policy would be a
security incident**, and it would be one that surfaces as a fleet-wide permission change
nobody authored. It follows that changing the shipped default in a later release never
reaches an existing Node. That is correct — Policy is the customer's (ADR-0002) — and is
recorded here so nobody later "fixes" it.

Nothing about the daemon's own semantics changes: a missing or unreadable Policy is still
deny-all, and a group- or world-writable one is still refused. This decides what the
*package places*, never what the *daemon does*.

**5. The container image is the evaluation artifact, not the recommended production
deployment.** The Relay containerizes cleanly — it is unprivileged by design
(`relay/packaging/README.md:10-25`) — but the CA key and the store want durable volumes
with real permissions, and the hardened unit expresses a posture a compose file does not.
It is the fastest path to a fleet on a laptop and should say so.

There is no daemon image, ever: a containerized daemon has no host to administer.

**6. No hosted package repository before v1.0.0.** Packages are release attachments
verified by digest, exactly like the binaries, and the non-hosted install path is
supported rather than tolerated — it is the only path there is until 1.0, so it gets first-
class documentation and testing.

Running a repository is a standing distribution commitment with its own signing keys,
custody, and availability expectations. It is a 1.0 promise, not a beta convenience, and
committing to it early would mean operating one through every pre-1.0 breaking change.
Operators pin digests in config management either way, so this is consistent with how the
binaries already ship rather than a regression from it.

## Consequences

Four artifacts per release instead of two: `relay`, `relay-daemon`, `relay-install.sh`,
and the daemon packages — all under one `SHA256SUMS`. The release pipeline grows; the
verification contract does not change.

The evaluation path and the production path are now genuinely different artifacts, and
the docs must not blur them. An evaluator running the container and an operator running
the `.deb` under the hardened unit are doing different things on purpose.

`relay-install.sh` becomes a thing that can drift from `relay/packaging/` — the unit file
and the env sample it installs. The existing drift gates
(`relay/cmd/relay/packaging_drift_test.go`, `daemon/tests/packaging_drift.rs`) exist
because exactly that drift already happened once and went unnoticed for several
milestones. Whatever the installer installs belongs under the same kind of gate.
