# Operations

Operator-facing runbooks: installing, enrolling, upgrading and recovering a Relay fleet. The
local development fleet is a separate document, [docs/dev-fleet.md](../dev-fleet.md).

## Installing

- **[relay-install.md](relay-install.md)** — installing and running the Relay from its OS package: verify-then-install, the generated `relay.toml`, `relay init`, upgrade and purge, and the Docker Compose path.
- **[relay-daemon-install.md](relay-daemon-install.md)** — installing the relay-daemon package on a Node: verify, install, the environment file, `relay-daemon join`, the shipped unit, upgrade and removal.
- **[release-artifacts.md](release-artifacts.md)** — release artifact naming, pinning, and verify-then-install.
- **[version-stamping.md](version-stamping.md)** — what a build reports for `--version`, and how the daemon's version feeds the ADR-0014 `min-daemon-version` gate.
- **[daemon-privilege-posture.md](daemon-privilege-posture.md)** — the hardened `systemd` unit and per-Operation privilege map for running relay-daemon in production.

## Joining Nodes and shaping what they run

- **[enrollment.md](enrollment.md)** — joining Nodes to the fleet: `sudo relay-daemon join`, Enrollment Tokens and their initial tags, one Node and a fleet, through the release's Ansible role or an SSH loop.
- **[policy-as-code.md](policy-as-code.md)** — Policy files in the IaC repo: `policy check` in CI, config-management distribution, fingerprint-verified rollout.
- **[template-packs.md](template-packs.md)** — Template Operations: authoring typed parameter slots, the template-pack convention, fingerprint-verified rollout, and the `unsupported` outcome.
- **[iac-upgrades.md](iac-upgrades.md)** — daemon upgrades through config management, installing the newer packages, observed by the `min-daemon-version` gate (ADR-0014).

## Credentials, approval and audit

- **[control-plane-credential.md](control-plane-credential.md)** — the API Token a control-plane caller presents, and why Relay configuration grants none.
- **[approval-gates.md](approval-gates.md)** — which dispatches wait for a human before they run, and where that is configured (ADR-0027).
- **[audit-output-retention.md](audit-output-retention.md)** — what the audit trail keeps of a Task's output: full for `mutate`, metadata-only for `read`.
- **[audit-chain.md](audit-chain.md)** — the hash-chained audit trail and `relay-audit-verify`: what the chain proves, what it does not, and how to check it.

## Recovery and validation

- **[ca-disaster-recovery.md](ca-disaster-recovery.md)** — CA key custody, backups, and the "burn it down" compromise runbook.
- **[beta-hardware-validation.md](beta-hardware-validation.md)** — the one validation that cannot be automated: proving a release on real machines.
- **[demo-fleet.md](demo-fleet.md)** — the nine-Node demo fleet (`deploy/demo`) as a presenter runbook: roster, beats, fault injection, reset.
