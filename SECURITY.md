# Security policy

Relay is remote code execution as a service by design: the Relay dispatches administrative
Operations to relay-daemons on Nodes. Vulnerability reports are the highest-priority work in
this repository.

## Supported versions

Relay is alpha. Only `main` is supported; fixes land on `main` and ship in the next
release. [docs/operations/release-artifacts.md](docs/operations/release-artifacts.md) describes
what a release is.

## Reporting a vulnerability

Report privately through GitHub private vulnerability reporting:
<https://github.com/Felag-Engineering/relay/security/advisories/new> (or the repository's
Security tab, then "Report a vulnerability"). This is the only channel. Do not open a public
issue, discussion or pull request for a suspected vulnerability.

A useful report contains:

- the affected component: the Relay, the relay-daemon, or a packaged unit;
- the version or commit (`relay --version` / `relay-daemon --version`);
- steps to reproduce, and the impact;
- the architecture invariant (numbered, in [AGENTS.md](AGENTS.md)) or trust boundary it
  breaks, if you know.

Please do not include live credentials, private keys, or Enrollment Tokens.

## What to expect

We aim to acknowledge a report within 5 business days and give an initial assessment after
triage. The report is worked in a draft GitHub Security Advisory with the reporter as a
collaborator. The fix is developed in the advisory's private fork and merged to `main`, and
released, when the advisory is published. The reporter is credited unless they decline. Please
hold public disclosure until then.

## Scope

In scope:

- the `relay` binary (the Relay) and the `relay-daemon` binary;
- the packaged units: the Relay's systemd unit and example `relay.toml`
  ([relay/packaging/](relay/packaging/)), and the relay-daemon's systemd unit, example
  EnvironmentFile and shipped Template catalog ([daemon/packaging/](daemon/packaging/)).

Out of scope:

- the demo fleet (`docker-compose.demo.yml`, `docker-compose.oauth.yml`, `docker/` and its
  fixtures, `make dev-fleet-up`, `make demo-up`, `make demo-up-oauth`): a local development
  fixture with dev-only credentials, not a deployment;
- vulnerabilities in third-party dependencies with no demonstrated path through Relay; report
  those upstream.

## Threat model

[docs/security/threat-model.md](docs/security/threat-model.md) maps the trust boundaries, the
adversaries, and which invariant defends each. A report showing one of the fourteen
architecture invariants in [AGENTS.md](AGENTS.md) failing is in scope. A gap already in the
[Known gaps](AGENTS.md#known-gaps-between-these-invariants-and-the-code) table is tracked;
cite its issue rather than reporting it again.
