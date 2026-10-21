# Contributing

**Relay is source-available, not open source, and does not accept code contributions from
outside Felag Engineering.** A pull request from outside is closed unmerged, however good the
change. The code is published under the Business Source License 1.1 ([LICENSE](LICENSE)) so it
can be read, audited and run under that license's terms. Selling commercial licenses depends on
Felag holding the rights to every line.

From outside, these are welcome:

- **Bug reports and feature requests** as GitHub issues.
- **Security reports** through [SECURITY.md](SECURITY.md), never an issue.

The rest of this file is for Felag Engineering's own contributors.

Read [AGENTS.md](AGENTS.md) first (the architecture invariants and conventions) and
[GLOSSARY.md](GLOSSARY.md), whose language is enforced in review.

## Build and verify

- A checkout cloned as `gleipnir-relay` works through GitHub's redirect; repoint it with
  `git remote set-url origin git@github.com:Felag-Engineering/relay.git` (or the HTTPS URL).
- Toolchains: Go at the version `relay/go.mod` names (the `Makefile` pins it), and stable Rust
  at or above `rust-version` in `daemon/Cargo.toml`. `make lint` and `make verify` also lint
  and build the daemon for musl, which needs the Rust target and a musl C compiler (`ring`
  builds C): `rustup target add x86_64-unknown-linux-musl` and, on Debian or Ubuntu,
  `sudo apt-get install musl-tools`. Without them both targets stop at `lint-daemon`.
- `make tools` (optional) pre-builds the pinned Go tools; any target builds them on first use.
- `make build test lint` is the inner loop.
- **`make verify` before opening a PR.** It mirrors CI gate for gate. A skipped gate (for
  example `zizmor` or `cargo-deny` absent) is not a passed gate; say so in the PR body.
- Wire and Operation changes start in `/proto` and are regenerated with `make proto`, never
  hand-edited (invariant 8).
- Optional: `make dev-fleet-up` runs a Relay and real relay-daemons in Docker; see
  [docs/dev-fleet.md](docs/dev-fleet.md).

## The security surface lands in front of a human

Changes to the paths listed in
[docs/agents/security-surface.txt](docs/agents/security-surface.txt) (`/proto`, ADRs, Policy,
execution, transport, mTLS and auth code, dependency manifests, the `Makefile`, CI,
`AGENTS.md`/`GLOSSARY.md`, and more) always get deliberate human review. Nothing merges
without a human, whoever wrote it. A change that seems to need breaking an invariant needs an
ADR first: open an issue and say so.

## How the dev-loop fits

Much of this repository is built by the dev-loop, an automated workflow that takes one
`loop:ready` issue at a time and opens pull requests a human merges
([docs/agents/workflow.md](docs/agents/workflow.md)). A human contributor needs neither Claude
nor Codex, does not apply `loop:*` labels, and skips the PR template's Reviews section.

Capability specifications in `docs/specs/` are co-authored with a human. If your change would
make a spec claim untrue, the spec is updated first: name the claim in the PR.

## Pull requests

One issue per PR. Fill in the template. Titles follow `<type>(<area>): ...` or `<type>: ...`,
as in the commit history.

