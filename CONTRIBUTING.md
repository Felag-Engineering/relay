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

## Repository layout

```
/proto/              protobuf contract, the spine. Edit here first for any wire or Operation change.
/relay/              Go: gRPC server, MCP server, Job engine, CA, registry, store.   (cd relay)
/relay/packaging/    the Relay's hardened systemd unit and example EnvironmentFile.
/daemon/             Rust: connection, Policy engine, Operation executors, exec.      (cd daemon)
/daemon/packaging/   relay-daemon systemd unit, example EnvironmentFile, shipped Template catalog.
/daemon/fuzz/        cargo-fuzz targets and corpus for the daemon.
/docker/             Dockerfiles, entrypoints, one-shots and the daemon image's baked fixtures.
/deploy/             one folder per environment: production/, test/ (three Nodes), demo/ (nine).
/scripts/            CI gates and repo tooling (docs checks, spec coverage, security surface).
/docs/adr/           architecture decision records: the why.
/docs/agents/        the workflow and the per-repo configuration agent skills read.
/docs/api/           Control API reference and OpenAPI surface.
/docs/brand/         the relay_ wordmark and icon and how to use them.
/docs/design/        console/ is the Console's per-screen specification; plans/ holds design plans.
/docs/operations/    operator runbooks: install, enrollment, upgrades, recovery, demo fleet.
/docs/proposals/     decided proposals: the problem, the objections and answers, the outcome.
/docs/security/      the threat model and the one register of accepted residual risk.
/docs/specs/         capability specifications: what each capability does today.
/.claude/            the workflow's commands and agents, committed so routines have them.
/.github/            CI workflows and the pull request template.
Makefile             wraps both toolchains; `make verify` is the CI-equivalent gate.
```

## Build and verify

| Task | Command |
|---|---|
| Build, test, lint everything (the inner loop) | `make build test lint` |
| **The CI-equivalent gate, before every PR** | **`make verify`** |
| Install the pinned proto plugins, then regenerate | `make proto-tools`, then `make proto` |
| Local Docker fleet: up, credentials, logs, down | `make dev-fleet-up` · `-creds` · `-logs` · `-down` |
| Relay only (Go) | `cd relay && go build ./... && go test ./...` |
| Daemon only (Rust) | `cd daemon && cargo build && cargo test && cargo clippy` |

- **`make build test lint` is not what CI runs.** CI also runs the race detector, the
  proto-drift and proto-breaking gates, the operation-schema and OpenAPI drift checks, the docs
  and security-surface self-checks, the strict-umask runs, both cross-binary suites, the shell
  and workflow linters, the devharness absence check, the secrets scan and cargo-deny.
  `make verify` mirrors CI gate for gate and is deliberately slow. On a PR, CI skips gates a
  change cannot reach (`scripts/ci-changed-paths.sh`); a draft PR runs only the docs job, and a
  push to `main` runs everything.
- **A skipped gate is not a passed gate**, whichever tool was absent (`buf`, `zizmor`,
  `cargo-deny`): say so in the PR body. `verify-proto` skips the proto-drift and
  proto-breaking checks with a notice when `buf` is absent; if your diff touches `/proto`, say
  so in the PR body. Install `buf` with `make proto-tools`.
- **Go.** The version is named once, in `relay/go.mod`, and the `Makefile` derives
  `GOTOOLCHAIN` from it; `gofmt` runs out of `go env GOROOT`. A bare `go test` outside `make` is
  not pinned. `GOTOOLCHAIN=local make <target>` is the one-run escape hatch. Lint is `gofmt`,
  `go vet` and `golangci-lint`. Raising the Go
  version is a decision, not a chore (#572).
- **Rust.** Stable, with the floor as `rust-version` in `daemon/Cargo.toml`, and deliberately no
  `rust-toolchain.toml`. CI and the release build on one exact stable, `RUST_TOOLCHAIN` in
  `ci.yml`; `rustup toolchain install` it to reproduce a CI failure. `make lint` and
  `make verify` build the daemon for musl, which needs `rustup target add
  x86_64-unknown-linux-musl` and, on Debian or Ubuntu, `musl-tools`. Lint is `cargo fmt` and
  `cargo clippy -- -D warnings`.
- **Proto codegen is version-sensitive.** An unpinned plugin produces a spurious diff that
  false-positives the proto-drift gate; re-run `make proto-tools` before believing a drift you
  did not cause. Never hand-edit generated code (invariant 8).
- `make test` is hermetic and will not catch real-binary startup bugs: run
  `make test-integration` when the diff touches Relay startup, the composition root or config
  defaults. `make dev-fleet-up` runs a Relay and real daemons in Docker
  ([docs/dev-fleet.md](docs/dev-fleet.md)).
- A checkout cloned as `gleipnir-relay` works through GitHub's redirect; repoint it with
  `git remote set-url origin git@github.com:Felag-Engineering/relay.git`.

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

