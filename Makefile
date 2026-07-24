# Relay — top-level build wrapper over both toolchains.
# Go builds the Relay (/relay); Cargo builds the relay-daemon (/daemon);
# proto codegen feeds both from /proto (the contract spine, ADR-0007).

# Prepend toolchain dirs so `make` works in non-login shells.
# Schedulers (cron, Claude routines) don't source ~/.profile, so cargo/go/buf may be absent.
export PATH := $(HOME)/.cargo/bin:$(HOME)/go/bin:$(HOME)/.local/bin:/usr/local/go/bin:$(PATH)

.PHONY: build test lint proto proto-tools proto-check proto-breaking build-relay build-daemon \
        test-relay test-relay-race test-daemon lint-relay lint-daemon clean test-integration \
        fmt fmt-relay fmt-daemon vuln-relay vuln-daemon build-daemon-release \
        build-relay-release build-release release-artifacts \
        build-relay-devharness devharness-absent-check test-crossbinary lint-devharness \
        gen-opschema dev-fleet-up dev-fleet-down dev-fleet-logs fuzz-relay

## --- build stamping (issue #249, ADR-0014) ---
# scripts/build-version.sh derives "<version> <commit> <build-date>" once per
# make invocation. No tags, or no git at all, is a normal case there, not an
# error: it still yields valid semver ("<base>-dev"). The version's semantic
# part comes from daemon/Cargo.toml, so both binaries carry the same version by
# construction. See docs/operations/version-stamping.md.
#
# The relay-daemon stamp is a cargo build-script input (daemon/build.rs), so a
# changed stamp correctly recompiles the daemon crate — which also means the
# unstamped `test-daemon`/`lint-daemon` targets recompile it once after a
# stamped `build-daemon`. That churn is deliberate: it keeps the stamp honest
# and leaves `cargo test` exercising the unstamped fallback path.
#
# The $(or ...) fallbacks cover only the case where the script produced nothing
# at all (unreadable Cargo.toml, no bash). They are exactly the compiled-in
# unstamped defaults of relay/internal/version, so a broken stamp degrades to an
# honest "this build is unidentified" rather than to a blank or fake version;
# 0.0.0-unknown is valid semver and sorts below every real release.
BUILD_STAMP    := $(shell bash scripts/build-version.sh)
BUILD_VERSION  := $(or $(word 1,$(BUILD_STAMP)),0.0.0-unknown)
BUILD_COMMIT   := $(or $(word 2,$(BUILD_STAMP)),unknown)
BUILD_DATE     := $(or $(word 3,$(BUILD_STAMP)),unknown)

VERSION_PKG := github.com/Felag-Engineering/gleipnir-relay/relay/internal/version
GO_LDFLAGS  := -X $(VERSION_PKG).Version=$(BUILD_VERSION) \
               -X $(VERSION_PKG).Commit=$(BUILD_COMMIT) \
               -X $(VERSION_PKG).BuildDate=$(BUILD_DATE)
DAEMON_STAMP := RELAY_BUILD_VERSION=$(BUILD_VERSION) \
                RELAY_BUILD_COMMIT=$(BUILD_COMMIT) \
                RELAY_BUILD_DATE=$(BUILD_DATE)

build: build-relay build-daemon

test: test-relay test-daemon

lint: lint-relay lint-daemon

## --- proto codegen ---
# Go types are generated (via buf) into relay/internal/relay/v1/ and committed.
# CI runs make proto-tools then make proto for the proto-drift check; Rust types are
# generated at cargo-build time by daemon/build.rs (tonic-build), so there is no
# Rust step here.  Run `make proto-tools` once before regenerating locally.
proto:
	cd proto && PATH="$$(go env GOPATH)/bin:$$PATH" buf generate

# Install the proto codegen toolchain at pinned versions (into $(go env GOPATH)/bin).
# Versions must match the committed generated code; @latest is intentionally avoided
# (protoc-gen-go-grpc@latest = v1.6.2 produces a spurious diff, false-positiving proto-drift).
proto-tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
	go install github.com/bufbuild/buf/cmd/buf@v1.54.0

# Verify no committed generated code drifts from the proto source (ADR-0007).
# Runs proto (which regenerates) then fails if relay/internal/relay/v1 differs.
proto-check: proto
	git diff --exit-code -- relay/internal/relay/v1

# Additive-only /proto gate (ADR-0014): fail if the working-tree proto breaks wire
# compatibility vs a base git ref. Run from repo root so the `.git` input resolves at
# the repo root; `subdir=proto` points buf at the proto module inside that revision.
# PROTO_BREAKING_REF defaults to origin/main for local use; CI passes the PR base SHA.
PROTO_BREAKING_REF ?= origin/main
proto-breaking:
	PATH="$$(go env GOPATH)/bin:$$PATH" buf breaking proto \
		--against ".git#ref=$(PROTO_BREAKING_REF),subdir=proto"

## --- Relay (Go) ---
# Emit the actual `relay` binary (into the gitignored relay/bin/), not just a
# compile check. `go build ./...` validates but produces no artifact.
build-relay:
	cd relay && go build -ldflags "$(GO_LDFLAGS)" -o bin/relay ./cmd/relay

test-relay:
	cd relay && go test ./...

test-relay-race:
	cd relay && go test -race ./...

lint-relay:
	cd relay && gofmt -l . && go vet ./... && golangci-lint run

## --- format-only targets (no compile; called by the format CI job) ---
# fmt-relay fails loudly if any file is unformatted: gofmt -l alone exits 0 even on drift.
fmt-relay:
	@test -z "$$(cd relay && gofmt -l .)" || { cd relay && gofmt -l . >&2; exit 1; }

fmt-daemon:
	cd daemon && cargo fmt --check

fmt: fmt-relay fmt-daemon

## --- relay-daemon (Rust) ---
build-daemon:
	cd daemon && $(DAEMON_STAMP) cargo build

# Release artifact for the fleet: small static musl binary (ADR-0007).
#
# --remap-path-prefix rewrites the absolute build paths that rustc otherwise
# compiles in: the generated proto module's path, and ~400 registry paths from
# dependency panic locations. Without it, two clones of the SAME tag at
# different paths produce different binaries (measured: 21 differing bytes plus
# every `$(HOME)/.cargo/registry/...` string), so rebuild-and-compare
# verification would be impossible anywhere but the original builder's machine
# — and the published artifact would leak that builder's home directory and
# checkout layout to every customer who runs `strings` on it. Cargo's
# `[profile.release] trim-paths` is the tidier spelling but is still
# nightly-gated on 1.94.1. Deliberately overrides any ambient RUSTFLAGS: the
# release build's output must not depend on the builder's environment.
RELEASE_RUSTFLAGS := --remap-path-prefix=$(CURDIR)=/build --remap-path-prefix=$(HOME)/.cargo=/cargo

build-daemon-release:
	cd daemon && $(DAEMON_STAMP) RUSTFLAGS="$(RELEASE_RUSTFLAGS)" \
		cargo build --release --target x86_64-unknown-linux-musl

## --- release artifacts (issue #250, closes #44) ---
# What a v* tag publishes. See docs/operations/release-artifacts.md.
#
# The Relay's release build is NOT build-relay: CGO_ENABLED=0 makes it
# libc-independent for the same reason the daemon targets musl (ADR-0007) —
# the default cgo build would link against the build machine's glibc and then
# refuse to start on any older one. -trimpath drops absolute build paths, which
# (with SOURCE_DATE_EPOCH pinned by the release workflow) is what keeps two
# builds of one tag byte-identical.
build-relay-release:
	cd relay && CGO_ENABLED=0 go build -trimpath -ldflags "$(GO_LDFLAGS)" -o bin/relay ./cmd/relay

build-release: build-relay-release build-daemon-release

# Verify + stage + checksum into dist/. Never publishes: the workflow's
# `gh release create` step runs only if this exits 0. Depends on build-release
# so `make release-artifacts TAG=v0.0.9` is the whole local rehearsal, with no
# way to check yesterday's binaries by accident.
# Usage: make release-artifacts TAG=v0.0.9   (TAG defaults to $GITHUB_REF_NAME)
#
# A TAG IS UNTRUSTED DATA. `git check-ref-format` accepts `;`, `&`, `|`, `>`,
# `$`, `'` and backticks in a tag name, so whoever can push a tag chooses this
# string — and it is consumed by a job holding `contents: write` and
# `github.token`. Two separate expanders want to eat it, and only one of them
# is closed by anything written here:
#
#  1. THE SHELL. make hands each recipe line to /bin/sh, so interpolating
#     $(TAG) into the recipe is a command-injection sink that fires before the
#     script's tag-shape guard ever runs. Quoting is NOT a fix, and was
#     measured not to be: `"$(TAG)"` stops `;` and `&` but still lets `` ` ``
#     and `$(...)` substitute, since the shell expands those inside double
#     quotes; single quotes just move the hole to `'`, also a legal tag
#     character. Hence TAG does not appear in the recipe text at all — `export`
#     puts it in the child's environment verbatim, with no shell parsing.
#
#  2. MAKE ITSELF, for variables set on the MAKE COMMAND LINE, which it
#     expands during command-line processing — `make TAG='v1$(shell ...)'`
#     runs that shell function, and there is no defusal (`$(value TAG)` was
#     tried; the substitution had already happened before it could see the
#     text). This one is NOT reachable from a real tag: make's `$(shell ...)`
#     needs whitespace after the function name, and `git check-ref-format`
#     rejects both space and tab in a ref, so the pushable form `$(shellid)`
#     is just an undefined variable that expands to nothing. All measured.
#     Environment-origin values are not expanded this way at all.
#
#     Belt and braces regardless: *** CI PASSES THE TAG THROUGH THE
#     ENVIRONMENT, NEVER AS `make release-artifacts TAG=...` ***
#     (.github/workflows/release.yml). The command-line form stays supported
#     for local use, where the developer typing it chose the value.
#
# No `export` is needed or wanted here: make already places both
# environment-origin and command-line-origin variables in a recipe's
# environment, so the script sees TAG either way — and without the export
# directive, TAG stays out of the environment of every OTHER recipe (the
# cargo and go builds) when it is not set. Verified in both origins.
TAG ?=
release-artifacts: build-release
	bash scripts/release-artifacts.sh

test-daemon:
	cd daemon && cargo test

## --- End-to-end integration tests ---
# test-integration is NOT part of the make test gate (hermetic suites only).
# Run explicitly: make test-integration
# Runs the mTLS smoke test (certless rejection) then the real-wire Go integration
# tests (//go:build integration) with the actual relay-daemon binary.
# Depends on build so both binaries exist before running.
test-integration: build
	bash scripts/smoke-test.sh
	cd relay && RELAY_DAEMON_BIN=$(CURDIR)/daemon/target/debug/relay-daemon go test -tags integration ./cmd/relay/...

lint-daemon:
	cd daemon && cargo fmt --check && cargo clippy -- -D warnings

## --- opschema golden (ADR-0015: daemon is the single source of truth for what
## it enforces) ---
# Regenerates the golden Operation schema by running the daemon's offline
# `dump-operation-schema` subcommand (same pre-runtime seam as `policy check`)
# and writing its canonical JSON straight to the committed golden. The golden
# MUST live inside relay/internal/opvocab/ (not repo root): opvocab_test.go
# //go:embed's it, and go:embed cannot reach above its own package tree.
gen-opschema: build-daemon
	$(CURDIR)/daemon/target/debug/relay-daemon dump-operation-schema > $(CURDIR)/relay/internal/opvocab/testdata/operations.schema.json

## --- #112 dev-harness cross-binary CI machinery ---
# Kept OUT of build/test/lint: build-relay-devharness produces a non-shippable
# binary (the devharness dispatch/control backdoor, ADR-relevant — see
# relay/cmd/relay/devharness.go), and test-crossbinary needs both real
# binaries and is non-hermetic, matching the existing test-integration
# exclusion above.

# The devharness-tagged relay binary: never the shippable relay/bin/relay.
build-relay-devharness:
	cd relay && go build -tags devharness -o bin/relay-devharness ./cmd/relay

# Vet the gated files that the default (untagged) lint-relay never compiles,
# let alone lints: devharness.go and the integration-tagged Go tests.
lint-devharness:
	cd relay && go vet -tags devharness ./cmd/relay && go vet -tags integration ./cmd/relay/...

# Mechanically proves the devharness surface is absent from the normal
# (untagged, shippable) relay binary and present in the devharness-tagged one.
devharness-absent-check:
	bash scripts/devharness-absent-check.sh

# The #112 acceptance test, plus the #103 fleet-semantics e2e suite (both
# real relay + real relay-daemon binaries over real loopback TCP, driven
# through the devharness control socket — the fleet suite additionally drives
# the real capability pipeline/Job engine, including a real Relay crash
# mid-Job, ADR-0004).
test-crossbinary: build-daemon build-relay-devharness
	cd relay && RELAY_BIN=$(CURDIR)/relay/bin/relay-devharness \
		RELAY_DAEMON_BIN=$(CURDIR)/daemon/target/debug/relay-daemon \
		go test -tags integration -run 'TestCrossBinary|TestFleetE2E' ./cmd/relay/...

## --- vulnerability scanning (nightly; non-blocking in CI) ---
# Install: go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
vuln-relay:
	cd relay && govulncheck ./...

# Install: cargo install cargo-audit --version 0.22.2 --locked # pinned for supply-chain reproducibility
vuln-daemon:
	cd daemon && cargo audit

## --- wire fuzzing (nightly; bounded) — issue #217 ---
# Native Go fuzzing. `go test -fuzz` fuzzes ONE target per invocation, so each
# target gets its own call (anchored regex) with `-run=^$$` so unit tests
# don't re-run. The seed corpus (f.Add(...) in each FuzzXxx) ALSO runs under
# the normal test gate (no -fuzz, see test-relay), so PRs stay green without
# open-ended fuzzing. Override FUZZTIME for longer nightly runs:
# `make fuzz-relay FUZZTIME=120s`.
#
# Recipe lines below are NOT `-`-prefixed, so `make` stops at the first
# failing target: a red nightly run surfaces the first crasher, and the next
# run (after that reproducer is committed as a regression seed) surfaces the
# next one. This is intentional — one crasher at a time keeps each failure
# triageable — not a bug.
#
# The fuzz corpus cache ($GOCACHE/fuzz) is not persisted across nightly runs
# (no cache step below, unlike the Go-modules cache); each run starts fresh
# from the in-code f.Add seeds. Known limitation — persisting the corpus
# across runs is a future follow-up, not required for issue #217's DoD.
FUZZTIME ?= 30s
fuzz-relay:
	cd relay && go test -run=^$$ -fuzz='^FuzzSignCSR$$'                -fuzztime=$(FUZZTIME) ./internal/ca/
	cd relay && go test -run=^$$ -fuzz='^FuzzFactsFromProto$$'         -fuzztime=$(FUZZTIME) ./internal/protoconv/
	cd relay && go test -run=^$$ -fuzz='^FuzzParseNodeLabel$$'         -fuzztime=$(FUZZTIME) ./internal/protoconv/
	cd relay && go test -run=^$$ -fuzz='^FuzzSnapshotFromProto$$'      -fuzztime=$(FUZZTIME) ./cmd/relay/
	cd relay && go test -run=^$$ -fuzz='^FuzzNodeLabelsFromHello$$'    -fuzztime=$(FUZZTIME) ./cmd/relay/
	cd relay && go test -run=^$$ -fuzz='^FuzzDaemonMessageUnmarshal$$' -fuzztime=$(FUZZTIME) ./cmd/relay/

## --- local dev fleet (DEV-ONLY; requires Docker + compose v2) ---
# Thin convenience wrappers over `docker compose` for the laptop dev fleet
# (docs/dev-fleet.md). NOT part of build/test/lint and never invoked by CI —
# the hermetic gate must never depend on Docker. Nothing else depends on these
# targets; docs/dev-fleet.md documents the raw commands too.
dev-fleet-up:
	docker compose up --build -d

dev-fleet-down:
	docker compose down

dev-fleet-logs:
	docker compose logs -f

clean:
	cd relay && go clean ./... || true
	cd daemon && cargo clean || true
