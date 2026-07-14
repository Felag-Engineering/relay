# Relay — top-level build wrapper over both toolchains.
# Go builds the Relay (/relay); Cargo builds the relay-daemon (/daemon);
# proto codegen feeds both from /proto (the contract spine, ADR-0007).

# Prepend toolchain dirs so `make` works in non-login shells.
# Schedulers (cron, Claude routines) don't source ~/.profile, so cargo/go/buf may be absent.
export PATH := $(HOME)/.cargo/bin:$(HOME)/go/bin:$(HOME)/.local/bin:/usr/local/go/bin:$(PATH)

.PHONY: build test lint proto proto-tools proto-check proto-breaking build-relay build-daemon \
        test-relay test-relay-race test-daemon lint-relay lint-daemon clean test-integration \
        fmt fmt-relay fmt-daemon vuln-relay vuln-daemon build-daemon-release \
        build-relay-devharness devharness-absent-check test-crossbinary lint-devharness \
        gen-opschema dev-fleet-up dev-fleet-down dev-fleet-logs

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
	cd relay && go build -o bin/relay ./cmd/relay

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
	cd daemon && cargo build

# Release artifact for the fleet: small static musl binary (ADR-0007).
build-daemon-release:
	cd daemon && cargo build --release --target x86_64-unknown-linux-musl

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
