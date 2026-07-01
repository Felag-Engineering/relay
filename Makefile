# Gleipnir Relay — top-level build wrapper over both toolchains.
# Go builds the Relay (/relay); Cargo builds the relay-daemon (/daemon);
# proto codegen feeds both from /proto (the contract spine, ADR-0007).

# Prepend toolchain dirs so `make` works in non-login shells.
# Schedulers (cron, Claude routines) don't source ~/.profile, so cargo/go/buf may be absent.
export PATH := $(HOME)/.cargo/bin:$(HOME)/go/bin:$(HOME)/.local/bin:/usr/local/go/bin:$(PATH)

.PHONY: build test lint proto proto-tools proto-check build-relay build-daemon \
        test-relay test-relay-race test-daemon lint-relay lint-daemon clean test-integration \
        fmt fmt-relay fmt-daemon vuln-relay vuln-daemon build-daemon-release

build: build-relay build-daemon

test: test-relay test-daemon test-integration

lint: lint-relay lint-daemon

## --- proto codegen ---
# Go types are generated (via buf) into relay/internal/gleipnir/v1/ and committed.
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
# Runs proto (which regenerates) then fails if relay/internal/gleipnir/v1 differs.
proto-check: proto
	git diff --exit-code -- relay/internal/gleipnir/v1

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

## --- End-to-end smoke test ---
# Boots both binaries and asserts the Hello→Ping handshake (ADR-0005, ADR-0007).
# Depends on build so binaries exist before the script runs.
test-integration: build
	bash scripts/smoke-test.sh

lint-daemon:
	cd daemon && cargo fmt --check && cargo clippy -- -D warnings

## --- vulnerability scanning (nightly; non-blocking in CI) ---
# Install: go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
vuln-relay:
	cd relay && govulncheck ./...

# Install: cargo install cargo-audit --version 0.22.2 --locked # pinned for supply-chain reproducibility
vuln-daemon:
	cd daemon && cargo audit

clean:
	cd relay && go clean ./... || true
	cd daemon && cargo clean || true
