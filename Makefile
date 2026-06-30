# Gleipnir Relay — top-level build wrapper over both toolchains.
# Go builds the Relay (/relay); Cargo builds the relay-daemon (/daemon);
# proto codegen feeds both from /proto (the contract spine, ADR-0007).

.PHONY: build test lint proto proto-tools build-relay build-daemon test-relay test-daemon \
        lint-relay lint-daemon clean \
        loop loop-dry loop-bootstrap loop-decompose loop-gate-test

build: build-relay build-daemon

test: test-relay test-daemon

lint: lint-relay lint-daemon

## --- proto codegen ---
# Go types are generated (via buf) into relay/internal/gleipnir/v1/ and committed,
# so CI needs neither buf nor the plugins. Rust types are generated at cargo-build
# time by daemon/build.rs (tonic-build), so there is no Rust step here.
# Run `make proto-tools` once to install the Go plugins before regenerating.
proto:
	cd proto && PATH="$$(go env GOPATH)/bin:$$PATH" buf generate

# Dev-only: install the protoc plugins `make proto` needs (into $(go env GOPATH)/bin).
proto-tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

## --- Relay (Go) ---
build-relay:
	cd relay && go build ./...

test-relay:
	cd relay && go test ./...

lint-relay:
	cd relay && gofmt -l . && go vet ./...

## --- relay-daemon (Rust) ---
build-daemon:
	cd daemon && cargo build

# Release artifact for the fleet: small static musl binary (ADR-0007).
build-daemon-release:
	cd daemon && cargo build --release --target x86_64-unknown-linux-musl

test-daemon:
	cd daemon && cargo test

lint-daemon:
	cd daemon && cargo fmt --check && cargo clippy -- -D warnings

clean:
	cd relay && go clean ./... || true
	cd daemon && cargo clean || true

## --- Autonomous dev-loop (scripts/dev-loop) ---
# One-time setup: create loop:* labels and roadmap milestones on GitHub.
loop-bootstrap:
	bash scripts/dev-loop/bootstrap.sh

# Human seam #1: draft issues for the active milestone (review before --apply).
# Apply with: bash scripts/dev-loop/decompose.sh <milestone> --apply
loop-decompose:
	bash scripts/dev-loop/decompose.sh

# Run one issue end-to-end. DRY_RUN variant does everything except push/merge.
loop:
	bash scripts/dev-loop/loop.sh
loop-dry:
	DRY_RUN=1 bash scripts/dev-loop/loop.sh

# Sanity-check the deterministic gate against sample diffs.
loop-gate-test:
	bash scripts/dev-loop/gate.test.sh
