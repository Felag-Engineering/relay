# Gleipnir Relay — top-level build wrapper over both toolchains.
# Go builds the Relay (/relay); Cargo builds the relay-daemon (/daemon);
# proto codegen feeds both from /proto (the contract spine, ADR-0007).

.PHONY: build test lint proto build-relay build-daemon test-relay test-daemon \
        lint-relay lint-daemon clean

build: build-relay build-daemon

test: test-relay test-daemon

lint: lint-relay lint-daemon

## --- proto codegen (wire up in v0.0.1) ---
# Generates Go types into relay/internal/proto and Rust types into daemon/src/gen.
# Recommended: buf. Until wired, this is the single place to define codegen.
proto:
	@echo "TODO(v0.0.1): wire proto codegen (buf) for Go + tonic/prost from ./proto"

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
