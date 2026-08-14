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
        gen-opschema dev-fleet-up dev-fleet-down dev-fleet-logs fuzz-relay fuzz-daemon \
        verify opschema-check openapi-check gen-apiclient apiclient-check

## --- verify: the local mirror of CI ---
# `make build test lint` is the fast inner loop. It is NOT what CI runs, and
# the gap has bitten: CI additionally runs the race detector, the proto-drift
# and proto-breaking gates, the operation-schema drift check, the devharness
# absence check, and both cross-binary suites. Work can pass the inner loop and
# fail CI on a class of problem the author never looked at.
#
# `make verify` closes that gap: one target, mirroring .github/workflows/ci.yml
# job for job, so "it passes locally" means the same thing it means in CI.
#
# It is deliberately slower than `make test` — race builds and two e2e suites —
# and deliberately not what you run on every save. Run it before opening a PR.
#
# The proto gates need `buf`, which is not part of a normal dev setup. When it
# is absent they are SKIPPED WITH A NOTICE rather than silently passed over or
# hard-failed: a check you did not run must not look like a check that passed.
verify: fmt lint-relay lint-daemon lint-devharness devharness-absent-check \
        test-relay-race test-daemon opschema-check openapi-check apiclient-check verify-proto \
        test-integration test-crossbinary
	@echo
	@echo "verify: all local CI-equivalent gates passed."

# Operation-schema drift (ci.yml: opschema-drift). Regenerates the committed
# schema from the daemon binary and fails if it moved.
opschema-check: gen-opschema
	git diff --exit-code -- relay/internal/opvocab/testdata/operations.schema.json

# Control API client codegen (#359). A typed Go client GENERATED from the
# published spec — the contract's conformance test: the client is compiled and
# checked against every operationId the spec declares, so a spec the server
# cannot honour, or generated code someone hand-edited, fails the build.
#
# There is deliberately no CLI consuming it (see internal/apiclient's package
# doc): the Console owns the human surface, and the client stands on its own as
# the conformance gate plus the starting point for any future Go integration.
#
# Pinned version — an unpinned generator would make the committed output depend
# on whatever was installed that day.
OAPI_CODEGEN_VERSION := v2.8.0

gen-apiclient:
	cd relay && go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION) \
		-config internal/apiclient/config.yaml ../docs/api/openapi.yaml

# Drift gate (ci.yml: openapi), mirroring opschema-check: regenerate from the
# committed spec and fail if the result moved. Catches a spec edit that was not
# regenerated AND a hand-edit of generated code.
apiclient-check: gen-apiclient
	git diff --exit-code -- relay/internal/apiclient/client.gen.go

# OpenAPI contract gate (ci.yml: openapi). Validates docs/api/openapi.yaml as a
# real OpenAPI 3.1 document and checks it against the route table the server
# actually mounts (api.Routes()), in BOTH directions — an undocumented route and
# a documented-but-unserved one each fail. It runs in the Go toolchain rather
# than through a Node linter on purpose: a gate that needs an uninstalled tool
# is a gate that never runs.
openapi-check:
	cd relay && go test ./internal/controlplane/api/ -run 'TestOpenAPISpec|TestServedRoutes' -count=1

# The two proto gates (ci.yml: proto-drift, proto-breaking), skipped with a
# notice when buf is unavailable.
verify-proto:
	@if command -v buf >/dev/null 2>&1; then \
		$(MAKE) proto-check proto-breaking; \
	else \
		echo "verify: SKIPPING proto-check and proto-breaking — buf not installed."; \
		echo "verify:   these run in CI regardless. Install with: make proto-tools"; \
	fi

## --- build stamping (issue #249, ADR-0014) ---
# scripts/build-version.sh derives "<version> <commit> <build-date>" once per
# make invocation. No tags, or no git at all, is a normal case there, not an
# error: it still yields valid semver ("<core>-0.dev"). The version's semantic
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
build-daemon-release:
	cd daemon && $(DAEMON_STAMP) cargo build --release --target x86_64-unknown-linux-musl

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
	cd daemon && cargo fmt --check && cargo clippy --all-targets -- -D warnings

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

## --- wire fuzzing, Rust half (nightly-only; bounded) — issues #238/#252 ---
# cargo-fuzz (libFuzzer) over the prost decode surface: the untrusted-bytes
# entry points the daemon parses off the wire (RelayMessage from the Tunnel
# stream, ADR-0005; EnrollResponse/RenewResponse from the Enrollment service,
# ADR-0006). Completes the coverage-guided half that #218's stable-toolchain
# proptest suite deliberately deferred.
#
# REQUIRES the NIGHTLY Rust toolchain plus cargo-fuzz
# (`rustup toolchain install nightly` then
#  `cargo install cargo-fuzz --version 0.13.2 --locked`).
# That is exactly why this target is wired ONLY into security-nightly.yml and
# must never be pulled into per-PR CI (ci.yml stays stable-only); the fuzz
# crate itself (daemon/fuzz) is a standalone workspace root, so the stable
# build/test/lint targets above never compile it.
#
# Bounds (documented per #238's DoD): -max_total_time caps wall-clock per
# target, -rss_limit_mb turns runaway allocation into a reported OOM crash,
# -max_len keeps inputs message-sized. Seed corpus is committed under
# daemon/fuzz/corpus/<target>/ (regenerate:
# `cd daemon/fuzz && cargo run --example gen_corpus`).
#
# Recipe lines are NOT `-`-prefixed, so `make` stops at the first crashing
# target — same one-crasher-at-a-time convention as fuzz-relay above. A crash
# leaves its minimized reproducer under daemon/fuzz/artifacts/<target>/; file
# it as a finding issue (#214/#215/#227/#236 pattern), never paper over it.
FUZZ_TOTAL_TIME ?= 60
FUZZ_RSS_MB     ?= 2048
FUZZ_MAX_LEN    ?= 65536
FUZZ_FLAGS      := -max_total_time=$(FUZZ_TOTAL_TIME) -rss_limit_mb=$(FUZZ_RSS_MB) -max_len=$(FUZZ_MAX_LEN)
fuzz-daemon:
	cd daemon && cargo +nightly fuzz run fuzz_relay_message_decode   -- $(FUZZ_FLAGS)
	cd daemon && cargo +nightly fuzz run fuzz_enroll_response_decode -- $(FUZZ_FLAGS)
	cd daemon && cargo +nightly fuzz run fuzz_renew_response_decode  -- $(FUZZ_FLAGS)

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
