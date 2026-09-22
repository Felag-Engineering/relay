# Relay — top-level build wrapper over both toolchains.
# Go builds the Relay (/relay); Cargo builds the relay-daemon (/daemon);
# proto codegen feeds both from /proto (the contract spine, ADR-0007).

# Prepend toolchain dirs so `make` works in non-login shells.
# Schedulers (cron, Claude routines) don't source ~/.profile, so cargo/go/buf may be absent.
export PATH := $(HOME)/.cargo/bin:$(HOME)/go/bin:$(HOME)/.local/bin:/usr/local/go/bin:$(PATH)

.PHONY: build test lint proto proto-tools proto-check proto-breaking build-relay build-daemon \
        test-relay test-relay-race test-daemon test-strict-umask test-strict-umask-relay \
        test-strict-umask-daemon lint-relay lint-daemon lint-tools tools \
        clean test-integration \
        fmt fmt-relay fmt-daemon vuln-relay vuln-daemon build-daemon-release \
        build-relay-devharness devharness-absent-check test-crossbinary lint-devharness \
        test-security-surface test-codex-review \
        gen-opschema dev-fleet-up dev-fleet-down dev-fleet-logs dev-fleet-creds \
        demo-build demo-reset demo-fault demo-up demo-down demo-creds test-demo-fleet \
        fuzz-relay fuzz-daemon \
        verify opschema-check openapi-check gen-apiclient apiclient-check

## --- verify: the local mirror of CI ---
# `make build test lint` is the fast inner loop. It is NOT what CI runs, and
# the gap has bitten: CI additionally runs the race detector, the proto-drift
# and proto-breaking gates, the operation-schema drift check, the devharness
# absence check, the security-surface gate self-test, the demo-fleet reset
# guard self-test, the codex-review gate self-test, the strict-umask test lane,
# and both cross-binary suites.
# Work can pass the inner loop and fail CI on a class of problem the author
# never looked at.
#
# `make verify` closes that gap: one target, mirroring .github/workflows/ci.yml
# gate for gate, so "it passes locally" means the same thing it means in CI.
# (CI groups several gates per job to share one toolchain setup and build cache;
# the gates themselves are these same targets.)
#
# It is deliberately slower than `make test` — race builds and two e2e suites —
# and deliberately not what you run on every save. Run it before opening a PR.
#
# The proto gates need `buf`, which is not part of a normal dev setup. When it
# is absent they are SKIPPED WITH A NOTICE rather than silently passed over or
# hard-failed: a check you did not run must not look like a check that passed.
verify: fmt lint-relay lint-daemon lint-devharness devharness-absent-check \
        test-relay-race test-daemon test-strict-umask opschema-check openapi-check \
        apiclient-check verify-proto docs-check test-security-surface \
        test-demo-fleet test-codex-review test-integration test-crossbinary
	@echo
	@echo "verify: all local CI-equivalent gates passed."

# Operation-schema drift (ci.yml: the daemon job's opschema-drift step). Regenerates the committed
# schema from the daemon binary and fails if it moved.
opschema-check: gen-opschema
	git diff --exit-code -- relay/internal/opvocab/testdata/operations.schema.json

# Control API client codegen (#359). A typed Go client GENERATED from the
# published spec — the contract's conformance test: a spec the server cannot
# honour, or one a real generator cannot consume, fails here.
#
# The output is NOT COMMITTED. There is deliberately no CLI consuming it (see
# internal/apiclient's package doc): the Console owns the human surface, so
# thousands of lines of generated code with no consumer would be pure
# repository weight. What has value is the act of generating and compiling it,
# and that is what CI does. The file is gitignored, so a stray `git add` cannot
# put it back.
#
# Pinned version — an unpinned generator would make the check depend on
# whatever was installed that day.
OAPI_CODEGEN_VERSION := v2.8.0

gen-apiclient:
	rm -f relay/internal/apiclient/client.gen.go
	cd relay && go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_VERSION) \
		-config internal/apiclient/config.yaml ../docs/api/openapi.yaml

# Contract gate (ci.yml: the relay job's OpenAPI steps): generate a client from the committed spec,
# COMPILE it, and assert the mapping is total — every operationId the spec
# declares has a client method. Generation alone would not catch a schema name
# that collides with a generated wrapper type; compilation would not catch an
# operation the generator silently skipped. Both halves are needed.
#
# `gen-apiclient` removes any previous output first, so a stale file cannot
# stand in for a generation that failed.
apiclient-check: gen-apiclient
	cd relay && go build -tags apiclient ./internal/apiclient/ \
		&& go test -tags apiclient ./internal/apiclient/ -count=1

# OpenAPI contract gate (ci.yml: the relay job's OpenAPI steps). Validates docs/api/openapi.yaml as a
# real OpenAPI 3.1 document and checks it against the route table the server
# actually mounts (api.Routes()), in BOTH directions — an undocumented route and
# a documented-but-unserved one each fail. It runs in the Go toolchain rather
# than through a Node linter on purpose: a gate that needs an uninstalled tool
# is a gate that never runs.
openapi-check:
	cd relay && go test ./internal/controlplane/api/ -run 'TestOpenAPISpec|TestServedRoutes' -count=1

# The two proto gates (ci.yml: the proto job's proto-drift and proto-breaking steps), skipped with a
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
	go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
	go install github.com/bufbuild/buf/cmd/buf@v1.54.0

# golangci-lint at a pinned version (full module path required: v2 module). Pinned
# here rather than in ci.yml so every `go install` pin lives in one place: CI keys
# its cached tool binaries on these lines, so bumping a version rebuilds the cache.
lint-tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2

tools: proto-tools lint-tools

# Documentation gates: ADR numbers are unique, and every test a capability spec
# names in its proof table still exists. Both catch drift that has happened here —
# two files once claimed ADR-0015, and a spec citing tests by name breaks silently
# when one is renamed. Cheap, hermetic, no network.
.PHONY: console-snapshots
# Render every Console screen against the test fixtures and write the HTML to
# relay/console-snapshots/ (gitignored). The design canvas is seeded from these so
# the UI is edited from the real pages; re-run after any Console change.
console-snapshots:
	@rm -rf relay/console-snapshots && cd relay && RELAY_CONSOLE_SNAPSHOT_DIR=$(CURDIR)/relay/console-snapshots \
	  go test ./internal/controlplane/console -run TestConsole_WriteScreenSnapshots -count=1 -v 2>&1 | grep -E 'wrote|FAIL|ok ' || true
	@ls relay/console-snapshots

.PHONY: docs-check adr-index
# Both run so a PR sees every finding at once; the target fails if either does. check-crosslinks
# includes the docs/adr/README.md drift gate (same pattern as opschema-check: regenerate, compare).
docs-check:
	@./scripts/check-docs.sh; a=$$?; ./scripts/check-crosslinks.sh; b=$$?; exit $$((a | b))

# Regenerate the ADR index from the ADR files. Commit the result; docs-check fails on drift.
adr-index:
	@./scripts/adr-index.sh > docs/adr/README.md && echo "adr-index: wrote docs/adr/README.md"

# Proves scripts/security-surface.sh sees what its header claims — untracked files, both halves
# of a rename, and an unresolvable base ref, the three ways it used to report "clean" (#634).
# Runs against a throwaway fixture repo; touches nothing in this working tree.
test-security-surface:
	bash scripts/security-surface-test.sh

# Proves scripts/demo-fleet.sh's guard refuses BEFORE any docker call unless the target
# is the relay-demo compose project on a local engine (#622). Hermetic: docker is a
# stub under a throwaway WORKDIR, so this touches no real Docker engine.
test-demo-fleet:
	bash scripts/demo-fleet-test.sh

# Proves scripts/codex-review.sh exits 3 only when Codex is ABSENT — plugin missing, quota
# exhausted, credentials rejected — and never for a delivered report, a real review failure
# or a killed run, and that no cause line carries a credential (#620). Hermetic: the
# companion is a stub under a throwaway WORKDIR.
test-codex-review:
	bash scripts/codex-review-test.sh

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

## --- format-only targets (no compile; fmt-relay is the relay CI job's gofmt step) ---
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

## --- strict-umask test lane (ci.yml: the relay and daemon jobs' umask steps) — issue #528 ---
# Everything else in the gate runs at ONE umask: 0022 on a GitHub runner, and
# in practice the same on a dev box. That made a whole defect class
# structurally invisible — a fixture that quietly stops being a valid input, or
# an assertion pinning a mode the code never actually guarantees. #481, #507,
# #508, #509, #510, #513 and #514 were every one of them found by a scan, never
# by a red build.
#
# 077 rather than 027: 027 is the realistic hardened-host setting, but 077 is
# strictly stronger and one lane is cheaper than two.
#
# Scope matches `make test` — the same two hermetic lanes, on BOTH toolchains,
# where this class lives (Go: #508/#509; Rust fixtures: #481/#507/#513/#514).
# They are inlined rather than delegated to `make test` because each line needs
# to carry the umask itself, and the Go half needs -count=1. The race detector
# and the e2e suites would mostly buy runtime: nothing about this class is
# concurrency- or cross-binary-shaped.
#
# Two things this recipe gets right on purpose, both of which would silently
# make the lane worthless:
#
#  1. `-count=1` is load-bearing, not habit. The Go test cache keys on the test
#     binary and its inputs, NOT on the ambient umask, so a cached `ok` from
#     the default-umask lane is a false pass for exactly the tests this lane
#     exists to re-run. `cargo test` caches compilation but never test results,
#     so the Rust half needs no equivalent.
#  2. Each recipe line is its OWN shell, so `umask 077` has to lead each one —
#     it must apply to the process that actually runs the tests. The echo makes
#     that visible in the log rather than merely asserted here.
#
# Individual tests must never set the umask themselves: umask(2) is
# process-global and Go tests run in parallel, so a test that sets it corrupts
# its neighbours (ruled out on those grounds in #481). Setting it once, around
# the whole lane, is the safe shape.
#
# Split per toolchain so CI can run each half in the job that already compiled
# that toolchain's tests; `test-strict-umask` remains the whole lane.
test-strict-umask: test-strict-umask-relay test-strict-umask-daemon

test-strict-umask-relay:
	umask 077 && echo "test-strict-umask: umask is $$(umask)" && cd relay && go test -count=1 ./...

test-strict-umask-daemon:
	umask 077 && echo "test-strict-umask: umask is $$(umask)" && cd daemon && cargo test

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
# The nightly job persists the coverage-grown corpus ($GOCACHE/fuzz) across runs
# within a month with a cache step (security-nightly.yml), so each run resumes from
# what the previous ones found rather than restarting from the in-code f.Add seeds.
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
#
# FUZZ_GROWN_CORPUS (absolute path, optional): a directory the nightly job persists
# across runs. When set, each target reads <dir>/<target> AND the committed seeds,
# and writes new inputs only to <dir>/<target> — libFuzzer adds to the FIRST corpus
# directory — so a persisted corpus never overwrites or pollutes the committed seeds.
FUZZ_GROWN_CORPUS ?=
FUZZ_DAEMON_TARGETS := fuzz_relay_message_decode fuzz_enroll_response_decode fuzz_renew_response_decode
fuzz_corpus = $(if $(FUZZ_GROWN_CORPUS),$(FUZZ_GROWN_CORPUS)/$(1) $(CURDIR)/daemon/fuzz/corpus/$(1))
fuzz-daemon:
	$(if $(FUZZ_GROWN_CORPUS),mkdir -p $(addprefix $(FUZZ_GROWN_CORPUS)/,$(FUZZ_DAEMON_TARGETS)))
	cd daemon && cargo +nightly fuzz run fuzz_relay_message_decode   $(call fuzz_corpus,fuzz_relay_message_decode) -- $(FUZZ_FLAGS)
	cd daemon && cargo +nightly fuzz run fuzz_enroll_response_decode $(call fuzz_corpus,fuzz_enroll_response_decode) -- $(FUZZ_FLAGS)
	cd daemon && cargo +nightly fuzz run fuzz_renew_response_decode  $(call fuzz_corpus,fuzz_renew_response_decode) -- $(FUZZ_FLAGS)

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

# Export the fleet's CA cert and BOTH control-plane credentials (the founding
# admin's and dev-approver's) to the gitignored ./.dev-fleet/ so a host-side MCP
# client or scripts/dev-fleet-mcp.sh can reach the control plane over VERIFIED
# TLS. Run after dev-fleet-up.
dev-fleet-creds:
	bash scripts/dev-fleet-mcp.sh init

## --- demo fleet (DEV-ONLY; `--profile demo`, #622) ---
# A FIXED, guarded compose project — `relay-demo`, never the checkout-directory-named
# default `dev-fleet-*` targets above use — driven entirely through scripts/demo-fleet.sh.
# Every subcommand refuses before any Docker call except two read-only checks (the
# local-engine context endpoint, and a check that no other checkout already owns the
# project) unless the target is that one project on a local engine
# (scripts/demo-fleet-test.sh, test-demo-fleet, proves the refusal). Never invoked by
# CI. `demo-reset` NEVER builds — run `demo-build` first (and again after any code
# change); it is the only target that does.
demo-build:
	bash scripts/demo-fleet.sh build

# DEMO_FAULT_NODES overrides the default fault targets (daemon-4, daemon-6); e.g.
# `make demo-fault DEMO_FAULT_NODES="daemon-2 daemon-9"`. Exported, not spliced into
# the recipe text: Make hands it to the recipe's shell as a real environment
# variable via execve, so a value carrying a shell metacharacter (';', a backtick,
# '$(') reaches the script as an opaque string, never as text a shell re-parses
# (#622 security review S2). The script splits it on whitespace and validates every
# token against the derived web roster before any exec — see cmd_fault.
export DEMO_FAULT_NODES ?=

demo-reset:
	bash scripts/demo-fleet.sh reset

demo-fault:
	bash scripts/demo-fleet.sh fault

demo-down:
	bash scripts/demo-fleet.sh down

# Bring the demo fleet back up after `demo-down`, WITHOUT wiping any volume —
# the opposite of `demo-reset` (no `-v`, no build, and no image precheck the
# way `demo-reset` has one). With `--pull never` the only loud failure is a
# missing image — run `demo-build` once first. This is NOT "no credential
# mint": see `demo-creds` below for what `up` does and does not do to them.
demo-up:
	bash scripts/demo-fleet.sh up

# Copy the CURRENT control-plane credentials (and CA) out to the gitignored
# .dev-fleet/ — this mints nothing itself (scripts/dev-fleet-mcp.sh init is a
# `docker compose cp` / `run --no-deps` read, nothing more). What mints is the
# `credential`/`approver`/`console-admin`/`console-password` one-shots: they
# have `restart: no`, but a stopped one-shot container is STARTED again by
# `compose up` — including a plain `demo-up` — which re-runs its entrypoint
# and re-mints into the (persisted) volume. Run `demo-creds` after EITHER
# `demo-reset` or `demo-up` to pick up whatever was most recently minted.
demo-creds:
	bash scripts/demo-fleet.sh creds

clean:
	cd relay && go clean ./... || true
	cd daemon && cargo clean || true
