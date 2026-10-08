# Relay — top-level build wrapper over both toolchains.
# Go builds the Relay (/relay); Cargo builds the relay-daemon (/daemon);
# proto codegen feeds both from /proto (the contract spine, ADR-0007).

# Prepend toolchain dirs so `make` works in non-login shells.
# Schedulers (cron, Claude routines) don't source ~/.profile, so cargo/go/buf may be absent.
export PATH := $(HOME)/.cargo/bin:$(HOME)/go/bin:$(HOME)/.local/bin:/usr/local/go/bin:$(PATH)

# The Go toolchain every `make` target builds and tests with (#667).
# relay/go.mod's `go` directive is a FLOOR: under GOTOOLCHAIN=auto the go
# command upgrades to it and never downgrades to it, so a developer with Go
# 1.26 installed runs every gate under 1.26 while CI (actions/setup-go, reading
# the same `go` line) runs 1.25.12 — a red `make verify` CI cannot reproduce
# (#572's ServeMux 301-vs-307 is the known symptom). Exporting the exact
# toolchain makes the floor a ceiling too. A `toolchain` directive would not
# have done this, and go.mod cannot even hold one equal to its own `go` line:
# the go command deletes it as redundant.
#
# `+auto` rather than a bare name: this repo's modules get the pinned toolchain,
# but a `go install <tool>@<version>` below whose own go.mod needs a NEWER one
# still upgrades instead of hard-failing. That is also the one residual path by
# which a newer toolchain runs anything here — every tool pinned below asks for
# 1.25.x or older today, so none of them takes it, and the relay module never
# does either way.
#
# Reach, stated so it is not over-read: GOTOOLCHAIN only re-execs the `go`
# command. Sibling binaries are not covered — which is why gofmt below is
# invoked out of `go env GOROOT` — and a bare `cd relay && go test ./...` run
# outside make is not pinned at all; internal/version's toolchain contract test
# is what catches that one.
#
# Derived from relay/go.mod so the version is named once. `?=` leaves a one-run
# escape hatch: `GOTOOLCHAIN=local make test-relay`. A `go` directive with no
# patch component (`go 1.26`) is not a valid toolchain name, so the awk yields
# nothing, the export is skipped, and the go command keeps its default.
GO_TOOLCHAIN := $(shell awk '$$1=="go" && $$2 ~ /^[0-9]+\.[0-9]+\.[0-9]+$$/ {print "go" $$2 "+auto"; exit}' relay/go.mod)
ifneq ($(GO_TOOLCHAIN),)
export GOTOOLCHAIN ?= $(GO_TOOLCHAIN)
endif

.PHONY: build test lint proto proto-tools proto-tools-check proto-check proto-breaking \
        build-relay build-daemon \
        test-relay test-relay-race test-daemon test-strict-umask test-strict-umask-relay \
        test-strict-umask-daemon lint-relay lint-daemon lint-tools tools \
        clean test-integration \
        fmt fmt-relay fmt-daemon vuln-relay vuln-daemon build-daemon-release print-release-daemon-bin \
        build-relay-devharness devharness-absent-check test-crossbinary lint-devharness \
        test-security-surface test-codex-review test-proto-tools-check test-ci-changed-paths \
        test-check-docs test-smoke-test test-maintainer-check \
        gen-opschema dev-fleet-up dev-fleet-down dev-fleet-logs dev-fleet-creds \
        demo-build demo-reset demo-reset-oauth demo-fault demo-up demo-up-oauth demo-down demo-creds \
        relay-demo-owner test-release-image-guard test-dev-fleet-make \
        fuzz-relay fuzz-daemon \
        verify verify-proto proto-lint opschema-check openapi-check gen-apiclient apiclient-check \
        lint-ci lint-shell lint-actions lint-zizmor zizmor-tool secrets-scan secrets-scan-history \
        deny-daemon deny-daemon-advisories deny-tool vuln-relay-gate test-vuln-gate

## --- verify: the local mirror of CI ---
# `make build test lint` is the fast inner loop. It is NOT what CI runs, and
# the gap has bitten: CI additionally runs the race detector, the proto-drift
# and proto-breaking gates, the operation-schema drift check, the devharness
# absence check, the security-surface gate self-test, the codex-review gate
# self-test, the proto-tools pin check self-test, the changed-paths classifier
# self-test, the docs-check, smoke-test, maintainer-check and dev-fleet Makefile
# guard self-tests, the strict-umask test lane, both cross-binary suites, the
# shell/workflow linters (lint-ci), the secrets scan and the daemon's cargo-deny
# policy. Work can pass the inner loop and fail CI on a class of problem the
# author never looked at.
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
# Every such skip is collected, and verify's last line says how many there were
# rather than claiming a full pass (the skip ledger, below). The same holds for the
# CI-hardening gates' tools (shellcheck, actionlint, zizmor, gitleaks, cargo-deny):
# under verify a missing one is a recorded skip; run on its own, it is a failure.
verify: fmt lint-relay lint-daemon lint-devharness devharness-absent-check \
        test-relay-race test-daemon test-strict-umask opschema-check openapi-check \
        apiclient-check verify-proto docs-check test-security-surface \
        test-codex-review test-proto-tools-check test-ci-changed-paths \
        test-check-docs test-smoke-test test-maintainer-check test-release-image-guard \
        test-dev-fleet-make test-integration test-crossbinary \
        lint-ci secrets-scan deny-daemon test-vuln-gate
	@echo
	@test -n "$(RELAY_VERIFY_SKIPS)" || { echo "verify: no skip ledger, so skipped gates cannot be ruled out" >&2; exit 1; }
	@if [ -s "$(RELAY_VERIFY_SKIPS)" ]; then \
		sed 's/^/verify: SKIPPED /' "$(RELAY_VERIFY_SKIPS)"; \
		echo "verify: every gate that ran passed, but $$(wc -l < "$(RELAY_VERIFY_SKIPS)") check(s) were SKIPPED (listed above; CI runs them) — NOT a full CI-equivalent pass."; \
	else \
		echo "verify: all local CI-equivalent gates passed; none skipped."; \
	fi; rm -f "$(RELAY_VERIFY_SKIPS)"

# GOFLAGS=-count=1, exactly as ci.yml's workflow-level env sets it, so no Go lane under verify
# (the race tests, both e2e suites, the contract checks) can replay a cached pass. The test
# cache does not key on everything a test depends on (the umask; a rebuilt relay-daemon at
# the same path), and CI never reuses results, so a local replay is a pass CI did not give.
# Target-specific, so it reaches every prerequisite verify builds and nothing outside verify.
verify: export GOFLAGS := -count=1

# The skip ledger. A gate that cannot run here (no buf; no GitHub for the milestone check)
# appends one line naming itself; verify's last line reports them instead of claiming a
# full pass. Created only when verify is a goal, and exported so the recursive $(MAKE) in
# verify-proto and the scripts see the same file. Skips do NOT fail verify: each is a gate
# CI runs unconditionally (its jobs install buf and hold a GitHub token), so a skip is a
# local tool gap, never a defect CI would reject — but it is reported as a skip, never as
# a pass. RELAY_VERIFY_SKIPS unset (any target run on its own) records nothing.
ifneq ($(filter verify,$(MAKECMDGOALS)),)
export RELAY_VERIFY_SKIPS := $(shell mktemp "$${TMPDIR:-/tmp}/relay-verify-skips.XXXXXX")
else ifeq ($(MAKELEVEL),0)
# Not under verify, and not a recursive make verify started (verify-proto's $(MAKE)
# inherits the ledger on purpose): a RELAY_VERIFY_SKIPS left in the caller's environment
# must not turn a gate run on its own into a recordable skip (need_tool, below).
unexport RELAY_VERIFY_SKIPS
override RELAY_VERIFY_SKIPS :=
endif

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

# The proto gates (ci.yml: the proto job's proto-drift and proto-breaking steps; proto-check
# includes buf lint), skipped with a notice when buf is unavailable — and recorded in verify's
# skip ledger, so the skip reaches verify's last line.
verify-proto:
	@if command -v buf >/dev/null 2>&1; then \
		$(MAKE) proto-check proto-breaking; \
	else \
		echo "verify: SKIPPING proto-check (buf lint, proto drift) and proto-breaking — buf not installed."; \
		echo "verify:   these run in CI regardless. Install with: make proto-tools"; \
		if [ -n "$$RELAY_VERIFY_SKIPS" ]; then \
			echo "verify-proto: buf lint, proto drift and proto-breaking (buf not installed)" >> "$$RELAY_VERIFY_SKIPS"; \
		fi; \
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

lint: fmt-relay lint-relay lint-daemon

## --- proto codegen ---
# Go types are generated (via buf) into relay/internal/relay/v1/ and committed.
# CI runs make proto-tools then make proto for the proto-drift check; Rust types are
# generated at cargo-build time by daemon/build.rs (tonic-build), so there is no
# Rust step here.  The Go generators are `tool` directives in relay/go.mod; only buf needs
# `make proto-tools` before regenerating locally.
proto: proto-tools-check
	cd proto && PATH="$$(go env GOPATH)/bin:$$PATH" buf generate

# Install buf at its pinned version (into $(go env GOPATH)/bin). protoc-gen-go and
# protoc-gen-go-grpc are no longer installed: they are `tool` directives in relay/go.mod,
# run by proto/buf.gen.yaml through `go tool`, so their versions follow the committed
# generated code and cannot be changed from a sibling worktree.
proto-tools:
	go install github.com/bufbuild/buf/cmd/buf@v1.54.0

# The `go install` lines are the ONLY copy of the Makefile's tool pins. The Go proto generators
# are not among them: they are `tool` directives in relay/go.mod (#891), pinned by go.sum and
# built per checkout by `go tool`, so never reintroduce a `go install` line for them. Three consumers read
# that exact line shape and none may be given a second copy: this recipe; ci.yml's cache-key
# step in both the relay and proto jobs (`grep -hE '^\s+go install ' Makefile | sha256sum`); and
# scripts/proto-tools-check.sh below, which parses them and refuses — before any codegen
# runs — if the installed tools disagree (#710: parallel dev-loop worktrees share
# $GOPATH/bin, so one runner's install used to surface on a sibling as a proto-drift diff
# whose entire content was the generator stamp). Reshape this recipe and update all three in
# the same change.
#
# proto-tools-check asserts buf, whose version is not recorded anywhere in
# the generated stamp — nothing else here can catch a wrong buf, and buf's version is what
# decides what `buf lint` and `buf breaking` accept. Silent on success, like proto-check.
proto-tools-check:
	@bash scripts/proto-tools-check.sh

# golangci-lint and the CI-hardening scanners at pinned versions (full module paths
# required). Pinned here rather than in ci.yml so every `go install` pin lives in one
# place: CI keys its cached tool binaries on these lines, so bumping a version rebuilds
# the cache. govulncheck's pin matches security-nightly.yml's GOVULNCHECK_VERSION.
lint-tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
	go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
	go install github.com/zricethezav/gitleaks/v8@v8.30.1
	go install golang.org/x/vuln/cmd/govulncheck@v1.1.4

tools: proto-tools lint-tools

.PHONY: console-snapshots
# Render every Console screen against the test fixtures and write the HTML to
# relay/console-snapshots/ (gitignored). The design canvas is seeded from these so
# the UI is edited from the real pages; re-run after any Console change.
console-snapshots:
	@rm -rf relay/console-snapshots && cd relay && RELAY_CONSOLE_SNAPSHOT_DIR=$(CURDIR)/relay/console-snapshots \
	  go test ./internal/controlplane/console -run TestConsole_WriteScreenSnapshots -count=1 -v 2>&1 | grep -E 'wrote|FAIL|ok ' || true
	@ls relay/console-snapshots

.PHONY: docs-check adr-index
# Documentation gates: ADR numbers are unique, and every test a capability spec
# names in its proof table still exists. Both catch drift that has happened here —
# two files once claimed ADR-0015, and a spec citing tests by name breaks silently
# when one is renamed. Cheap, hermetic, no network.
#
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

# Proves scripts/release-image-guard.sh, the check release.yml runs on the OCI archive before
# it is pushed and signed (#892), refuses a wrong binary digest, a root User, a tampered blob,
# a symlink/hardlink binary, a malformed digest and a binary hidden under a whiteout.
# Hermetic: tiny archives built from tar, jq and sha256sum; no Docker.
test-release-image-guard:
	bash scripts/release-image-guard-test.sh

# Proves scripts/codex-review.sh exits 0 only on a parsed result.verdict, 3 on anything else
# — including the recorded real quota capture (#673) — a refusal with 2, and a killed run
# with 1; that no count it prints can be forged by a hostile payload; and that it stays
# read-only. Hermetic: a stub companion under a throwaway WORKDIR. Needs node and git; no
# Codex CLI, no network (#694).
test-codex-review:
	bash scripts/codex-review-test.sh

# Proves scripts/proto-tools-check.sh fires on a wrong version and on an absent plugin, reads
# the binary `make proto` would actually invoke (GOPATH/bin first, then the ambient PATH,
# never merely whatever happens to be first on the caller's own PATH), and refuses rather
# than passing when it parses no pins from the proto-tools recipe OR meets a recipe line it
# cannot parse (#710). Hermetic: a stub `go` and stub tools under a throwaway WORKDIR, touching
# no real toolchain, installing nothing, deriving the pins from the Makefile so a pin bump
# needs no test edit.
test-proto-tools-check:
	bash scripts/proto-tools-check-test.sh

# Proves scripts/ci-changed-paths.sh runs the code jobs for every docs/ path a Go or Rust test
# reads, skips them only for documentation nothing reads, trips the proto gates on every input
# they depend on, and fails open off a pull request or without a parent commit. Hermetic: bash
# and git against throwaway fixture repos under a mktemp WORKDIR.
test-ci-changed-paths:
	bash scripts/ci-changed-paths-test.sh

# Proves scripts/check-docs.sh's cited-test check covers Go Test/Benchmark/Fuzz names and, in
# proof rows, Rust test fns and cargo-fuzz targets — failing on a name that does not exist, a
# Rust fn that is not a test, or a test only under target/. Hermetic: a throwaway fixture repo
# holding the real script; no Go or Rust toolchain.
test-check-docs:
	bash scripts/check-docs-test.sh

# Proves scripts/smoke-test.sh's mTLS verdict is not vacuous: it passes only when a certless
# Enroll reaches its handler (positive control) AND certless Renew and Tunnel/Open are refused
# by the transport interceptors, and fails when nothing listens or mTLS is off. Hermetic: the
# real script against a stub Relay and a stub curl replaying a recorded real capture. The real
# binary half is test-integration.
test-smoke-test:
	bash scripts/smoke-test-test.sh

# Proves scripts/maintainer-check.sh, the one check every routine runs before a GitHub author's
# text may instruct it (docs/agents/routines.md): it admits exactly role_name
# admin/maintain/write, refuses a non-collaborator, tells a refusal (1) from a check that could
# not run (2), validates the login before any call, and accepts the REST login form the
# commands read (#910); fork PRs and loop replies (the loop marker) produce no action (#918);
# the loop:halt check is REST and fails closed (#924); a review thread a loop reply answered
# without a push is not actionable (#927).
# Hermetic: a stub gh under a throwaway WORKDIR; bash and jq, no token,
# no network.
test-maintainer-check:
	bash scripts/maintainer-check-test.sh

# Proves the Makefile's dev-fleet guards (#893): demo-fault's injection and glob defences,
# the relay-demo-owner refusals, and the STATE_DIR/BASE scrub. Hermetic: a stub docker on
# PATH; no Docker engine, no python.
test-dev-fleet-make:
	bash scripts/dev-fleet-make-test.sh

# Verify no committed generated code drifts from the proto source (ADR-0007).
# Lints /proto first, then runs proto (which regenerates) and fails if relay/internal/relay/v1
# differs.
proto-check: proto-lint proto
	git diff --exit-code -- relay/internal/relay/v1

# buf lint over /proto, by the rules proto/buf.yaml configures (STANDARD, minus the three
# exceptions it records and justifies). Read-only: it reports, it never rewrites /proto.
proto-lint: proto-tools-check
	cd proto && PATH="$$(go env GOPATH)/bin:$$PATH" buf lint

# Additive-only /proto gate (ADR-0014): fail if the working-tree proto breaks wire
# compatibility vs a base git ref. Run from repo root so the `.git` input resolves at
# the repo root; `subdir=proto` points buf at the proto module inside that revision.
# PROTO_BREAKING_REF defaults to origin/main for local use; CI passes the PR base SHA.
PROTO_BREAKING_REF ?= origin/main
proto-breaking: proto-tools-check
	PATH="$$(go env GOPATH)/bin:$$PATH" buf breaking proto \
		--against ".git#ref=$(PROTO_BREAKING_REF),subdir=proto"

## --- Relay (Go) ---
# Emit the actual `relay` binary (into the gitignored relay/bin/), not just a
# compile check. `go build ./...` validates but produces no artifact.
#
# CGO_ENABLED=0 and -trimpath are for the release (release.yml runs this recipe, unchanged):
# the Relay is pure Go (modernc.org/sqlite), so the bytes then depend on neither the runner's
# gcc/glibc nor the checkout path, and the same binary runs in the alpine image. One recipe
# for dev, CI and release; there is no parallel release build path.
build-relay:
	cd relay && CGO_ENABLED=0 go build -trimpath -ldflags "$(GO_LDFLAGS)" -o bin/relay ./cmd/relay

test-relay:
	cd relay && go test ./...

test-relay-race:
	cd relay && go test -race ./...

# Formatting is fmt-relay's job, not this target's: CI runs it as a separate,
# last step so a formatting slip never hides lint and test results.
# --allow-serial-runners: a second golangci-lint on the same host (a parallel worktree) waits
# for the first one's lock instead of failing on it. Runs are serialised, never skipped.
lint-relay:
	cd relay && go vet ./... && golangci-lint run --allow-serial-runners

## --- format-only targets (no compile; fmt-relay is the relay CI job's gofmt step) ---
# fmt-relay fails loudly if any file is unformatted: gofmt -l alone exits 0 even on drift.
# gofmt is invoked out of the running toolchain's GOROOT, not off PATH (#667): the
# GOTOOLCHAIN export at the top re-execs `go` only, so a bare `gofmt` would be
# whatever the host happens to ship, and formatting the tree with one toolchain
# while compiling it with another is the skew #667 is about. The lookup is guarded
# before the path is built, because an absent or half-installed `go` makes
# `$(go env GOROOT)/bin/gofmt` collapse to the absolute `/bin/gofmt` — which on a
# Debian-style host exists and is some other Go's formatter, i.e. exactly that
# skew, passing silently. Resolving once also keeps `test -z` from reading a
# failed formatter's empty output as a clean tree.
fmt-relay:
	@root="$$(go env GOROOT)" || { echo "fmt-relay: go env GOROOT failed — is go on PATH?" >&2; exit 1; }; \
	test -n "$$root" || { echo "fmt-relay: go env GOROOT is empty — is go on PATH?" >&2; exit 1; }; \
	gofmt="$$root/bin/gofmt"; \
	test -x "$$gofmt" || { echo "fmt-relay: no gofmt at $$gofmt" >&2; exit 1; }; \
	unformatted="$$(cd relay && "$$gofmt" -l .)" || exit 1; \
	test -z "$$unformatted" || { printf '%s\n' "$$unformatted" >&2; exit 1; }

fmt-daemon:
	cd daemon && cargo fmt --check

fmt: fmt-relay fmt-daemon

## --- relay-daemon (Rust) ---
# Where build-daemon's `cargo build` leaves the debug relay-daemon, for every target that then
# runs it (gen-opschema, test-integration, test-crossbinary). Cargo honours CARGO_TARGET_DIR
# (and CARGO_BUILD_TARGET_DIR below it), resolving a relative value against the directory it
# runs in — daemon/, since every recipe here does `cd daemon` first. A hardcoded daemon/target/
# made a shared target dir build one binary and then run another, or none at all. Unset, the
# path is the same as before. A target dir set only in a cargo config file is not seen here;
# gen-opschema refuses loudly, and the e2e suites fail, rather than run a stale binary.
DAEMON_TARGET_DIR_RAW := $(or $(CARGO_TARGET_DIR),$(CARGO_BUILD_TARGET_DIR))
DAEMON_TARGET_DIR     := $(if $(DAEMON_TARGET_DIR_RAW),$(if $(filter /%,$(DAEMON_TARGET_DIR_RAW)),$(DAEMON_TARGET_DIR_RAW),$(abspath $(CURDIR)/daemon/$(DAEMON_TARGET_DIR_RAW))),$(CURDIR)/daemon/target)
DAEMON_DEBUG_BIN      := $(DAEMON_TARGET_DIR)/debug/relay-daemon

# The release daemon. RELEASE_DAEMON_TARGET is the only knob: release.yml sets it per
# architecture (x86_64 and aarch64 musl) and asks `print-release-daemon-bin` where the
# result landed, so no workflow hardcodes daemon/target/<triple>/.
RELEASE_DAEMON_TARGET ?= x86_64-unknown-linux-musl
CARGO_HOME_DIR        := $(or $(CARGO_HOME),$(HOME)/.cargo)
# Remap the checkout and CARGO_HOME out of the binary so a rebuild from another path, or by
# another person with another CARGO_HOME, produces the same bytes.
DAEMON_RELEASE_RUSTFLAGS := --remap-path-prefix=$(CURDIR)=/relay-src --remap-path-prefix=$(CARGO_HOME_DIR)=/cargo
DAEMON_RELEASE_BIN    = $(DAEMON_TARGET_DIR)/$(RELEASE_DAEMON_TARGET)/release/relay-daemon

build-daemon:
	cd daemon && $(DAEMON_STAMP) cargo build

# Release artifact for the fleet: small static musl binary (ADR-0007).
# --locked: the build may not move Cargo.lock. CC_<triple>=musl-gcc names the C compiler that
# cc-rs uses for ring, rather than leaving it to cc-rs's per-target fallback, which differs
# between x86_64 and aarch64. RUSTFLAGS here replaces any ambient value; with --target set it
# reaches only the shipped artifact, not build scripts or proc-macros. `-p relay-daemon`
# selects the package by name so the recipe is the same in a single-package manifest and in a
# workspace rooted at daemon/.
build-daemon-release:
	cd daemon && $(DAEMON_STAMP) CC_$(subst -,_,$(RELEASE_DAEMON_TARGET))=musl-gcc RUSTFLAGS="$(DAEMON_RELEASE_RUSTFLAGS)" cargo build --release --locked -p relay-daemon --target $(RELEASE_DAEMON_TARGET)

# Where build-daemon-release leaves its binary (CARGO_TARGET_DIR-safe).
print-release-daemon-bin:
	@echo $(DAEMON_RELEASE_BIN)

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
# Runs the mTLS smoke test (certless refusal, with a positive control) then the
# real-wire Go integration tests (//go:build integration) with the actual
# relay-daemon binary.
# Depends on build so both binaries exist before running.
#
# Two settings make this suite prove what it claims:
#  - RELAY_E2E_REQUIRED=1 turns an e2e test's "binary not set" skip into a failure
#    (relaytest.SkipMissingBin), so a path mistake fails the gate instead of passing it with
#    every real-binary test skipped. A bare `go test` leaves it unset and still skips.
#  - -race: the Relay under test here runs in-process, inside the test binary, so the race
#    detector instruments it directly.
# The cross-binary tests need RELAY_BIN too and run in test-crossbinary, so they are skipped
# here by the same pattern that target selects; without that, the requirement switch would fail them.
CROSSBINARY_TESTS := TestCrossBinary|TestFleetE2E
test-integration: build
	bash scripts/smoke-test.sh
	cd relay && RELAY_E2E_REQUIRED=1 RELAY_DAEMON_BIN=$(DAEMON_DEBUG_BIN) \
		go test -race -tags integration -skip '$(CROSSBINARY_TESTS)' ./cmd/relay/...

# Depends on fmt-daemon rather than repeating it, so `verify` (which also pulls in
# fmt) checks Rust formatting once. CI's daemon job relies on this target for it.
lint-daemon: fmt-daemon
	cd daemon && cargo clippy --all-targets -- -D warnings

## --- opschema golden (ADR-0015: daemon is the single source of truth for what
## it enforces) ---
# Regenerates the golden Operation schema by running the daemon's offline
# `dump-operation-schema` subcommand (same pre-runtime seam as `policy check`)
# and writing its canonical JSON straight to the committed golden. The golden
# MUST live inside relay/internal/opvocab/ (not repo root): opvocab_test.go
# //go:embed's it, and go:embed cannot reach above its own package tree.
#
# The golden is replaced only by a complete, non-empty dump: the schema is written to a temp
# file beside it and renamed into place on success. A plain `>` redirect truncated the
# committed file before the binary ran, so a missing binary left it empty — and the drift
# check then reported that emptying as the change under review.
OPSCHEMA_GOLDEN := $(CURDIR)/relay/internal/opvocab/testdata/operations.schema.json
gen-opschema: build-daemon
	@test -x "$(DAEMON_DEBUG_BIN)" || { echo "gen-opschema: FAIL no relay-daemon at $(DAEMON_DEBUG_BIN) (CARGO_TARGET_DIR?); golden left untouched" >&2; exit 1; }
	@tmp="$$(mktemp "$(OPSCHEMA_GOLDEN).XXXXXX")" || exit 1; trap 'rm -f "$$tmp"' EXIT; \
	"$(DAEMON_DEBUG_BIN)" dump-operation-schema > "$$tmp" \
		|| { echo "gen-opschema: FAIL dump-operation-schema exited non-zero; golden left untouched" >&2; exit 1; }; \
	test -s "$$tmp" || { echo "gen-opschema: FAIL dump-operation-schema printed nothing; golden left untouched" >&2; exit 1; }; \
	chmod 644 "$$tmp" && mv -f "$$tmp" "$(OPSCHEMA_GOLDEN)" \
		&& echo "gen-opschema: wrote $(OPSCHEMA_GOLDEN) from $(DAEMON_DEBUG_BIN)"

## --- #112 dev-harness cross-binary CI machinery ---
# Kept OUT of build/test/lint: build-relay-devharness produces a non-shippable
# binary (the devharness dispatch/control backdoor, ADR-relevant — see
# relay/cmd/relay/devharness.go), and test-crossbinary needs both real
# binaries and is non-hermetic, matching the existing test-integration
# exclusion above.

# The devharness-tagged relay binary: never the shippable relay/bin/relay. Built with -race:
# its one consumer is test-crossbinary, where the Relay under test is this subprocess, not
# the test binary, so the race detector reaches the Relay only if it is compiled in here.
# The test harness fails a test whose Relay log carries a race report.
build-relay-devharness:
	cd relay && go build -race -tags devharness -o bin/relay-devharness ./cmd/relay

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
# RELAY_E2E_REQUIRED and -race as in test-integration: a missing binary fails rather than
# skips, and the test binary's own half (the harness client) runs under the race detector too.
test-crossbinary: build-daemon build-relay-devharness
	cd relay && RELAY_E2E_REQUIRED=1 RELAY_BIN=$(CURDIR)/relay/bin/relay-devharness \
		RELAY_DAEMON_BIN=$(DAEMON_DEBUG_BIN) \
		go test -race -tags integration -run '$(CROSSBINARY_TESTS)' ./cmd/relay/...

## --- vulnerability scanning ---
# Nightly over the whole tree (non-blocking, files a tracking issue), and on a pull request
# only when it changes a dependency manifest or lockfile (ci.yml: the relay job, gated on
# scripts/ci-changed-paths.sh's deps=). Install: make lint-tools (govulncheck is pinned there).
vuln-relay:
	cd relay && govulncheck ./...

# The pull-request form: fails only on a reachable vulnerability that
# relay/govulncheck-exceptions.txt does not list, or on a listed one the scan no longer
# reports. vuln-relay above (nightly) still reports everything. See scripts/vuln-gate.sh.
vuln-relay-gate:
	$(call need_tool,govulncheck,vuln-relay-gate,make lint-tools)
	bash scripts/vuln-gate.sh

# vuln-gate.sh's verdicts, proved against fixture govulncheck streams. Hermetic: bash + jq.
test-vuln-gate:
	bash scripts/vuln-gate-test.sh

# Install: cargo install cargo-audit --version 0.22.2 --locked # pinned for supply-chain reproducibility
vuln-daemon:
	cd daemon && cargo audit

## --- CI hardening: shell, workflow, secrets and dependency-policy gates ---
# Each runs as a step of a job CI already has (ci.yml), so it costs seconds, not a job.
#
# need_tool: run a gate's command only if its tool is installed. Under `make verify` a missing
# tool is a recorded skip (the skip ledger above), so a contributor without zizmor still gets
# an honest verdict; anywhere else — CI included — a missing tool FAILS, so an install step
# that broke can never turn into a gate that quietly passed.
#   $(call need_tool,<binary>,<gate name>,<how to install>)
define need_tool
	@command -v $(1) >/dev/null 2>&1 || { \
		if [ -n "$$RELAY_VERIFY_SKIPS" ]; then \
			echo "verify: SKIPPING $(2) — $(1) not installed (CI runs it; install: $(3))"; \
			echo "$(2) ($(1) not installed)" >> "$$RELAY_VERIFY_SKIPS"; \
			exit 0; \
		fi; \
		echo "$(2): $(1) is not installed (install: $(3))" >&2; exit 1; \
	}
endef

ZIZMOR_VERSION := 1.30.1
CARGO_DENY_VERSION := 0.20.2

lint-ci: lint-shell lint-actions lint-zizmor

# shellcheck over every tracked shell script, at warning severity and above. Several of
# these scripts ARE CI gates (the changed-paths classifier decides which jobs run at all),
# so a quoting bug in one is a gate that silently stops gating. shellcheck ships on the
# GitHub-hosted runner image; locally: apt install shellcheck, or pip install shellcheck-py.
lint-shell:
	$(call need_tool,shellcheck,lint-shell,apt install shellcheck)
	@if command -v shellcheck >/dev/null 2>&1; then \
		git ls-files -z '*.sh' | xargs -0 shellcheck -S warning; \
	fi

# actionlint: workflow syntax, expression types, and (with shellcheck on PATH) the shell in
# every `run:` block.
lint-actions:
	$(call need_tool,actionlint,lint-actions,make lint-tools)
	@if command -v actionlint >/dev/null 2>&1; then actionlint; fi

# zizmor: workflow security — template injection, over-broad permissions, credential
# persistence, cache poisoning of release builds. With GH_TOKEN set (CI) it also runs its
# online audits (impostor commits, known-vulnerable pinned actions). Every finding at low
# severity and above fails; the help-level self-repository hint is style.
lint-zizmor:
	$(call need_tool,zizmor,lint-zizmor,make zizmor-tool)
	@if command -v zizmor >/dev/null 2>&1; then \
		if [ -n "$$GH_TOKEN" ]; then zizmor --min-severity low .github/; \
		else env -u GH_TOKEN zizmor --offline --min-severity low .github/; fi; \
	fi

# zizmor is a Python package; pipx keeps it out of the system interpreter (PEP 668).
zizmor-tool:
	pipx install --force zizmor==$(ZIZMOR_VERSION)

# gitleaks over every tracked file in the working tree (default rules plus .gitleaks.toml's
# reviewed allowlists). Tracked files only, via a staging copy: a build tree's binaries are
# not what a commit would leak. Scanned from inside the copy so reported paths are
# repo-relative, which is what the allowlists' anchored path patterns match. Findings are
# redacted in the output.
secrets-scan:
	$(call need_tool,gitleaks,secrets-scan,make lint-tools)
	@if command -v gitleaks >/dev/null 2>&1; then \
		tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && \
		git ls-files -z | tar --null -T - -cf - | tar -xf - -C "$$tmp" && \
		cd "$$tmp" && gitleaks dir . --config "$(CURDIR)/.gitleaks.toml" --redact --no-banner; \
	fi

# The whole git history (security-nightly.yml): a secret committed and then deleted in a
# later commit is still in the history every clone carries. Needs a full-depth checkout.
secrets-scan-history:
	$(call need_tool,gitleaks,secrets-scan-history,make lint-tools)
	gitleaks git . --config .gitleaks.toml --redact --no-banner

# cargo-deny's offline policy for the root daemon (daemon/deny.toml): licences, banned crates
# (a second crypto stack), and allowed sources. Runs on every daemon change.
deny-daemon:
	$(call need_tool,cargo-deny,deny-daemon,make deny-tool)
	@if command -v cargo-deny >/dev/null 2>&1; then \
		cd daemon && cargo deny --locked check bans licenses sources; \
	fi

# Known advisories against the daemon's dependency tree. Network (the RustSec database), so
# CI runs it on a pull request only when the dependencies changed (deps=), like vuln-relay;
# the nightly `cargo audit` covers the rest.
deny-daemon-advisories:
	$(call need_tool,cargo-deny,deny-daemon-advisories,make deny-tool)
	cd daemon && cargo deny --locked check advisories

deny-tool:
	cargo install cargo-deny --version $(CARGO_DENY_VERSION) --locked

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
#
# One recipe line per FUZZ_DAEMON_TARGETS entry (the foreach ends each with a newline), so the
# list above is the only place a target is named and make still stops at the first crasher.
define fuzz_daemon_newline


endef
fuzz-daemon:
	$(if $(FUZZ_GROWN_CORPUS),mkdir -p $(addprefix $(FUZZ_GROWN_CORPUS)/,$(FUZZ_DAEMON_TARGETS)))
	$(foreach t,$(FUZZ_DAEMON_TARGETS),cd daemon && cargo +nightly fuzz run $(t) $(call fuzz_corpus,$(t)) -- $(FUZZ_FLAGS)$(fuzz_daemon_newline))

## --- local dev fleet (DEV-ONLY; Docker + Compose >= 2.18) ---
# The laptop fleet (docs/dev-fleet.md) and its nine-Node demo (docs/operations/demo-fleet.md).
# Never in build/test/lint or CI: the hermetic gate must never depend on Docker.
# - One fixed project, relay-demo: docker-compose.demo.yml names it, and -p pins it against
#   a stray COMPOSE_PROJECT_NAME. Three Nodes by default, nine under --profile demo.
# - The overlay is named on every down/logs, so an IdP from an OAuth run goes with the
#   fleet; that is why even the plain targets need Compose >= 2.18 (`!reset`).
# - The approval gate is chosen per target here, not by the caller's shell or .env.
# - Startup waits in two steps, so --wait never covers the init one-shot (it exits, and
#   older Compose fails `up --wait` on any exited container).
RELAY_DEMO_COMPOSE := docker compose -p relay-demo -f docker-compose.demo.yml
DEV_GATE  := DEV_FLEET_APPROVAL_GATE_CONFIG=/etc/relay/approval-gates.json
DEMO_GATE := DEV_FLEET_APPROVAL_GATE_CONFIG=/etc/relay/approval-gates.demo.json
DEV_COMPOSE        := $(DEV_GATE) $(RELAY_DEMO_COMPOSE)
DEMO_COMPOSE       := $(DEMO_GATE) $(RELAY_DEMO_COMPOSE) --profile demo
DEMO_OAUTH_COMPOSE := $(DEMO_GATE) $(RELAY_DEMO_COMPOSE) -f docker-compose.oauth.yml --profile demo
ALL_COMPOSE        := $(RELAY_DEMO_COMPOSE) -f docker-compose.oauth.yml --profile demo
DEMO_WAIT_SECONDS ?= 240
# Must match ROSTER's role=web entries in daemon/tests/dev_fleet_fixtures.rs (a test checks).
DEMO_WEB_NODES := daemon-1 daemon-2 daemon-4 daemon-5 daemon-6 daemon-9
# DEMO_FAULT_NODES overrides the default fault targets; e.g.
# `make demo-fault DEMO_FAULT_NODES="daemon-2 daemon-9"`. Exported, not spliced into the
# recipe text: Make hands it to the recipe's shell as a real environment variable, so a
# value carrying a shell metacharacter (';', a backtick, '$(') reaches the recipe as an
# opaque string, never as text a shell re-parses (#622 security review S2).
export DEMO_FAULT_NODES ?= daemon-4 daemon-6
# dev-fleet-mcp.sh reads STATE_DIR and BASE from the environment; a leftover value would
# redirect where credentials are written or which Relay they are sent to, so every call
# from here scrubs both (#622 security review S4).
DEV_FLEET_MCP := env -u STATE_DIR -u BASE bash scripts/dev-fleet-mcp.sh

# relay-demo is one project per Docker engine, but this repo is checked out into many
# worktrees. Refuse a non-local engine (DOCKER_HOST or the docker context), and any
# relay-demo container brought up from a different checkout. Read-only `docker ps`, never
# `docker compose`. Paths are compared physically (`pwd -P`): Compose records the logical cwd.
# If that checkout is gone, `down` from here (docs/dev-fleet.md, Troubleshooting).
relay-demo-owner:
	@set -eu; here=$$(pwd -P); \
	case "$${DOCKER_HOST:-unix://}" in unix://*) ;; \
	  *) echo "refusing: DOCKER_HOST points at a non-local engine ('$$DOCKER_HOST')" >&2; exit 2;; esac; \
	case "$$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null || true)" in unix://*) ;; \
	  *) echo "refusing: the current docker context is not a local engine" >&2; exit 2;; esac; \
	dirs=$$(docker ps -a --filter label=com.docker.compose.project=relay-demo \
	  --format '{{.Label "com.docker.compose.project.working_dir"}}') \
	  || { echo "refusing: could not list relay-demo containers (docker ps failed)" >&2; exit 2; }; \
	printf '%s\n' "$$dirs" | sort -u | while IFS= read -r d; do \
	  [ -z "$$d" ] && continue; \
	  [ "$$(cd "$$d" 2>/dev/null && pwd -P)" = "$$here" ] || { \
	    echo "refusing: relay-demo is running from another checkout at '$$d' (this checkout is '$$here'); stop it there first, or run this from that checkout" >&2; exit 2; }; \
	done

# Refuse to `up` in the other mode: the plain and OAuth fleets put the Relay's ports on
# different containers, so Compose would recreate relay and then fail to bind. $(1) is plain|oauth.
define relay_demo_mode
	@set -eu; s=$$(docker ps -a --filter label=com.docker.compose.project=relay-demo \
	  --format '{{.Label "com.docker.compose.service"}}') \
	  || { echo "refusing: docker ps failed" >&2; exit 2; }; \
	if printf '%s\n' "$$s" | grep -qx relay-netns; then have=oauth; \
	elif printf '%s\n' "$$s" | grep -qx relay; then have=plain; else have=none; fi; \
	[ "$$have" = none ] || [ "$$have" = $(1) ] || { \
	  echo "refusing: relay-demo is up in $$have mode; run 'make demo-down' first" >&2; exit 2; }
endef

# Step 2 waits for health on everything but the one-shot. $(1) is the compose command.
define relay_demo_wait
	$(1) up -d --no-build --pull never --no-deps --no-recreate --wait --wait-timeout $(DEMO_WAIT_SECONDS) $$($(1) config --services | grep -vx init)
endef

# Step 1 runs init to completion (every daemon depends on it) and starts the daemons.
define relay_demo_up
	$(1) up -d --no-build --pull never
	$(call relay_demo_wait,$(1))
endef

define relay_demo_reset
	@imgs=$$($(1) config --images) && [ -n "$$imgs" ] && docker image inspect $$imgs >/dev/null \
	  || { echo "demo-reset: an image is missing; run 'make demo-build' (nothing was touched)" >&2; exit 1; }
	$(ALL_COMPOSE) down -v --remove-orphans --timeout 5
	$(call relay_demo_up,$(1))
	$(DEV_FLEET_MCP) init
	@echo "demo-reset: reset complete — init exited 0, every service is healthy, .dev-fleet/ holds the fresh credentials."
	@echo "demo-reset: the CA was regenerated, so a registered MCP client still holds the OLD bearer token AND the OLD CA (NODE_EXTRA_CA_CERTS is read only at process start). Restart it — .dev-fleet/ is already current, so there is no need to run 'make demo-creds' again first:"
	@echo "demo-reset:   claude mcp remove relay"
endef

dev-fleet-up: relay-demo-owner
	$(call relay_demo_mode,plain)
	$(DEV_COMPOSE) up --build -d
	$(call relay_demo_wait,$(DEV_COMPOSE))

dev-fleet-down: relay-demo-owner
	$(ALL_COMPOSE) down

dev-fleet-logs:
	$(ALL_COMPOSE) logs -f

# Export the fleet's CA cert and BOTH control-plane credentials (the founding admin's and
# dev-approver's) to the gitignored ./.dev-fleet/ so a host-side MCP client or
# scripts/dev-fleet-mcp.sh can reach the control plane over VERIFIED TLS. This mints
# nothing: it is a `docker compose cp` read out of the exited `init` container. `init`
# re-mints on every `compose up` (a stopped one-shot is started again), including a plain
# `demo-up`; run this after either `demo-reset` or `demo-up` to pick up the latest.
dev-fleet-creds: relay-demo-owner
	$(DEV_FLEET_MCP) init

demo-creds: dev-fleet-creds

# `demo-reset` NEVER builds — run `demo-build` first (and again after any code change).
demo-build: relay-demo-owner
	$(DEMO_COMPOSE) build
	$(DEMO_OAUTH_COMPOSE) pull --ignore-buildable --policy missing

demo-reset: relay-demo-owner
	$(call relay_demo_reset,$(DEMO_COMPOSE))
	@echo "demo-reset:   claude mcp add --transport http relay https://relay:9443/mcp --header \"Authorization: Bearer \$$(cat .dev-fleet/control-credential)\""

# The registration that signs Claude Code in through the IdP instead of a bearer token
# (docs/operations/demo-fleet.md, "Signing in as a human over OAuth"). The client id and
# callback port are the realm fixture's (docker/fixtures/keycloak/relay-demo-realm.json).
define oauth_hint
	@echo "demo-reset:   claude mcp add --transport http --client-id relay-demo-claude-code --callback-port 33418 relay https://relay:9443/mcp"
	@echo "demo-reset: then start Claude Code with NODE_EXTRA_CA_CERTS=\"\$$PWD/.dev-fleet/ca-cert.pem\", run /mcp, pick relay, Authenticate, and sign in as demo-user / dev-only-demo-user (DEV-ONLY)."
endef

demo-reset-oauth: relay-demo-owner
	$(call relay_demo_reset,$(DEMO_OAUTH_COMPOSE))
	$(oauth_hint)

# Bring the demo fleet back up after `demo-down` WITHOUT wiping any volume: no `-v`, no
# build. With `--pull never` the only loud failure is a missing image — run `demo-build`
# once first. This is NOT "no credential mint": `init` re-runs (see `dev-fleet-creds`).
demo-up: relay-demo-owner
	$(call relay_demo_mode,plain)
	$(call relay_demo_up,$(DEMO_COMPOSE))
	@echo "demo-up: relay-demo is up and healthy (no volume touched). init re-ran and re-minted; run 'make demo-creds' to refresh .dev-fleet/."

# The same two, with the opt-in OAuth overlay (docker-compose.oauth.yml, #351): a
# DEV-ONLY Keycloak identity provider, and the Relay's OAuth resource-server half turned
# on, so an MCP client can sign in as a human. `demo-build`'s pull names the overlay, so it
# fetches the IdP's image too.
demo-up-oauth: relay-demo-owner
	$(call relay_demo_mode,oauth)
	$(call relay_demo_up,$(DEMO_OAUTH_COMPOSE))
	@echo "demo-up: relay-demo is up and healthy with OAuth (no volume touched). init re-ran and re-minted; run 'make demo-creds' to refresh .dev-fleet/."
	@echo "demo-up: OAuth is on. A Claude Code already signed in stays signed in (the IdP's sessions survive down/up); to register one:"
	$(oauth_hint)

demo-down: relay-demo-owner
	$(ALL_COMPOSE) down

# Kill the demo service on each target Node (default daemon-4 and daemon-6: one env=prod
# and one env=staging web Node). `-f` disables globbing of the exported value, which is
# read as $$DEMO_FAULT_NODES and validated against the role=web Nodes before any exec.
# Kill by pidof, not the pidfile: a stale pidfile cannot redirect the kill. `exec` names
# --profile demo because daemon-4..9 are profile-gated, and no gate because it recreates
# nothing.
demo-fault: relay-demo-owner
	@set -euf; \
	[ -n "$$DEMO_FAULT_NODES" ] || { echo "demo-fault: DEMO_FAULT_NODES is empty" >&2; exit 2; }; \
	for n in $$DEMO_FAULT_NODES; do case " $(DEMO_WEB_NODES) " in *" $$n "*) ;; \
	  *) echo "demo-fault: refusing $$n: not a role=web Node, so it runs no demo service" >&2; exit 2;; esac; done; \
	for n in $$DEMO_FAULT_NODES; do \
	  $(RELAY_DEMO_COMPOSE) --profile demo exec -T $$n sh -c 'pids="$$(pidof httpd 2>/dev/null || true)"; [ -z "$$pids" ] || kill $$pids; exit 0'; \
	  i=0; while :; do rc=0; $(RELAY_DEMO_COMPOSE) --profile demo exec -T $$n /usr/local/bin/dev-fleet-service status >/dev/null 2>&1 || rc=$$?; \
	    [ $$rc -eq 3 ] && break; i=$$((i+1)); [ $$i -ge 5 ] && { echo "$$n: httpd still answering after kill" >&2; exit 1; }; sleep 1; done; \
	  echo "$$n: dev-fleet demo service DOWN (dev-fleet-service status: exit 3)"; done

# relay/bin/ holds build-relay's and build-relay-devharness's output, which `go clean` does not
# know about; it is gitignored, so nothing tracked lives there.
clean:
	cd relay && go clean ./... || true
	rm -rf relay/bin
	cd daemon && cargo clean || true
