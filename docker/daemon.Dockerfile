# relay-daemon image for the local dev fleet (docs/dev-fleet.md). DEV-ONLY
# packaging — not a production deployment artifact. Build context is the repo
# root so the builder can see BOTH /daemon and /proto (build.rs compiles the
# proto contract from ../proto relative to /daemon).
#
# There is no host Rust toolchain assumption: the daemon is compiled inside this
# image as a musl static binary, using the same target as the CI release-build
# job.
#
# NOT a release recipe. It deliberately does NOT build-stamp the binary (issue
# #249): the build below sets no RELAY_BUILD_* variables, so the daemon in the
# dev fleet reports the unstamped fallback (`<Cargo.toml version>-dev`, commit
# and build date "unknown"), which is honest for a dev image and keeps that
# fallback path exercised. A real release artifact must be produced by
# `make build-daemon-release`, which derives and passes the stamp — see
# docs/operations/version-stamping.md.

# ---- build stage: compile the relay-daemon (Rust) as a musl static binary -----
FROM rust:1-bookworm AS build

# musl-tools provides the musl linker; add the musl target. build.rs uses
# protoc_bin_vendored, so NO system protoc is required.
RUN apt-get update \
    && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add x86_64-unknown-linux-musl

WORKDIR /src
# /proto must be present for build.rs (it resolves ../proto from /src/daemon).
COPY proto/ ./proto/
COPY daemon/ ./daemon/

# Same profile and target as `make build-daemon-release`, but intentionally
# UNSTAMPED (see the header): no RELAY_BUILD_* here, so this is a dev-fleet
# binary, not a release artifact.
RUN cd daemon && cargo build --release --target x86_64-unknown-linux-musl

# ---- final stage: minimal runtime image ---------------------------------------
# busybox:stable-musl ships sh (for the entrypoint) + test (for the enrollment
# healthcheck). The musl static binary needs no libc.
FROM busybox:stable-musl

COPY --from=build \
    /src/daemon/target/x86_64-unknown-linux-musl/release/relay-daemon \
    /usr/local/bin/relay-daemon

# Bake the Policy fixture in. COPY lands it owned by root:root (UID/GID 0), which
# satisfies the daemon's fail-closed owner check. The explicit chmod 0644 is
# load-bearing: COPY preserves the host file's mode bits, and a dev laptop's
# umask commonly leaves files group-writable — which the loader rejects (it
# refuses any group/world-writable Policy). Forcing 0644 here makes the image
# correct regardless of the builder's umask. Baking the Policy in — rather than
# bind-mounting from the host, where the file would be owned by an unprivileged
# user and rejected — is the ADR-0002 "Policy arrives with the image, never over
# the wire" option.
COPY docker/fixtures/policy.toml /etc/relay-daemon/policy.toml
RUN chmod 0644 /etc/relay-daemon/policy.toml

# busybox ships no /etc/os-release; bake one in so the documented
# list_operations file.read example (path=/etc/os-release) succeeds on the
# dev fleet (docs/dev-fleet.md). DEV-ONLY fixture.
COPY docker/fixtures/os-release /etc/os-release

# The entrypoint lifts the bootstrap-minted Enrollment Token file into the env
# var the daemon reads, then execs the daemon (see docker/daemon-entrypoint.sh).
# chmod so the exec-form ENTRYPOINT works regardless of the host file's mode.
COPY docker/daemon-entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
