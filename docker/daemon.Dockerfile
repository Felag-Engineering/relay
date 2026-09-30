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
# dev fleet reports the unstamped fallback (`<Cargo.toml numeric core>-0.dev`, commit
# and build date "unknown"), which is honest for a dev image and keeps that
# fallback path exercised. A real release artifact must be produced by
# `make build-daemon-release`, which derives and passes the stamp — see
# docs/operations/version-stamping.md.

# ---- build stage: compile the relay-daemon (Rust) as a musl static binary -----
# rust:1 (latest stable) satisfies daemon/Cargo.toml's `rust-version` floor by
# construction (#667). The one way that can now fail is a stale locally-cached
# rust:1 older than the MSRV, which cargo reports by name; `docker build --pull`
# is the fix. CI always pulls fresh.
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

# Bake the Policy fixtures in. COPY --chmod lands each file owned by root:root
# (UID/GID 0) with the mode forced in the same layer — load-bearing, not
# style: a dev laptop's umask commonly leaves a checked-out file
# group-writable, which the daemon's fail-closed loader rejects (it refuses
# any group/world-writable Policy). `--chmod=` gives that guarantee in one
# layer, exactly as docker/relay.Dockerfile already does. Baking the Policy in
# — rather than bind-mounting from the host, where the file would be owned by
# an unprivileged user and rejected — is the ADR-0002 "Policy arrives with the
# image, never over the wire" option.
#
# There are now THREE Policy fixtures, all baked into this one image; compose
# picks which one each daemon reads via RELAY_POLICY_PATH (docker-compose.demo.yml).
# The daemon loads only the one file its own RELAY_POLICY_PATH names, so a
# fixture baked in but unread by the default (non-demo) profile changes
# nothing about that profile's behaviour:
#   - policy.web.toml — the `role=web` Nodes: demo service allow (structured
#     service.restart + the dev-fleet-service raw-exec allow) plus the demo
#     Template pack's vocabulary.
#   - policy.db.toml — the `role=db` Nodes: neither the demo service allow nor
#     the Template vocabulary; deny-by-default refuses the repair here.
#   - policy.bastion.toml — the `role=bastion` Node, demo-profile only: the
#     narrowest of the three — exactly one `file.read` path, no
#     `service.restart`, and no `[raw_exec]` section at all.
# The daemon has no Policy include mechanism, so divergence means separate
# files rather than one.
COPY --chmod=0644 docker/fixtures/policy.web.toml     /etc/relay-daemon/policy.web.toml
COPY --chmod=0644 docker/fixtures/policy.db.toml      /etc/relay-daemon/policy.db.toml
COPY --chmod=0644 docker/fixtures/policy.bastion.toml /etc/relay-daemon/policy.bastion.toml

# The demo Template pack (#389) — loaded and Policy-enforced on every Node
# (one image, one vocabulary; only Policy diverges), but not yet dispatchable
# (#626). The template loader is fail-closed and WHOLE-SET exactly like the
# Policy loader (TemplateSet::load, ADR-0002's trust root applies to templates
# verbatim), which is why the mode is forced here exactly as for the Policy
# above — a bad mode on this one file would empty the Node's entire template
# vocabulary rather than merely dropping this pack.
COPY --chmod=0644 docker/fixtures/templates.d/relay-demo/catalog.toml /etc/relay-daemon/templates.d/relay-demo/catalog.toml

# The demo service (#389): a root-owned script that manages a real
# `busybox httpd` on the `role=web` Nodes (docker/daemon-entrypoint.sh starts
# it), reachable through the Raw Exec allow in policy.web.toml and, via the
# systemctl shim below, through `service.restart`.
COPY --chmod=0755 docker/fixtures/dev-fleet-service /usr/local/bin/dev-fleet-service
COPY --chmod=0644 docker/fixtures/www/index.html /srv/dev-fleet-service/www/index.html
RUN mkdir -p /var/lib/dev-fleet-service && chmod 0755 /var/lib/dev-fleet-service

# DEV-ONLY: a systemctl stand-in so the Native `service.restart` Operation can
# restart the demo service on the `role=web` Nodes (docker/fixtures/systemctl-shim
# says what it does and does not fake). Baked OFF the PATH on purpose: the one
# image serves every Node, and docker/daemon-entrypoint.sh links it to
# /usr/local/bin/systemctl only where RELAY_NODE_LABELS says role=web. On the db
# and bastion Nodes there is still no systemctl to spawn.
COPY --chmod=0755 docker/fixtures/systemctl-shim /usr/local/lib/dev-fleet-service/systemctl

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
