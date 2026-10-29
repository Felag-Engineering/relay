# Relay image. Build context is the repo root so the builder can see /relay.
#
# Three targets:
#
#   dev-fleet  DEV-ONLY, and only when named (`target: dev-fleet`, as every
#              Relay build in deploy/test and deploy/demo does): the runtime image
#              plus curl (for the `init` one-shot). Unprivileged, like runtime;
#              it carries no fixture, because the fleet's relay.toml and gate
#              files arrive as a read-only mount (docs/dev-fleet.md).
#   release    the PUBLISHED image (ghcr.io/felag-engineering/relay, built by
#              .github/workflows/release.yml). Its binary is not compiled
#              here: it is the released, rebuild-verified one, supplied as the
#              named build context `release-binary`. Unprivileged, like runtime.
#              deploy/production/docker-compose.yml pins this published image by
#              digest: the single-host deployment in
#              docs/operations/relay-install.md, section 7.
#   runtime    the LAST stage, so the default for a build that names no
#              target: the Relay and nothing else, as an unprivileged user,
#              compiled from this checkout: what a local build gets, and no
#              committed stack runs it. No fixture, gate rule or credential is
#              baked into it.

# ---- build stage: compile the Relay (Go) as a static binary --------------------
# golang:1.26-bookworm is a CEILING, and only that: the in-image `go build` below
# never sees the Makefile, so nothing here exports GOTOOLCHAIN (#667). The
# floating 1.26 tag simply can never be 1.27, and if the image ships a 1.26.x
# older than relay/go.mod's `go` directive the go command downloads the named
# toolchain at image-build time.
FROM golang:1.26-bookworm AS build

WORKDIR /src
COPY relay/ ./relay/

# CGO_ENABLED=0: the Relay's SQLite store is pure-Go (modernc.org/sqlite), so the
# binary needs no libc and runs on a musl/scratch base. -trimpath keeps the build
# reproducible and free of local path leakage.
RUN cd relay && CGO_ENABLED=0 go build -trimpath -o /out/relay ./cmd/relay

# ---- os stage: what every target below shares, minus the binary ---------------
# alpine rather than busybox: the compose healthcheck completes a real TLS
# handshake with each listener, and both listeners are TLS 1.3 only — busybox's
# ssl_client stops at 1.2. openssl s_client does 1.3 and verifies the chain
# against the Relay's own CA. The static Go binary needs no libc.
#
# Pinned by digest: this is the only base that reaches the published image (the
# golang builder above never ships). Dependabot's docker ecosystem refreshes the
# tag and digest together (.github/dependabot.yml).
FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS os

RUN apk add --no-cache openssl

# 7654 = node-plane gRPC (relay-daemon dial-home); 9443 = control-plane HTTPS
# (MCP + /api/v1). Distinct listeners, published to distinct host ports by
# compose — listener separation is honored end to end.
EXPOSE 7654 9443

# The Relay reads /etc/relay/relay.toml, mounted read-only by the compose file that
# runs the image, and nothing from the environment (ADR-0043).
ENTRYPOINT ["/usr/local/bin/relay"]

# ---- unprivileged: os plus the non-root user, still without a binary ----------
# The container expression of relay/packaging/relay.service's `User=relay`: the
# Relay needs no privilege, so it does not run as root, and its start-time check
# refuses a root process. The UID/GID are fixed so that a relay.toml or secret
# file mounted in can be group-owned by a known number on the host: root:10001,
# mode 0640, which the Relay accepts (ADR-0043).
#
# /var/lib/relay is created 0700 and owned by that user, so a fresh named
# volume mounted there inherits both — the CA key under it is the most
# sensitive file in the deployment (docs/operations/ca-disaster-recovery.md).
# /etc/relay is root-owned 0755, so the ancestor of every mounted configuration
# file is a directory the image defines and the Relay cannot write. Every target
# below builds on this stage, so none can drift apart in posture; they differ
# only in where the binary comes from.
FROM os AS unprivileged

RUN addgroup -S -g 10001 relay \
 && adduser -S -D -H -u 10001 -G relay -s /sbin/nologin relay \
 && install -d -o relay -g relay -m 0700 /var/lib/relay \
 && install -d -o root -g root -m 0755 /etc/relay

USER 10001:10001

# ---- base stage: unprivileged plus the binary compiled above ------------------
FROM unprivileged AS base

COPY --from=build /out/relay /usr/local/bin/relay

# ---- dev-fleet: DEV-ONLY, selected by name ---------------------------------
# The dev and demo fleets run the Relay unprivileged, like runtime, because the
# Relay's start-time check refuses root. A one-shot that needs root says so with
# `user: "0:0"` in the fleets' compose files (relay-config does).
FROM base AS dev-fleet

# The dev fleet's `init` one-shot calls the Control API over TLS 1.3, which
# busybox wget cannot do. The long-running dev-fleet `relay` container shares
# this stage, so it carries curl too. No other stage gets it.
USER root
RUN apk add --no-cache curl
USER 10001:10001

# ---- release-binary: empty on purpose ----------------------------------------
# release.yml overrides this with `--build-context release-binary=<dir>`. A
# `--target release` build without it fails at the COPY below, rather than
# quietly compiling and shipping a binary nobody rebuild-verified.
FROM scratch AS release-binary

# ---- release: the published image ---------------------------------------------
# The binary is the one the release job built twice and compared byte for byte
# and listed in the signed SHA256SUMS. COPY lands it root:root regardless of USER.
FROM unprivileged AS release

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=unknown
ARG REVISION=unknown

LABEL org.opencontainers.image.source="https://github.com/Felag-Engineering/relay" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

COPY --from=release-binary --chmod=0755 relay-${TARGETOS}-${TARGETARCH} /usr/local/bin/relay

# ---- runtime: the build-from-checkout target, and the LAST stage ---------------
# Last on purpose: a build that names no target gets this fixture-free,
# non-root image, never the dev fleet's.
FROM base AS runtime
