# Relay image. Build context is the repo root so the builder can see /relay.
#
# Three targets:
#
#   dev-fleet  DEV-ONLY, and only when named (`target: dev-fleet`, as every
#              Relay build in docker-compose.demo.yml does): it adds the dev
#              and demo fleets' approval-gate fixtures and curl (for the
#              `init` one-shot) and runs as root,
#              exactly as this image did before the split (docs/dev-fleet.md).
#   release    the PUBLISHED image (ghcr.io/felag-engineering/relay, built by
#              .github/workflows/release.yml, #892). Its binary is not compiled
#              here: it is the released, rebuild-verified one, supplied as the
#              named build context `release-binary`. Unprivileged, like runtime.
#   runtime    the LAST stage, so the default for a build that names no
#              target: the Relay and nothing else, as an unprivileged user,
#              compiled from this checkout. deploy/compose/docker-compose.yml
#              builds it until it pins the published image by digest — the
#              single-host deployment in docs/operations/relay-install.md,
#              section 7. No fixture, gate file or credential is baked into it.

# ---- build stage: compile the Relay (Go) as a static binary --------------------
# golang:1.25-bookworm is a CEILING, and only that: the in-image `go build` below
# never sees the Makefile, so nothing here exports GOTOOLCHAIN (#667). The
# floating 1.25 tag simply can never be 1.26, and if the image ships a 1.25.x
# older than relay/go.mod's `go` directive the go command downloads the named
# toolchain at image-build time.
FROM golang:1.25-bookworm AS build

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

# All configuration is supplied as RELAY_* environment by the compose file
# that runs the image.
ENTRYPOINT ["/usr/local/bin/relay"]

# ---- base stage: os plus the binary compiled above --------------------------
FROM os AS base

COPY --from=build /out/relay /usr/local/bin/relay

# ---- dev-fleet: DEV-ONLY, selected by name ---------------------------------
# FROM base, not FROM runtime: the dev and demo fleets run the Relay as root,
# as they always have, and their one-shots rely on it. Only a build that asks
# for it by name (`target: dev-fleet`, as every Relay build in
# docker-compose.demo.yml does) gets this stage and its fixtures.
FROM base AS dev-fleet

# The dev fleet's `init` one-shot calls the Control API over TLS 1.3, which
# busybox wget cannot do. The long-running dev-fleet `relay` container shares
# this stage, so it carries curl too (dev-only, root, already has openssl). No
# other stage gets it.
RUN apk add --no-cache curl

# The approval gate (ADR-0027) arrives WITH THE IMAGE, never over the wire —
# the same posture as the daemon's Policy file (ADR-0002). COPY lands it
# root:root 0644, which is what the Relay's fail-closed loader demands: it
# refuses a group/world-writable gate file, a symlink, or a missing one. A
# gate file that cannot be loaded is a startup failure, never a silent
# "nothing needs approval" — so a broken fixture crash-loops this container
# instead of quietly disarming the fleet's approvals.
# --chmod is explicit rather than inherited: a plain COPY carries the BUILD
# HOST's mode, so whoever's umask happened to be 002 would ship a 0664 file and
# the loader would (correctly) refuse to start. The image mode must not depend
# on whose laptop built it.
COPY --chmod=0644 docker/fixtures/approval-gates.json /etc/relay/approval-gates.json

# A SECOND gate file, baked beside the first under the same rules, for the
# nine-Node demo fleet only (docs/operations/demo-fleet.md). Its two rules match
# the same dispatches as the file above, but ask in-band with no audience and
# `requester_allowed: true`, so an MCP client can be asked the approval
# question (MRTR) or answer with `approve_request`. The Relay reads only the
# file RELAY_APPROVAL_GATE_CONFIG names: docker-compose.demo.yml defaults that to
# the file above, and only the Makefile's demo-* targets point it here.
# `make dev-fleet-up` and `make demo-*` each set it explicitly; only a bare
# `docker compose -f docker-compose.demo.yml up` reads
# DEV_FLEET_APPROVAL_GATE_CONFIG from the caller's shell or a repo-root .env,
# so a stray value there would select this file.
COPY --chmod=0644 docker/fixtures/approval-gates.demo.json /etc/relay/approval-gates.demo.json

# No credential fixture is baked into the image: since #298 (ADR-0023) the
# control plane accepts only per-Account API Tokens, and the dev fleet's first
# one is minted at runtime by the `init` service (docker/dev-fleet-init.sh)
# using this image's own `relay bootstrap-token` subcommand.

# ---- unprivileged: os plus the non-root user, still without a binary ----------
# The container expression of relay/packaging/relay.service's `User=relay`: the
# Relay needs no privilege, so it does not run as root. The UID/GID are fixed so
# that a file the operator mounts in (a webhook secret must be 0600 and owned
# by the reading user) can be chowned to a known number on the host.
#
# /var/lib/relay is created 0700 and owned by that user, so a fresh named
# volume mounted there inherits both — the CA key under it is the most
# sensitive file in the deployment (docs/operations/ca-disaster-recovery.md).
# release and runtime both build on this stage, so they cannot drift apart in
# posture; they differ only in where the binary comes from.
FROM os AS unprivileged

RUN addgroup -S -g 10001 relay \
 && adduser -S -D -H -u 10001 -G relay -s /sbin/nologin relay \
 && install -d -o relay -g relay -m 0700 /var/lib/relay

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
FROM unprivileged AS runtime

COPY --from=build /out/relay /usr/local/bin/relay
