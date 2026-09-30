# Relay image. Build context is the repo root so the builder can see /relay.
#
# Two targets, one binary:
#
#   runtime    the Relay and nothing else, running as an unprivileged user.
#              The root docker-compose.yml builds this one (`target: runtime`):
#              the single-host deployment in docs/operations/relay-install.md.
#              No fixture, gate file or credential is baked into it.
#   dev-fleet  the LAST stage, so the default for any build that names no
#              target — docker-compose.demo.yml's. DEV-ONLY: it adds the dev
#              and demo fleets' approval-gate fixtures and runs as root,
#              exactly as this image did before the split (docs/dev-fleet.md).
#
# Neither is a published, reviewed release image yet (#399).

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

# ---- base stage: what both targets below share ------------------------------
# alpine rather than busybox: the compose healthcheck completes a real TLS
# handshake with each listener, and both listeners are TLS 1.3 only — busybox's
# ssl_client stops at 1.2. openssl s_client does 1.3 and verifies the chain
# against the Relay's own CA. The static Go binary needs no libc.
FROM alpine:3.22 AS base

RUN apk add --no-cache openssl

COPY --from=build /out/relay /usr/local/bin/relay

# 7654 = node-plane gRPC (relay-daemon dial-home); 9443 = control-plane HTTPS
# (MCP + /api/v1). Distinct listeners, published to distinct host ports by
# compose — listener separation is honored end to end.
EXPOSE 7654 9443

# All configuration is supplied as RELAY_* environment by the compose file
# that runs the image.
ENTRYPOINT ["/usr/local/bin/relay"]

# ---- runtime: the deployment target -------------------------------------------
# The container expression of relay/packaging/relay.service's `User=relay`: the
# Relay needs no privilege, so it does not run as root. The UID/GID are fixed so
# that a file the operator mounts in (a webhook secret must be 0600 and owned
# by the reading user) can be chowned to a known number on the host.
#
# /var/lib/relay is created 0700 and owned by that user, so a fresh named
# volume mounted there inherits both — the CA key under it is the most
# sensitive file in the deployment (docs/operations/ca-disaster-recovery.md).
FROM base AS runtime

RUN addgroup -S -g 10001 relay \
 && adduser -S -D -H -u 10001 -G relay -s /sbin/nologin relay \
 && install -d -o relay -g relay -m 0700 /var/lib/relay

USER 10001:10001

# ---- dev-fleet: DEV-ONLY, the default target ---------------------------------
# FROM base, not FROM runtime: the dev and demo fleets run the Relay as root,
# as they always have, and their one-shots rely on it.
FROM base AS dev-fleet

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
# the file above, and by convention only scripts/demo-fleet.sh points it here.
# That convention is all that keeps the default three-Node fleet off this
# gate: a bare `docker compose -f docker-compose.demo.yml up` (`make
# dev-fleet-up` included) reads
# DEV_FLEET_APPROVAL_GATE_CONFIG from the caller's shell or a repo-root .env,
# so a stray value there would select this file.
COPY --chmod=0644 docker/fixtures/approval-gates.demo.json /etc/relay/approval-gates.demo.json

# No credential fixture is baked into the image: since #298 (ADR-0023) the
# control plane accepts only per-Account API Tokens, and the dev fleet's first
# one is minted at runtime by the `credential` service (docker/mint-credential.sh)
# using this image's own `relay bootstrap-token` subcommand.
