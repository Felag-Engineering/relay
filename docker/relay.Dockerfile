# Relay image for the local dev fleet (docs/dev-fleet.md). DEV-ONLY packaging —
# not a production deployment artifact. Build context is the repo root so the
# builder can see /relay (see docker-compose.yml / the `docker build` command in
# the doc).

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

# ---- final stage: minimal runtime image ---------------------------------------
# alpine rather than busybox: the compose healthcheck completes a real TLS
# handshake with each listener, and both listeners are TLS 1.3 only — busybox's
# ssl_client stops at 1.2. openssl s_client does 1.3 and verifies the chain
# against the Relay's own CA. The static Go binary needs no libc.
FROM alpine:3.22

RUN apk add --no-cache openssl

COPY --from=build /out/relay /usr/local/bin/relay

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
# file RELAY_APPROVAL_GATE_CONFIG names: docker-compose.yml defaults that to
# the file above, and only scripts/demo-fleet.sh points it here — so baking
# this file in changes nothing about the default three-Node fleet.
COPY --chmod=0644 docker/fixtures/approval-gates.demo.json /etc/relay/approval-gates.demo.json

# No credential fixture is baked into the image: since #298 (ADR-0023) the
# control plane accepts only per-Account API Tokens, and the dev fleet's first
# one is minted at runtime by the `credential` service (docker/mint-credential.sh)
# using this image's own `relay bootstrap-token` subcommand.

# 7654 = node-plane gRPC (relay-daemon dial-home); 9443 = control-plane HTTPS
# (MCP + /api/v1). Distinct listeners, published to distinct host ports by
# compose — listener separation is honored end to end.
EXPOSE 7654 9443

# All configuration is supplied via RELAY_* env in docker-compose.yml.
ENTRYPOINT ["/usr/local/bin/relay"]
