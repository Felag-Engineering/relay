# Relay image for the local dev fleet (docs/dev-fleet.md). DEV-ONLY packaging —
# not a production deployment artifact. Build context is the repo root so the
# builder can see /relay (see docker-compose.yml / the `docker build` command in
# the doc).

# ---- build stage: compile the Relay (Go) as a static binary --------------------
# golang:1.25 matches `go 1.25.0` in relay/go.mod.
FROM golang:1.25-bookworm AS build

WORKDIR /src
COPY relay/ ./relay/

# CGO_ENABLED=0: the Relay's SQLite store is pure-Go (modernc.org/sqlite), so the
# binary needs no libc and runs on a musl/scratch base. -trimpath keeps the build
# reproducible and free of local path leakage.
RUN cd relay && CGO_ENABLED=0 go build -trimpath -o /out/relay ./cmd/relay

# ---- final stage: minimal runtime image ---------------------------------------
# busybox:stable-musl is tiny but ships sh + nc, which the compose healthcheck
# uses to probe the listeners. The static Go binary needs no libc.
FROM busybox:stable-musl

COPY --from=build /out/relay /usr/local/bin/relay

# The control-plane credential HASH (never the plaintext). DEV-ONLY fixture; it
# is the sha256 of the documented dev plaintext and grants full control-plane
# access. See docs/dev-fleet.md's security note — never reuse it anywhere real.
COPY docker/fixtures/control-credential.hash /fixtures/control-credential.hash

# 7654 = node-plane gRPC (relay-daemon dial-home); 9443 = control-plane HTTPS
# (MCP + /api/v1). Distinct listeners, published to distinct host ports by
# compose — listener separation is honored end to end.
EXPOSE 7654 9443

# All configuration is supplied via RELAY_* env in docker-compose.yml.
ENTRYPOINT ["/usr/local/bin/relay"]
