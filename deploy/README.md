# deploy/

One folder per environment. Each holds its `docker-compose.yml` and every configuration file
that compose file loads; nothing outside the folder configures it, apart from the Dockerfiles
and one-shot scripts in `docker/` that the builds use.

| Folder | What it runs | Make target | Runbook |
| --- | --- | --- | --- |
| `production/` | The Relay alone: one service, one external data volume, no relay-daemons, fixtures or credentials. | none (deployed by hand or by a compose tool) | [relay-install.md, section 7](../docs/operations/relay-install.md#7-running-it-with-docker-compose) |
| `test/` | DEV-ONLY test fleet, project `relay-test`: the Relay, the `relay-config` and `init` one-shots, `daemon-1..3`. | `make dev-fleet-up` / `-down` / `-logs` / `-creds` | [dev-fleet.md](../docs/dev-fleet.md) |
| `demo/` | DEV-ONLY demo fleet, project `relay-demo`: the test fleet plus `daemon-4..9`, its own in-band gate, and the opt-in OAuth overlay `oauth.yml`. | `make demo-build` / `-reset` / `-up` / `-down` / `-logs` / `-creds` / `-fault`, and `-reset-oauth` / `-up-oauth` | [demo-fleet.md](../docs/operations/demo-fleet.md) |

The folder name is the environment, not a hardening claim: `production/` is a supported path
beside the systemd unit, and its posture is stated in its runbook (ADR-0033).

**Configuration.** Production's `relay.toml` is a host file by design (ADR-0043): it is
root-owned on the deployment host, at `/etc/relay/relay.toml` unless `RELAY_CONFIG_FILE`
names another absolute path, and is never in the checkout. The test and demo fleets carry
theirs in the folder (`relay.toml`, `approval-gates.json`, and for the demo `relay.oauth.toml`);
their `relay-config` one-shot stages them onto a named volume on every `up`, so an edit to the
folder reaches the Relay on the next `up`.

**One dev fleet per Docker engine.** The test and demo fleets publish the same host ports,
`7654` and `9443`, so only one of them runs per engine; each fleet's up targets refuse while
the other has containers. Neither belongs on a host that runs `production/`.

## Running with Komodo (or any compose tool)

Any tool that deploys a compose stack from a git checkout can run these files.

- **Compose file:** the folder's `docker-compose.yml`, for example
  `deploy/test/docker-compose.yml`.
- **Run directory:** the repository root. Build contexts are relative to the compose file, so
  they resolve the same from anywhere; running from the root keeps the commands below as
  written.
- **Build:** on. Every image is built from the checkout.
- **Environment:** `RELAY_PUBLISH_ADDR` and `CONSOLE_ADMIN_PASSWORD`, and optionally
  `FLEET_HOSTNAME` and `RELAY_PUBLISH_PORT`.
  `CONSOLE_ADMIN_PASSWORD` must be 12 or more characters, and is required once
  `RELAY_PUBLISH_ADDR` is not loopback: `init` refuses the committed default then. For test
  and demo it reaches only the `init` one-shot. Publishing beyond loopback makes the control
  plane network-reachable remote code execution for whoever holds a credential.
- **A DNS name and port 443 (test and demo):** `FLEET_HOSTNAME=relay.example.lan` puts that
  name in the Relay's certificate (lowercase DNS name; default `relay`), and
  `RELAY_PUBLISH_PORT=443` publishes the control plane on host port 443 instead of 9443. Point
  the name at the Docker host, then open `https://relay.example.lan/`. The certificate
  is signed by the fleet's own CA: trust `ca-cert.pem` (below) on the machines that use the
  Console. A new name takes effect on the next deploy, with no wipe. The CA is new after every
  `down -v`, though, so a nightly wipe means re-trusting the CA each morning. The OAuth
  overlay assumes the name `relay`.
- **Project name:** set by the file's `name:`; do not override it.
- **Fresh fleet nightly:** a pre-deploy command of
  `docker compose -f deploy/test/docker-compose.yml down -v` wipes the CA, the store and every
  Node identity before each deploy.

Read the admin API Token and the CA certificate out of the exited `init` container:

```console
$ docker compose -f deploy/test/docker-compose.yml cp init:/credential/control-credential - | tar -xO
$ docker compose -f deploy/test/docker-compose.yml cp init:/var/lib/relay/ca/ca-cert.pem - | tar -xO > ca-cert.pem
```

The same commands work for `deploy/demo/docker-compose.yml`. The token is a live admin
credential: keep it off shared terminals and out of logs.
