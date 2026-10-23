# The read catalog ships with the daemon

**Status:** Accepted (owner decision 2026-10-23).

Behaviour: `docs/specs/daemon-installation.md`, `docs/specs/operations-and-templates.md` and
`docs/specs/policy.md`. This ADR supersedes in part ADR-0021 decision 11 and ADR-0033's
amendment of 2026-10-15, where the shipped read catalog is its own optional package.

## Decision

A freshly installed Node can answer the questions an AI-agent asks first: processes, service
status, disk usage, listening ports, installed packages, a service's recent journal, a file's
checksum. The seven read Templates that answer them ship inside the `relay-daemon` package, and
the shipped default Policy allows all seven, the journal tail included. There is no separate
`relay-read` package to find and install. A customer who does not want journal lines reaching
their AI model's provider denies `log.tail` with a one-line Policy fragment, or narrows its allow
to chosen units in the Policy file.

## The decisions

1. **One package.** The read catalog is package-owned files of `relay-daemon`, replaced on upgrade
   and removed with the package. The catalog ledger still binds each released Template name to
   its body and risk class, so an upgrade adds Templates and never changes what an allowed name
   does.
2. **The default allows the whole catalog, `log.tail` included.** The default Policy's
   confidentiality deny-list still applies over it (deny beats allow, invariant 3).
3. **Narrowing is documented.** Deny beats allow, so a fragment can take `log.tail` away but
   cannot narrow the default's allow. The runbook shows the fragment that denies it, and the edit
   to the Policy file (the operator's own after first install, ADR-0022) that narrows its allow to
   chosen units.

## Why

A Node that can do nothing until a second package is found is the likeliest stumble on a
thirty-minute setup. ADR-0021 made placing the catalog the operator's choice because a read's
output travels to the AI model's provider. The owner weighed that and chose usefulness on day one,
with the egress named and turning it off one line away.

## What changes

- `daemon-installation.md`, `operations-and-templates.md` and `policy.md`.
- The threat model names the accepted residual: by default, journal lines from any unit can
  reach the AI model's provider through `log.tail`, and they carry whatever a service logs.

## Alternatives

- **Fold the catalog in, but leave `log.tail` off by default.** Safer for secrets in logs, and the
  first incident question ("what did this service log?") needs a Policy change to answer.
- **Keep two packages.** Explicit opt-in, and a first run that does nothing if one is missed.
