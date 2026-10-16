# AGENTS.md

Instructions for AI agents working in this repository. Read this fully before making changes.

## What this is

Relay is a **fleet-administration control plane** — a system that runs administrative
commands on a fleet of Linux servers, drivable by an AI orchestrator. It is **security-critical
by nature: it is remote code execution as a service.** Treat every change to the execution,
Policy, transport, or auth paths as security-sensitive.

The product is **Relay**. **Gleipnir** is the separate first-party AI-agent system that drives
it — a consumer of Relay, never a component of it. The repo was formerly `gleipnir-relay`
(GLOSSARY.md, ADR-0016).

Orient in this order: the invariants below for what must always be true,
[GLOSSARY.md](GLOSSARY.md) for the language, [docs/specs/](docs/specs/) for the capability
you're touching, then the [ADRs](docs/adr/) governing it — each invariant names the ADR that
governs it. [README.md](README.md) is the outside view: what Relay is, and why.

## Ubiquitous language — use it exactly

[GLOSSARY.md](GLOSSARY.md) is the canonical glossary — every term, and the synonyms this project
has rejected. An `_Avoid_` line is a decision, not a suggestion. Use the canonical term in code,
comments, commits, issue titles, test names and prose.

Two are worth naming here, because they are the pair that actually gets confused and the
confusion is not cosmetic — one of these is an AI and the other must never be mistaken for one:

- **relay-daemon** — the non-AI Rust daemon on each Node. **Never call it "agent".**
- **AI-agent** — the AI orchestrator. The only thing called "agent", and always qualified.

Internal identifiers say `Relay` / `RELAY_`, never "gleipnir" (ADR-0016).

## Architecture invariants — do not violate without a new ADR

**Status: current as of 2026-09-21.** Every invariant below is a constraint the code is
expected to satisfy today, except where the gap table names otherwise. The date says when
this section was last audited against the code — not when it was last edited.

These are load-bearing decisions. If a task seems to require breaking one, **stop and flag it**;
it needs an ADR, not a quiet workaround.

1. **Nothing on the wire can compose or escalate a command.** A Task's arguments may never
   change which command runs, append a second one, or reach past what the Operation's author
   fixed. Execution is three tiers ordered by trust, each holding the line its own way: **Native**
   Operations by argv and never `/bin/sh`; **Template** Operations by a structure fixed in a
   root-owned local file, with no slot value ever part of the text the Template's shell parses;
   **Raw Exec** —
   the caller-supplied, exceptional tier — by being argv-only and regex-gated by Policy. New
   vocabulary is Templates, never new Natives: the Native vocabulary is frozen at four.
   Per-tier mechanism lives in `docs/specs/execution.md`. (ADR-0001, ADR-0021; Template clause
   amended 2026-10-14)
2. **Policy is locally-rooted and remotely-immutable.** The Relay may *query* a Node's Policy; it
   may **never** modify it over the wire. The daemon enforces; the Relay only reads. (ADR-0002)
3. **Deny-by-default, deny-beats-allow,** with argument-level granularity. (ADR-0002)
4. **At-most-once Task execution.** Tasks carry unique IDs; the daemon dedups across reconnects.
   Never make execution at-least-once. (ADR-0004)
5. **Blast-radius cap is enforced on the Relay before dispatch.** (ADR-0004)
6. **mTLS everywhere; the daemon refuses an untrusted Relay.** Node identity is its client cert.
   (ADR-0005, 0006)
7. **Labels are namespaced, and each namespace has exactly one writer.** Four namespaces, each
   immutable from every side but its own author: `node:` is written by the Node's own config
   management and never by the Relay; `relay:` by the Relay and never by the Node; `tag:` by an
   operator through the control plane and never by the Node; `state:` by nobody at all — it is
   Relay-derived from the registry, evaluated at Selector-resolution time from a closed
   vocabulary. No Account writes a `relay:` label directly: each `relay:` key is written only as
   the side effect of the Relay action that defines it. **The security lane targets only labels
   no Node can write.** Remediation and secret distribution target `relay:` and only `relay:`.
   Engaging a quarantine — which only ever reduces what may run — may target `relay:` or `tag:`;
   lifting one targets `relay:` only. `node:` and `state:` are for routine targeting and are
   never a security-lane target. A compromised Node can forge its own `node:` labels, and can
   influence `state:` by lying in `Hello`, but never `relay:` or `tag:`.
   (ADR-0006, ADR-0020, ADR-0034; amended 2026-09-16)
8. **`/proto` is the single source of truth** for the wire protocol and Operation vocabulary.
   Change the contract there; regenerate both sides. Don't hand-edit generated code. (ADR-0007)
9. **The System Model is advisory; its grounding facts are AI-immutable.** The AI-agent may
   freely create/update/delete Services, Dependencies, and Annotations (with provenance,
   audited via git commits), but may never edit Nodes or `relay:` labels through it, and the
   model never bypasses Selectors → Policy → blast cap. It is never a desired-state spec:
   Relay does not auto-reconcile, ever. (ADR-0008)
10. **One capability layer; every interface is an adapter over it.** Ports and adapters: the
    capability layer is the single implementation of what may be done, who may do it, and how it
    is recorded, decided there and never per interface. An adapter exposes that layer and
    **narrows only** — it may offer less than the layer allows, and it may never widen it,
    reimplement any part of it, or decide anything itself. Which surface exposes what is in the
    capability specifications, not here. Reaching a Node any other way is a parallel control
    path, and there is never a reason to build one; the `no_dispatch` structural guard covers
    each adapter. The Console is **not** read-only by design (ADR-0026 superseded
    ADR-0009's no-execution scope): where it executes, it does so preflight-by-default, with
    step-up re-authentication on a mutate apply, role-gated by the capability layer, and behind
    the root-owned `console_execution` flag. (ADR-0009, ADR-0010, ADR-0026; wording amended
    2026-09-20 for ADR-0038)
11. **Neither a credential nor the Relay itself can change the terms on which credentials
    are accepted.** The configuration that bounds *who may authenticate, and how recently they
    proved it* — listeners, which CA and TLS material are used, auth bootstrap, the identity
    provider Relay believes, session and step-up windows, `console_execution`, and the approval
    notification path — is the **security floor**. It is set by whoever administers the
    Relay's host, outside Relay, and nothing Relay runs or accepts can write it: no API, no
    request, and not the Relay process. Key material the Relay generates — its CA key, the
    certificates it issues — is the Relay's own, not floor. Configuration that
    only bounds *reach* — blast caps, approval-gate rules, the minimum daemon version, rate
    and capacity limits — may be a runtime object, changed only by a human Account with
    step-up re-authentication, and audited. Secrets never pass through the environment or
    the command line; the Relay can read them and cannot rewrite them, except key material
    it generates itself. (ADR-0010, amended 2026-09-15; ADR-0004, ADR-0012, ADR-0027;
    reworded 2026-10-15, ADR-0033, ADR-0043)
12. **Policy is evaluated only by the daemon's live engine** — including hypotheticals
    (`PolicyQuery`, the Policy preflight). Never reimplement Policy evaluation on the Relay side.
    (ADR-0011; wording amended 2026-09-20 for ADR-0038)
13. **Every Operation declares a risk class (`read` | `mutate`)**; blast caps are chosen by
    class, Raw Exec always takes the mutate-cap, and the class is security-relevant contract
    that no caller can set or loosen. Where the class is reported by Nodes rather than fixed in
    `/proto`, a dispatch takes the most restrictive class the Nodes it reaches report.
    (ADR-0012, ADR-0042; amended 2026-10-02)
14. **The daemon never self-upgrades and the Relay never pushes binaries.** Daemon upgrades
    flow only through the customer's config management; the Relay's lever is the
    dispatch-level minimum-version gate. (ADR-0014)

**The numbering is a public interface.** `docs/security/threat-model.md` maps all fourteen to
the boundaries they defend; ADR-0006, ADR-0010, ADR-0020, ADR-0026, and ADR-0034 each record
amending a specific numbered invariant; GLOSSARY.md, `docs/security/threat-model.md`, and
several Go source comments cite them by number. Amend an invariant in place and record the
amendment in its ADR. **Never renumber or drop one.**

**Amending one is not finished until its consumers are updated.** `docs/security/threat-model.md`
maps each invariant to the boundary it defends and is the one that goes silently wrong: it has
no mechanism of its own to notice an amendment, so every amendment that skips it leaves it
describing the previous system (three did, between 2026-09-08 and 09-10). An amendment PR
checks it, the capability specs that cite the invariant, `GLOSSARY.md`, and the ADRs the
amending ADR says it amends — each of those must record the amendment on its own page.

### Known gaps between these invariants and the code

Found by adversarial review (2026-09-08), during a spec migration (2026-09-21), and in #974
(2026-10-14), and left in
place deliberately: correcting invariant text needs an ADR amendment in
front of a human, which is a separate change.
**Until that lands, believe this table over the invariant text above.**

**A row is deleted by the PR that closes its issue** — removing it is part of that issue's
definition of done, not a later chore. This table has the same failure mode it exists to fix,
and that rule is the only thing keeping it honest.

| # | The clause | What is actually true today | Tracked |
|---|---|---|---|
| 7 | `tag:`'s writer, and `relay:`'s | `tag:` has **no storage on the Node record and no write path**, so nothing can be written to the namespace the invariant says an operator writes. Since #561 a `tag:` term is **refused at parse** with a recognisable sentinel rather than silently matching nothing, identically on every surface — so the gap is now an honest refusal instead of a false negative. `relay:` labels are stamped at enrollment today; the Relay actions that write them afterwards (quarantine engage and lift, `quarantine-node.md`) are unbuilt, so quarantine by either `relay:` or `tag:` does not exist yet. Behaviour detail in `docs/specs/selectors-and-labels.md`. | #430 |
| 10 | Console execution | The Console does **not** execute yet. The route-gating mechanism is real and tested both ways, but the composition root hardcodes it off and ships no config key to change it — deliberately, since there is no execution route to gate. Forced on, `/console/run` renders a placeholder, not a composer. Everything else in the invariant, `no_dispatch` included, is true today. | #438 |
| 11 | Secrets: the Relay can read them and cannot rewrite them, except key material it generates | Decided 2026-10-15 (ADR-0043): one configuration file the Relay reads itself, refusing to run if it could write that file or anyone else could read it. Not built: the floor still arrives as `RELAY_*` environment variables placed by systemd, secrets are separate files whose owner nothing checks, the webhook secret's mode check refuses the packaged layout, the Relay's help and error text still say "root-owned", and the CA private key is read back with no mode or owner check at all. | #1002 |

### Writing or amending an invariant

Two rules, each learned from a gap above.

**A constraint, not a status report.** Write *"where X happens, it happens thus"* — never
*"X happens."* A constraint stays true across the milestone that builds it; a status claim goes
stale the moment it ships or slips. Invariants 7 and 10 are stale for exactly this reason, and
neither would be if the clause had been written as a rule.

**The property, not the mechanism that currently delivers it.** State what must hold, not how
today's code holds it. A mechanism-shaped invariant breaks the moment a second mechanism
arrives satisfying the same property differently — which is what the Template tier did to
invariant 1's "argv, never `/bin/sh`". The property there was always the *second* sentence:
arguments can never change which command runs. Where the mechanisms are worth writing down,
they belong in the capability specification, not here.

If a constraint genuinely cannot avoid asserting that something exists, it belongs in the gap
table with its issue number until it does.

## When documents and the code disagree

**Stop and escalate. Do not resolve it in either direction.**

> **A capability spec binds only once it is migrated to the claim format** (Status `current`
> or `designed, not built`). A spec still marked `aspirational` or `stub` describes intent, drift
> from the code is expected, and the two rows below that name a capability spec do not apply to
> it; the invariant row always does. See the establishing phase in `docs/specs/README.md`.

That rule is deliberately absolute, because the right direction depends on which kind of
statement disagreed — and getting it backwards is expensive in one specific way. Invariant 2
says the Relay may never write a Node's Policy. An agent that found a write path and "fixed
the document to match the code" would amend away this system's central security property,
having followed a reasonable-sounding rule correctly.

| Conflict | What it means | Who resolves |
|---|---|---|
| An invariant ↔ the code | Either a security defect in the code, or a defect in this file | A human, always |
| A capability spec ↔ the code | Either the spec is stale, or the code has the bug the spec correctly describes | A human, always |
| A capability spec ↔ an ADR or an invariant | The spec is subordinate — the presumption is that the spec is the defect | A human, always |

Only ADRs and the invariants carry human sign-off by construction. Everything below that line
is maintained continuously, including by agents, so nothing below it silently wins against the
code.

This governs a disagreement you **discover**. When you are **making** a change, the spec
leads: write the capability specification first, then the code, in the same PR. Intent flows
spec → code; drift escalates.

## Out of realm — proposed, and deliberately rejected

Each of these has been asked for. Each is a "no" with an authority behind it, which means
you may refuse the work rather than negotiate with yourself about it. An issue never
redefines one; if a task appears to require one, stop and flag it.

- **Configuration management.** Relay is response and fleet administration. *If Ansible could
  check it in check-mode, it is out of realm.* Settled 2026-07-08 and restated here in its own
  right, because its original home is being retired.
- **Desired-state reconciliation.** The System Model is advisory. Relay does not converge a
  fleet toward a spec, ever. (Invariant 9)
- **Software distribution.** The Relay never pushes binaries and the daemon never
  self-upgrades; upgrades are the customer's config management. (Invariant 14)
- **Central Policy authorship.** The Relay may read a Node's Policy and may never write it.
  Policy authoring stops at the clipboard. (Invariant 2)
- **A general-purpose remote shell.** Raw Exec is a conspicuous, regex-gated exception to a
  typed vocabulary, not the primary path. (Invariant 1)
- **Widening the `relay` binary.** It may perform an act only if no credential could exist
  to perform it over the wire. The official CLI was built and then deliberately removed; a
  bootstrap command with no stated boundary becomes that CLI again, one convenient verb at
  a time. (ADR-0030)

## Repository layout

```
/proto/              protobuf contract — the spine. Edit here first for any wire/Operation change.
/relay/              Go: gRPC server, MCP server, Job engine, CA, registry, store.   (cd relay)
/relay/packaging/    the Relay's hardened systemd unit and example EnvironmentFile.
/daemon/             Rust: connection, Policy engine, Operation executors, exec.      (cd daemon)
/daemon/packaging/   relay-daemon systemd unit, example EnvironmentFile, shipped Template catalog.
/daemon/fuzz/        cargo-fuzz targets and corpus for the daemon.
/docker/             Dockerfiles, entrypoints, and fixtures for the local Docker fleet;
                     docker-compose.demo.yml at the root composes it (there is no root
                     docker-compose.yml), with docker-compose.oauth.yml as the opt-in overlay.
/deploy/compose/     the single-Relay deployment stack, split from the dev fleet (#783).
/scripts/            CI gates and repo tooling (docs checks, spec coverage, security surface).
/docs/adr/           architecture decision records — the *why*.
/docs/agents/        per-repo configuration agent skills read (tracker, labels, domain rules).
/docs/api/           Control API reference and OpenAPI surface.
/docs/brand/         the relay_ wordmark and icon (SVG + PNG) and how to use them.
/docs/design/        console/ is the Console's live per-screen specification, cited from source;
                     the rest is pre-ADR design for work not yet decided.
/docs/operations/    operator-facing runbooks: install, enrollment, upgrades, recovery, demo fleet.
/docs/security/      threat model — maps all fourteen invariants to the boundaries they defend.
/docs/specs/         capability specifications — what each capability does today, every surface.
/docs/deferred.md    work agreed in principle, not yet specified; ADR at pickup.
/docs/dev-fleet.md   the local Docker fleet: how to run Relay + real daemons.
/.claude/            the workflow's commands and agents, committed so unattended routines have them.
/.github/            CI workflows and the pull request template.
Makefile             wraps both toolchains; `make verify` is the CI-equivalent gate.
GLOSSARY.md          the ubiquitous language.
AGENTS.md            this file; CLAUDE.md imports it for Claude Code.
```

## Toolchains & commands

Two toolchains. The `Makefile` wraps both — prefer it.

| Task | Command |
|---|---|
| Build everything | `make build` |
| Test everything | `make test` |
| Lint/format everything | `make lint` |
| **Full CI-equivalent gate — run before opening a PR** | **`make verify`** |
| Install pinned proto plugins (do this first) | `make proto-tools` |
| Regenerate proto code | `make proto` |
| Local Docker fleet, up / creds / logs / down | `make dev-fleet-up` · `-creds` · `-logs` · `-down` |
| Relay only (Go) | `cd relay && go build ./... && go test ./...` |
| Daemon only (Rust) | `cd daemon && cargo build && cargo test && cargo clippy` |

**`make build test lint` is the fast inner loop. It is not what CI runs, and the gap has
bitten.** CI additionally runs the race detector, the proto-drift and proto-breaking gates,
the operation-schema and OpenAPI drift checks, the docs and security-surface self-checks, the
strict-umask runs, the devharness absence check, both cross-binary suites, the shell and workflow
linters, the secrets scan, and the daemon's cargo-deny policy. Work can pass the inner loop and fail CI on a class of problem the author
never looked at. `make verify` mirrors CI gate for gate; it is deliberately slow and deliberately
not what you run on every save. On a pull request CI skips the gates a change cannot reach — the
toolchain jobs for documentation-only changes, the proto gates when neither `/proto` nor its
generated code moved, the advisory scans when no lockfile moved (`scripts/ci-changed-paths.sh`);
a **draft** PR runs only the docs job until it is marked ready for review; pushes to `main` run
everything.

- **Go (relay):** `gofmt`/`go vet`/`golangci-lint`, under the toolchain the `Makefile` exports.
  The version is named once, in `relay/go.mod`'s `go` directive, and the `Makefile` derives
  `GOTOOLCHAIN` from it so every target runs that toolchain whatever the host's `go` happens to
  be. Two limits, stated because both have bitten: `GOTOOLCHAIN` re-execs the `go` command and
  not its sibling binaries, so `gofmt` is invoked out of `go env GOROOT`; and a bare
  `cd relay && go test ./...` outside `make` is not pinned at all — `internal/version`'s
  toolchain contract test is what catches that one. `GOTOOLCHAIN=local make <target>` is the
  one-run escape hatch. Raising the Go version is a decision, not a chore: it is one edit in
  `relay/go.mod`, and #572 is the open question it waits on.
- **Rust (daemon):** stable toolchain, with the floor declared as `rust-version` in
  `daemon/Cargo.toml`; `cargo fmt`/`cargo clippy -- -D warnings`. There is deliberately no
  `rust-toolchain.toml` — it would override the components and targets CI and the musl Docker
  build install. Build the daemon for musl when producing release artifacts (small static
  binary for the fleet).
- **Proto codegen is version-sensitive.** Run `make proto-tools` before `make proto`: it pins
  protoc-gen-go, protoc-gen-go-grpc and buf, at the versions the `proto-tools` target names.
  Unpinned `@latest` produces a spurious diff that false-positives the proto-drift gate, and so
  does a second checkout that installed a different version into the shared `GOPATH/bin` — if
  the gate reports drift you did not cause, re-run `make proto-tools` before believing it.
- `make test` is hermetic and will not catch real-binary startup bugs. `make verify` includes
  `make test-integration`; run that target on its own when the diff touches Relay startup, the
  composition root, or config defaults and you are not yet ready for a full verify.
- **Dogfooding:** `make dev-fleet-up` brings up a Relay and real daemons in Docker. See
  `docs/dev-fleet.md`.

## How to work here

**1. Read before writing.** GLOSSARY.md, the capability specification for what you're touching,
then the ADR(s) governing it. `docs/agents/domain.md` carries the consumer rules; the invariants
above are the index into `docs/adr/`.

**2. Shape before you spec.** Ambiguity is resolved by interrogation, not by guessing.
Stress-test the idea against the codebase and the ADRs *first*; a decision reached in the
conversation is worth more than one discovered mid-implementation.

**3. Spec, design, decompose, implement.** The order is deliberate, and who may author what
changes at each step. The full chain, its five human gates and the authority table are in
`docs/agents/workflow.md`; each step below is a command in `.claude/commands/`.

1. **Create or update the capability specification** — `docs/specs/<capability>.md`: what that
   capability does, across every surface, as claims with stable IDs. **Co-authored with a
   human, in an interactive session (`/spec-author`) — never by an unattended run.** Checked
   with `/spec-check` before its PR. These are the most impactful artifacts in the repo;
   everything below decomposes from them.
2. **Design the solution** against the spec's *Designed, not built* claims (`/design`): a
   milestone-scoped plan under `docs/design/plans/`, adversarially reviewed by two vendors,
   merged by a human, deleted when the milestone closes.
3. **Decompose into bite-size issues** (`/decompose`), each sized to a single fresh context
   window, naming the claims it promotes and what blocks it, created as `loop:proposed` until
   a human flips it to `loop:ready`. **One issue per capability is its testing issue** — the
   tests that prove each claim with no proof row, and benchmarks where they are worth measuring.
4. **Implement**, one issue at a time (`/dev-loop`), with the spec's proof rows updated in the
   same PR; then `/pr-respond` for review comments, and `/milestone-close` at the end.

A capability specification is **durable** — maintained as the capability evolves, never archived
because a feature shipped. An **implementation specification is a GitHub issue, and is
disposable**: it dies with its PR, so anything in it that outlives the change must be promoted
before the issue closes (see 7).

**If you are implementing, you read a spec's claims and never write them.** A change that would
make any claim in a migrated capability spec untrue is a stop-and-escalate, not a docs edit: a
human updates the spec first, and the code follows. That is *When documents and the code
disagree*, above, applied before the disagreement exists. The loop does maintain a spec's
*evidence* — proof rows, Status, and promoting a Designed claim verbatim once its test
lands — and nothing else; the split is the authority table in `docs/agents/workflow.md`.

Bugs never get specs: diagnose and fix. If the spec described the broken behaviour as correct,
that is an escalation too.

Specs and tickets name modules and contracts, **never file paths or code snippets**: those go
stale within a sprint.

**4. Work the current milestone.** **GitHub milestones are the authority on what is in flight**
— read them with `gh`, don't infer the target from a file. A milestone's acceptance criteria live
on its issues; durable behaviour lives in the capability specification, never in a planning
document. `ROADMAP.md` was retired on 2026-09-12: its status was a hand-synced copy of GitHub
that went badly stale, and its acceptance criteria now live in `docs/specs/`. Git history has it
if you need the milestone narrative.

Milestones here were deliberately built out of order, and some are gated on things an agent
cannot supply (real hardware, an open licensing decision). Issues decompose a milestone; they
never redefine one. Don't pull future milestones forward, and don't self-assign a gated one.

**5. Contract-first.** Wire or Operation changes start in `/proto`, then regenerate, then
implement both sides. `/proto` is the single source of truth; don't hand-edit generated code.

**6. Verify before you open a PR.** `make verify` is the gate, not `make build test lint` —
see Toolchains above for why the difference has bitten. Two failure modes to report rather
than swallow: a **skipped** gate is not a passed gate, and `verify-proto` skips the proto-drift
and proto-breaking checks with a notice when `buf` is absent. If your diff touches `/proto` and
those gates were skipped, say so in the PR body. CI runs them regardless, and invariant 8 plus
the escalation list below both put `/proto` in front of a person.

**7. Write an ADR** when a decision is hard to reverse, surprising without context, *and* the
result of a real trade-off — all three, not any one. Number it sequentially in `docs/adr/`.
Match the surrounding style: ADRs here are longer than the usual one-paragraph form because
they encode invariants agents are expected to check themselves against.

**Promote before the issue closes.** An implementation specification is a GitHub issue and is
disposable; a closed issue is not a record. Before the PR merges, lift everything in it that
outlives the change: behaviour that is now true of the system → the **capability specification**;
a decision meeting all three tests above → an **ADR**, cited by number rather than re-argued;
a shift in domain language → **GLOSSARY.md**; a change to what must always be true → **an
invariant above**, which is a conversation with a human and an ADR amendment, never a quiet
edit. This is the most common way a repo
loses its own reasoning.

**8. Update GLOSSARY.md** in the same change whenever the domain language shifts.

**9. Security posture.** Never weaken Policy, never add an implicit shell to an Operation,
never log secrets (tokens, private keys), never make the Relay able to mutate Node Policy.
When in doubt on the daemon (privileged) side, prefer the more restrictive option and flag it.

## Code comments

A comment says what the code cannot: why it is this way, what it must never do, what would
break. It is not a changelog and not a design document.

- **No issue or PR numbers in shipped code.** The commit and the PR carry a change's
  history. Where a comment explains why something is true, cite the ADR (`ADR-0012`), the
  invariant (`invariant 13`) or the spec claim that holds the reason; where none does,
  state the reason. `make lint-comments` enforces this; `Deprecated:` lines are exempt,
  and a test may cite the issue it regresses.
- **Present tense.** Say what the code does, not what it used to do: no "previously",
  "no longer", "was moved", "since #NNN".
- **Short headers.** A package or file header says what the package is in a few lines.
  Rationale that needs a page belongs in an ADR, cited once by number, not argued again
  in the code.
- **Match this section, not the neighbours.** Older code is denser than this; don't copy
  its density.

## Agent skills

Agent skills read their per-repo configuration from `docs/agents/`. Keep these current: they
are what a fresh session — including an unattended cloud routine — uses instead of asking.

- **Issue tracker** — GitHub Issues on `Felag-Engineering/relay` via the `gh` CLI,
  with GitHub milestones as the human-owned spine above it. See `docs/agents/issue-tracker.md`.
- **Triage labels** — the five canonical triage roles mapped onto this repo's `loop:*` lanes.
  `decision` and `idea` are human-owned and never loop work. See `docs/agents/triage-labels.md`.
- **Domain docs** — single-context: GLOSSARY.md at the root plus `docs/adr/`. Contradicting an
  ADR here is a stop-and-escalate, not a flag-and-proceed. See `docs/agents/domain.md`.
- **Routines** — what a scheduled cloud run executes, the environment it needs, the caps, and
  the `loop:halt` kill switch. See `docs/agents/routines.md`.
- **The workflow** — the chain from a spec edit to a closed milestone, its human gates, the
  authority table, and the two-vendor review rule. See `docs/agents/workflow.md`.

## Routines & merge authority

This repo is **product-only.** It is built largely by a Claude-driven agentic loop — working
one issue at a time on a branch, running `make verify`, having a separate
agent review the diff, and opening a PR. It runs both as interactive sessions and as unattended
cloud routines.

**Nothing merges autonomously. A person is always the merge authority.** This is the load-bearing
guardrail on a repo that ships remote code execution; it does not relax because a run is
unattended.

If you are an agent implementing an issue: **stay in scope**, you have **no merge authority**
(open a PR; a human merges), and **stop and flag a human** rather than guess on a hard call.

**Always escalate — never try to land without review** — anything on the security surface
(`docs/agents/security-surface.txt` is the one list: `proto/`, `docs/adr/`,
Policy/exec/transport/mTLS/auth/session/store code, the dependency manifests,
`AGENTS.md`/`GLOSSARY.md`, the `Makefile`, CI, and the commands and agents that run the
workflow); any failed build; any high-severity review finding. These are the security surface and
the architecture invariants; they always land in front of a person. Editing an invariant is
never a docs chore.

**Running unattended changes what you have, not what you may do.** A routine gets a fresh clone
and sees only what is committed here plus whatever skills its environment supplies. If a skill
or command the workflow depends on is missing, say so and stop — do not improvise the pipeline
by hand. An escalation you cannot deliver interactively becomes a PR left unmerged with the
reason stated plainly, never a decision made on the human's behalf.

**Unattended runs use `/dev-loop-queue` and `/pr-respond`.** The queue takes one `loop:ready`
issue per tick and opens a PR without ever waiting for a merge; `pr-respond` addresses a human's
review comments on an open loop PR and hands it back. Nothing above those two runs unattended.
Either way a human merges, and `loop:halt` on any open issue stops every tick before it starts
work.

**Schedulers don't source `~/.profile`,** so `cargo`, `go`, and `buf` may be missing from a
routine's `PATH`. The Makefile prepends the usual toolchain directories to compensate, but
`buf` is not part of a normal dev setup and will usually be absent — which silently downgrades
`make verify` by two proto gates. Install it with `make proto-tools`, or report the skip.
Never let a routine's thinner environment quietly become a weaker standard of proof.
