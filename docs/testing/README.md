# Manual end-to-end validation scripts

Every milestone ships a **human-runnable manual validation script** in this directory,
named `validate-vX.Y.Z.md`, that validates the milestone's acceptance criteria
end to end on a running system. The automated suites (`make test`, `make test-integration`,
`make test-crossbinary`, CI) remain the primary gate; these scripts exist so a human can
prove, with their own hands and eyes, that the shipped surface actually behaves as the
milestone promised — the same skepticism the product asks of its operators.

## The convention

1. **One script per milestone, named `validate-vX.Y.Z.md`.** The baseline is
   [`validate-v0.0.9-current.md`](validate-v0.0.9-current.md), which covers the entire
   surface shipped up to and including v0.0.9 (no scripts existed before it, so it is
   cumulative from v0.0.1). Every later milestone gets its own script:
   [`validate-v0.1.0-beta.md`](validate-v0.1.0-beta.md),
   [`validate-v0.2.0.md`](validate-v0.2.0.md).

2. **Steps map 1:1 to the milestone's acceptance criteria.** Each step states the exact
   command(s), the expected observation, and which milestone/ADR acceptance item it
   discharges. An acceptance item that cannot be validated manually (CI-only gates,
   timing-dependent races, criteria needing infrastructure that does not exist yet) is
   still listed, marked as such, with a pointer to the automated test or the missing
   prerequisite — never silently skipped.

3. **Drive the product only through its real surfaces.** Steps use what an operator or
   AI-agent actually has: the MCP tools (`list_nodes`, `describe_node`,
   `list_operations`, `run_operation`, `raw_exec`, `cancel_job`, `get_job`), the Control
   API (`/api/v1`), the binaries' CLI flags and subcommands (`--version`,
   `bootstrap-token`, `policy check`, `dump-operation-schema`), signals, and the logs.
   Never inspect internal stores directly — **except** where an acceptance criterion is
   explicitly about stored state (e.g. "every dispatch produces a queryable audit
   record", which today has no read surface other than the store itself); such steps say
   so explicitly.

4. **Each script is a cumulative delta.** A milestone's script assumes the *previous*
   milestone's script passed and validates what the new milestone added or changed. It
   repeats an earlier step only when the new milestone changed that behavior. The
   baseline script is the one exception (nothing preceded it).

5. **Each script ends with a sign-off checklist**: the date, the exact version/commit
   validated (`relay --version` / `relay-daemon --version` output), which steps passed,
   which were skipped and why, and the operator who ran it.

6. **Writing or updating the milestone's script is part of the milestone's definition
   of done.** The milestone is not complete until its script exists, runs, and has a
   recorded sign-off — **or the run is explicitly waived** (below). Acceptance criteria live
   on the milestone's issues; durable behaviour lives in `docs/specs/`, whose proof tables are
   the automated half of the same question.

7. **A waived run is recorded, never omitted.** The owner may close a milestone with the
   script written but unrun, accepting the automated suites as sufficient for that
   milestone. When that happens, both the GitHub milestone and the script's own
   header say so: who waived it, when, and **what the run would have covered that CI
   cannot** — real service managers and system tooling, real file ownership and
   permissions, multi-machine behavior, and anything an operator can only judge by
   reading output with their own eyes. The script is not deleted or downgraded; it stays
   ready for the next fleet that exists. A waiver is a dated decision with a stated cost,
   which is the opposite of quietly skipping a step.

   First use: v0.2.0 (2026-08-10).

## Language and safety

Scripts use the [GLOSSARY.md](../../GLOSSARY.md) ubiquitous language exactly (Relay,
relay-daemon, Node, Operation, Raw Exec, Policy, Job, Task, Selector, Freeze, Plan, …).
Steps that are destructive (revocation, wrong-CA probes) or that require real
infrastructure or a published release are clearly marked so an operator can run the
non-destructive core on a laptop and the full script on disposable machines.
