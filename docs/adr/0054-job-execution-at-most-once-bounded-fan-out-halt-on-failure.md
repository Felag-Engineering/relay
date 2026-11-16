# Job execution: at-most-once Tasks, bounded fan-out, and a halt on failure

**Status:** Accepted (owner decision 2026-11-15).

Behaviour: `docs/specs/execution.md`. This ADR supersedes ADR-0004, and supersedes in part
ADR-0010's and ADR-0012's amendments of 2026-09-15 where they put the blast caps in the store.
The reasoning is recorded here; there is no separate proposal.

## Decision

A dispatch becomes one Job of one Task per targeted Node, handed back by ID. Each Task runs at
most once, so nothing a crash or a reconnect does ever runs it twice. Work fans out
concurrently, a fixed 16 Tasks of one Job at a time. Once a change fails on one Node, it is sent
to no further Nodes. A caller that retries with the same idempotency key within 24 hours gets
the first Job back, not a second run. Every Task has a timeout no longer than 300 seconds, and
asking for longer is refused rather than quietly cut. Nothing is queued for an offline Node and
nothing is rolled back: the caller decides what next.

## The decisions

1. **A Job, handed back.** Where a dispatch is accepted, it creates one Job with one Task per
   resolved Node, returns the Job's ID for the caller to poll, and reports an outcome per Task.
2. **At most once (invariant 4).** A Task is stored before any Task of its Job is sent, and
   recorded as sent before it is sent. A Task re-sent after a Relay restart is safe only because
   the relay-daemon dedups by Task ID. Execution never becomes at-least-once (EX-29 to EX-31).
3. **No store-and-forward, no rollback.** A Task for a Node not connected at dispatch resolves
   `unreachable` at once, and a Task never sent is never run later on the Relay's own
   initiative. Arbitrary actions cannot be undone, so the caller decides remediation.
4. **The blast-radius cap (invariants 5 and 13).** Where a dispatch would reach Nodes, the Relay
   caps their number before dispatch, by risk class (ADR-0012). The cap values are reach-bounding
   settings in the Relay's configuration file (`relay-configuration.md`), so no session can
   change one.
5. **Bounded fan-out.** At most 16 Tasks of one Job are in flight, a built-in constant (EX-22).
6. **Per-Node concurrency by risk class.** A Node runs `mutate` Tasks one at a time and `read`
   Tasks under a small fixed bound (EX-23).
7. **A failing mutation halts.** Where a `mutate` Job sees its first `failure` or `timeout`, no
   further Task of it is sent and each unsent Task resolves `cancelled`; Tasks already in flight
   finish. A Task in flight when its Node disconnects from a serving Relay, or a halted Job's
   in-flight Task across a Relay restart, may have run: it is a `failure`, never re-sent (EX-28,
   EX-62). Outcomes that describe a Node rather than the change do not halt, and a `read` Job
   never halts.
8. **An idempotency key above Task-ID dedup.** Task-ID dedup cannot catch a re-sent dispatch,
   which would mint new Tasks. Where a dispatch carries a key, a repeat by the same Account
   within a fixed 24 hours returns the existing Job, and the same key with different arguments
   is refused. The Relay never infers a repeat from request content.
9. **One Task timeout ceiling.** A Task's timeout defaults to 30 seconds and is never above 300,
   the same for every Operation. Where a caller asks for more, the Relay refuses the dispatch and
   names the ceiling, rather than accepting a value the daemon would cut without saying so.
10. **Output is final and capped** by the daemon before the wire (EX-42).

## Why

ADR-0004 decided at-most-once, the cap and fail-fast for offline Nodes; the code then decided
the in-flight bound, the halt and the idempotency key with no record, and the execution spec
cannot bind claims to decisions nobody signed. Each addition keeps the original premise: every
Task that runs has someone behind it who decided it, now.

- **The bound is a constant** because pre-release Relay prefers a fixed, documented limit to a
  setting.
- **The halt** keeps one bad change from reaching the whole mutate cap. A Node that refused or
  was unreachable says nothing about the change, so it does not halt. Across a restart the Relay
  cannot know whether an in-flight Task ran, and says so rather than guessing.
- **The key's window is fixed** because a setting would be configuration surface it does not
  need (invariant 11), and 24 hours covers any client's retry after a broken connection.
- **The caps stay in the file** because a session that could raise a cap is R15's risk, and the
  MVP needs no one to turn that dial from a browser; ADR-0047 made the same call for gate rules.
- **One ceiling, refused above** because a per-Operation timeout is a mechanism nobody needs
  yet, and silently cutting a caller's timeout tells an AI-agent its Task ran longer than it did.

## What changes

- Invariants 4, 5 and 11 cite this ADR.
- `execution.md` states each decision as claims. The Relay's refusal above the timeout ceiling,
  and a Control API that hands back the Job and takes the idempotency key, are designed there.
- The threat model records the halt's in-flight remainder (R56).

## Alternatives

- **Rewrite ADR-0004.** Rejected: it had used its one amendment, and ADR-0046 allows a
  rewrite only to restate; these are new decisions.
- **A per-Operation timeout a caller may only shorten.** Rejected for now: no Operation declares
  one, and it needs a contract change nobody needs. It waits in
  `roadmap: relay/failure-policy-and-retries`.
- **Let the daemon cut a long timeout silently.** Rejected: the caller is never told.
- **Halt every Job on its first failure.** Rejected for reads: one Node failing a read says
  nothing about the others.
