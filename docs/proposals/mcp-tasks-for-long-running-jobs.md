# MCP Tasks for long-running Jobs

**Status:** idea (`2026-10-22`). Origin: owner review of the approval spec; the approval use of
Tasks is cut for the MVP (ADR-0028's shim, `approval.md` AP-71).

## Problem

A Job can run for minutes across hundreds of Nodes. Today the AI-agent waits up to
`wait_seconds` inside `run_operation`, then polls `get_job` and stops work with `cancel_job`, a
Relay-specific pattern the model has to learn and that spends a turn on every poll. The MCP Tasks
extension (SEP-2663, in the 2026-07-28 revision) is the protocol's own shape for exactly this:
a long call returns a handle, and the client checks it, reads the result, or cancels it.

## Proposal

When a dispatch is still running at the end of its wait, `run_operation` and `raw_exec` return an
MCP task handle to a client that negotiated Tasks. `tasks/get` reports the Job's progress and,
once it finishes, its per-Node results; `tasks/cancel` is `cancel_job`. A client that did not
negotiate Tasks sees today's behaviour unchanged. Gleipnir, which we control, is the first
consumer: Tasks returns when we decide Gleipnir should use it, not when other clients catch up.

The approval use, where a parked request for a client that cannot be asked became a handle, is
not coming back: elicitation answers approvals, and `pending_approval` covers the rest.

## Changes

`execution.md` (a Job's MCP surface); ADR-0028, rewritten around Jobs rather than approval, or
superseded; `approval.md` loses AP-71 when the cut lands; the glossary's *MCP task handle*.

## Objections

1. **Relay's Go MCP library does not implement Tasks** (go-sdk#626), so Relay carries its own shim
   on the security surface, outside the library. — open. The removed approval shim, in git
   history, is the starting point; its result rewrite and `tasks/get`/`tasks/cancel` methods carry
   over, its approval-derived status does not.
2. **Few clients consume Tasks.** As of 2026-10-22 Claude Code (anthropics/claude-code#102347) and
   Codex have open requests, the Python SDK has no client side, and smaller clients (mcpc,
   Strands' TypeScript harness) do. — Accepted: Gleipnir is enough of a reason.
3. **Does a handle that outlives the call keep at-most-once execution (invariant 4)?** Polling a
   handle must read a Job, never dispatch one. — open.
4. **A handle is not a bearer capability.** Resolving one must check the caller, as the approval
   shim did. — open.
