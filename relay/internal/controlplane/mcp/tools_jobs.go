package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// This is an EXEC file (listed in no_dispatch_test.go's execFiles — see
// tools_execution.go's doc comment for the full rationale).

// cancelJobInput is cancel_job's argument.
type cancelJobInput struct {
	JobID string `json:"job_id" jsonschema:"the Job id to cancel — from run_operation/raw_exec's job_id, or get_job."`
}

// cancelJobOutput is cancel_job's success shape: an empty acknowledgement
// carrying JobID back, so a caller can confirm which Job it cancelled.
type cancelJobOutput struct {
	JobID string `json:"job_id"`
}

// getJobInput is get_job's argument.
type getJobInput struct {
	JobID string `json:"job_id" jsonschema:"the Job id to re-read — from run_operation/raw_exec's job_id."`
}

// registerJobTools registers cancel_job and get_job on srv.
//
// The long-running-Job contract (ADR-0004): run_operation/raw_exec
// return as soon as the Job's Tasks are persisted (or, with wait_seconds, once
// they finish), and get_job is the polling path — it re-reads the same Job by
// id and reports job_status running or complete — without a second, separate
// polling protocol.
func registerJobTools(srv *sdkmcp.Server, exec Executor, results JobResultReader, reads ReadAuditor) {
	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "cancel_job",
		Description: "Cancel a Job's Tasks (ADR-0013): undispatched Tasks are marked cancelled without " +
			"ever being sent, in-flight Tasks are asked to cancel over their Tunnels, and already-" +
			"resolved Tasks keep their truthful outcome. Best-effort for in-flight Tasks — a Task that " +
			"completes before the cancel reaches it reports its real outcome, never a fabricated cancel. " +
			"Requires an Account of operator or above; a viewer is refused and the Job continues. A " +
			"human Account may cancel any Job; a machine Account may cancel only a Job it requested " +
			"itself — a Job with no recorded requester, or another Account's Job, is refused.",
	}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, in cancelJobInput) (*sdkmcp.CallToolResult, cancelJobOutput, error) {
		logPrincipal(ctx, "cancel_job")
		p, err := requirePrincipal(ctx)
		if err != nil {
			return nil, cancelJobOutput{}, err
		}

		if err := exec.CancelJob(ctx, p, in.JobID); err != nil {
			return nil, cancelJobOutput{}, fmt.Errorf("cancel job %q: %w", in.JobID, err)
		}
		return nil, cancelJobOutput(in), nil
	})

	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "get_job",
		Description: "Re-read a Job's per-Node results by id — the result-retrieval/polling shape for a " +
			"Job started via run_operation/raw_exec (which return as soon as the Job is persisted: poll " +
			"get_job until job_status=complete; it also re-reads the Job after cancel_job). While " +
			"job_status=running an unfinished Task's outcome reads unspecified. Per-Node exit_code is present only when a process actually ran and " +
			"exited with a status; a Task that never executed or was killed without one has no exit_code " +
			"key — outcome is the authoritative state. A Task whose daemon report the Relay refused as a " +
			"protocol violation also has no exit_code key and is neither of those: it may well have executed.",
	}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, in getJobInput) (*sdkmcp.CallToolResult, ExecutionOutput, error) {
		// get_job returns a Job's captured per-Node stdout, so it is the
		// sharpest case for read auditing: a caller can read back command
		// output somebody else produced.
		if err := auditRead(ctx, reads, "get_job", ReadEvent{JobID: in.JobID}); err != nil {
			return nil, ExecutionOutput{}, err
		}

		out, err := renderJob(ctx, results, in.JobID)
		if err != nil {
			return nil, ExecutionOutput{}, err
		}
		return nil, out, nil
	})
}
