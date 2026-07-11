package mcp

import (
	"context"
	"fmt"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// This is an EXEC file (no_dispatch_test.go's relaxed partition — see
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
// The long-running-Job contract this issue settles: run_operation/raw_exec
// are synchronous — they block until every matched Node's Task reaches a
// terminal outcome and return the full per-Node result set directly. get_job
// exists to re-read that same Job's results later by id (e.g. after using
// cancel_job to stop it, or simply to poll a still-in-flight Job's Tasks
// from a second call) — the simplest result-retrieval shape that covers both
// "I already have my results" and "let me check again", without requiring a
// second, separate polling protocol.
func registerJobTools(srv *sdkmcp.Server, exec Executor, results JobResultReader) {
	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "cancel_job",
		Description: "Cancel a Job's Tasks (ADR-0013): undispatched Tasks are marked cancelled without " +
			"ever being sent, in-flight Tasks are asked to cancel over their Tunnels, and already-" +
			"resolved Tasks keep their truthful outcome. Best-effort for in-flight Tasks — a Task that " +
			"completes before the cancel reaches it reports its real outcome, never a fabricated cancel.",
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
			"Job started via run_operation/raw_exec (which already block and return full results; " +
			"get_job re-reads the same Job later, e.g. after cancel_job, or to check on a still-in-flight " +
			"Job from a second call).",
	}, func(ctx context.Context, _ *sdkmcp.CallToolRequest, in getJobInput) (*sdkmcp.CallToolResult, executionOutput, error) {
		logPrincipal(ctx, "get_job")

		out, err := renderJob(ctx, results, in.JobID)
		if err != nil {
			return nil, executionOutput{}, err
		}
		return nil, out, nil
	})
}
