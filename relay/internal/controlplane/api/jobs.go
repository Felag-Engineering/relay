package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// jobs.go is the read + stop side of the Control API's execution surface:
// re-read a Job's per-Node results later, and halt one in flight. The REST twin
// of MCP's get_job/cancel_job, over the same capability layer (invariant 10).
// The read goes through the capability read lane, which records it under
// get_job, the MCP tool's name, so an auditor asking who read back command
// output gets one answer across every surface; rendering uses the same helpers
// execution.go's dispatch path uses, so the same Job read through either door
// tells the same story, byte for byte.

// JobReader is the capability read lane's GetJob call, narrowed to the one
// method this route needs. capability.ReadLane satisfies it with no adapter. It
// records the read before it answers and refuses the read if it cannot
// (invariant 10, ADR-0025): this surface records no read of its own.
type JobReader interface {
	GetJob(ctx context.Context, p capability.Principal, jobID string) (capability.JobResult, error)
}

// jobResponse is GET /api/v1/jobs/{id}'s body: the Job's identity plus its
// per-Node Task results, rendered exactly as a dispatch response renders them
// (same perNodeResult shape, same exit_code presence rules). job_status tells a
// poller when to stop (EX-57); it has no omitempty so a poller always has its
// stop condition.
type jobResponse struct {
	JobID     string          `json:"job_id"`
	JobStatus string          `json:"job_status"`
	CreatedAt string          `json:"created_at,omitempty"`
	Results   []perNodeResult `json:"results"`
	Halt      *haltResponse   `json:"halt,omitempty"`

	OutcomeAuditFailure *outcomeAuditFailureResponse `json:"outcome_audit_failure,omitempty"`
}

// cancelJobResponse acknowledges a cancel, carrying the id back so a caller
// can confirm which Job it stopped.
type cancelJobResponse struct {
	JobID string `json:"job_id"`
}

// handleGetJob implements GET /api/v1/jobs/{id}: re-read a Job's per-Node
// results through the capability read lane, which records the read under
// get_job before it returns the Job and refuses the read if it cannot (ADR-0025).
//
// Any authenticated caller may read a Job. That is the same posture the MCP
// get_job tool has, and it is deliberate rather than an omission: Jobs carry no
// owner column (the jobs table is (job_id, created_at)), so there is no
// per-Account scoping to enforce here and inventing one in this handler would
// be a security boundary that only one surface honours. Per-Account visibility
// is an open schema question — until it is settled, the honest
// posture is "authenticated callers may read Jobs, and every read is audited".
func handleGetJob(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}
		if d.JobReader == nil {
			writeProblem(w, http.StatusInternalServerError, "execution unavailable",
				"the Control API was mounted without its execution dependencies")
			return
		}

		jobID, ok := requirePathValue(w, r, "id", "job id required", "")
		if !ok {
			return
		}

		// The lane's text never reaches a problem detail (see nodes.go): the
		// fixed sentences below say what the caller can act on.
		res, err := d.JobReader.GetJob(r.Context(), p, jobID)
		switch {
		case err == nil:
		case errors.Is(err, capability.ErrReadUnaudited):
			writeProblem(w, http.StatusInternalServerError, "read audit failed",
				"the Job was not read because the access record could not be written")
			return
		case errors.Is(err, capability.ErrQueriesUnavailable):
			writeProblem(w, http.StatusInternalServerError, "execution unavailable",
				"the Control API was mounted without its execution dependencies")
			return
		default:
			writeJobError(w, jobID, err)
			return
		}

		out := executionResponseFrom(jobID, controlplane.RenderJobResult(res.Job, res.Tasks))
		writeJSON(w, http.StatusOK, jobResponse{
			JobID:               out.JobID,
			JobStatus:           out.JobStatus,
			CreatedAt:           controlplane.RFC3339(res.Job.CreatedAt),
			Results:             out.Results,
			Halt:                out.Halt,
			OutcomeAuditFailure: out.OutcomeAuditFailure,
		})
	}
}

// handleCancelJob implements POST /api/v1/jobs/{id}/cancel (ADR-0013):
// undispatched Tasks are marked cancelled without ever being sent, in-flight
// Tasks are asked to cancel over their Tunnels, and already-resolved Tasks keep
// their truthful outcome.
//
// The ROLE floor is `operator`, decided by the capability layer's
// AuthorizeControl(ControlCancelJob), not here (invariant 10). A
// refused caller gets writeJobError's authz.ErrUnauthorized branch below,
// before any existence check runs. The SCOPE is also decided in the
// capability layer (owner decision 2026-09-17): a human Account may
// cancel any Job; a machine Account may cancel only a Job it requested
// itself, refused via capability.ErrJobNotRequestedByCaller otherwise.
//
// Best-effort for in-flight Tasks by design: a Task that completes before the
// cancel reaches it reports its real outcome, never a fabricated `cancelled`.
// Cancelling an already-finished Job is therefore a clean 200 no-op — every
// Task is terminal and none is touched — while an unknown id is a 404, which
// is the legible answer to "that Job does not exist" rather than pretending a
// cancel succeeded.
func handleCancelJob(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}
		if d.Exec == nil {
			writeProblem(w, http.StatusInternalServerError, "execution unavailable",
				"the Control API was mounted without its execution dependencies")
			return
		}

		jobID, ok := requirePathValue(w, r, "id", "job id required", "")
		if !ok {
			return
		}

		if err := d.Exec.CancelJob(r.Context(), p, jobID); err != nil {
			writeJobError(w, jobID, err)
			return
		}
		writeJSON(w, http.StatusOK, cancelJobResponse{JobID: jobID})
	}
}

// writeJobError renders a Job-addressed error: an unknown Job id is a 404, a
// role or human-kind refusal unwraps to authz.ErrUnauthorized and
// a machine-Account scoping refusal is capability.ErrJobNotRequestedByCaller
// — both render 403 with the gate's own reason, the same recognize-don't-
// re-decide pattern writeFreezeError and writeExecutionError use — and
// anything else is a 500. The 404 text names the id the caller asked for,
// which is theirs already and discloses nothing.
func writeJobError(w http.ResponseWriter, jobID string, err error) {
	switch {
	case errors.Is(err, jobs.ErrJobNotFound):
		writeProblem(w, http.StatusNotFound, "job not found",
			fmt.Sprintf("no Job with id %q", jobID))
	case errors.Is(err, authz.ErrUnauthorized), errors.Is(err, capability.ErrJobNotRequestedByCaller):
		writeProblem(w, http.StatusForbidden, "forbidden", err.Error())
	default:
		writeProblem(w, http.StatusInternalServerError, "job request failed", err.Error())
	}
}
