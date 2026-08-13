package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// jobs.go is the read + stop side of the Control API's execution surface
// (#357, v0.4.0 [2/7]): re-read a Job's per-Node results later, and halt one in
// flight. The REST twin of MCP's get_job/cancel_job, over the same capability
// layer (invariant 10) and rendering through the same helpers execution.go's
// dispatch path uses — so the same Job read through either door tells the same
// story, byte for byte.

// ReadAuditor records a read-access event (#288, ADR-0025).
//
// Reading a Job returns the captured stdout of a previously-dispatched Task, so
// a caller can read back command output somebody else produced — ADR-0025 calls
// this the sharpest case for read auditing, and it is why the MCP get_job tool
// is audited. A REST twin that skipped the record would be an unaudited back
// door to exactly the same material: same capability, different accountability
// depending on which door was used. So this surface records it too.
//
// **Metadata only, never content**: who read, which capability, which Job, when
// — never what came back. Recording the result would copy the material the
// decision exists to limit into a trail that outlives the Job.
//
// The signature is *auditsink.Sink.RecordRead's exactly, so the composition
// root passes the Sink straight in with no adapter. (MCP needs an adapter only
// because its read files may not name a capability type; this package already
// handles capability.Principal on every route.)
type ReadAuditor interface {
	RecordRead(ctx context.Context, p capability.Principal, tool, selector, nodeID, jobID string) error
}

// readCapabilityGetJob is the name this surface records for a Job read.
//
// Deliberately the MCP tool's name rather than a route string: ADR-0025's
// question is "who read back command output", and an auditor asking it should
// get one answer across every surface instead of having to know each door's
// spelling. Which door was used is still recoverable — the verified lane
// records the Account, its token, and the auth method.
const readCapabilityGetJob = "get_job"

// jobResponse is GET /api/v1/jobs/{id}'s body: the Job's identity plus its
// per-Node Task results, rendered exactly as a dispatch response renders them
// (same perNodeResult shape, same exit_code presence rules).
type jobResponse struct {
	JobID     string          `json:"job_id"`
	CreatedAt string          `json:"created_at,omitempty"`
	Results   []perNodeResult `json:"results"`
}

// cancelJobResponse acknowledges a cancel, carrying the id back so a caller
// can confirm which Job it stopped.
type cancelJobResponse struct {
	JobID string `json:"job_id"`
}

// handleGetJob implements GET /api/v1/jobs/{id}: re-read a Job's per-Node
// results.
//
// Any authenticated caller may read a Job. That is the same posture the MCP
// get_job tool has, and it is deliberate rather than an omission: Jobs carry no
// owner column (the jobs table is (job_id, created_at)), so there is no
// per-Account scoping to enforce here and inventing one in this handler would
// be a security boundary that only one surface honours. Per-Account visibility
// is a schema question, noted on #357 — until it is settled, the honest
// posture is "authenticated callers may read Jobs, and every read is audited".
func handleGetJob(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := principal(w, r)
		if !ok {
			return
		}
		if d.Jobs == nil {
			writeProblem(w, http.StatusInternalServerError, "execution unavailable",
				"the Control API was mounted without its execution dependencies")
			return
		}

		jobID := r.PathValue("id")
		if jobID == "" {
			writeProblem(w, http.StatusBadRequest, "job id required", "")
			return
		}

		// Audit the read BEFORE returning any content, and fail closed if it
		// cannot be recorded (ADR-0025): a Relay that cannot write its access
		// trail must stop answering rather than answer invisibly. Recorded even
		// when the Job turns out not to exist — an attempted read is exactly
		// what an incident reviewer wants to see.
		if err := auditRead(r.Context(), d.Reads, p, readCapabilityGetJob, jobID); err != nil {
			writeProblem(w, http.StatusInternalServerError, "read audit failed", err.Error())
			return
		}

		out, err := renderJob(r.Context(), d.Jobs, jobID)
		if err != nil {
			writeJobError(w, jobID, err)
			return
		}

		resp := jobResponse{JobID: out.JobID, Results: out.Results}
		if job, err := d.Jobs.GetJob(r.Context(), jobID); err == nil {
			resp.CreatedAt = rfc3339(job.CreatedAt)
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// handleCancelJob implements POST /api/v1/jobs/{id}/cancel (ADR-0013):
// undispatched Tasks are marked cancelled without ever being sent, in-flight
// Tasks are asked to cancel over their Tunnels, and already-resolved Tasks keep
// their truthful outcome.
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

		jobID := r.PathValue("id")
		if jobID == "" {
			writeProblem(w, http.StatusBadRequest, "job id required", "")
			return
		}

		if err := d.Exec.CancelJob(r.Context(), p, jobID); err != nil {
			writeJobError(w, jobID, err)
			return
		}
		writeJSON(w, http.StatusOK, cancelJobResponse{JobID: jobID})
	}
}

// writeJobError renders a Job-addressed error: an unknown Job id is a 404,
// anything else a 500. The 404 text names the id the caller asked for, which is
// theirs already and discloses nothing.
func writeJobError(w http.ResponseWriter, jobID string, err error) {
	if errors.Is(err, jobs.ErrJobNotFound) {
		writeProblem(w, http.StatusNotFound, "job not found",
			fmt.Sprintf("no Job with id %q", jobID))
		return
	}
	writeProblem(w, http.StatusInternalServerError, "job request failed", err.Error())
}

// auditRead records one read-access event, or returns an error that fails the
// request (fail closed, ADR-0025 — see ReadAuditor).
//
// A nil auditor skips recording, matching the MCP surface's precedent: it keeps
// tests and any not-yet-wired surface working rather than failing shut on a
// missing dependency. The composition root always supplies one.
func auditRead(ctx context.Context, a ReadAuditor, p capability.Principal, capabilityName, jobID string) error {
	if a == nil {
		return nil
	}
	if err := a.RecordRead(ctx, p, capabilityName, "", "", jobID); err != nil {
		return fmt.Errorf("record read audit for %s: %w", capabilityName, err)
	}
	return nil
}
