package capability

import (
	"context"
	"fmt"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
)

// readlane_jobresult.go is the one read of a Job's stored result. It follows
// readlane.go's order: validate, record (fail closed), read. The record is for
// the id asked for, so a probe of a missing Job is on the trail, and it is
// written under one name on every surface.

// WithJobResultSource wires the Job-result read into the lane.
func WithJobResultSource(src JobResultSource) ReadLaneOption {
	return func(l *ReadLane) { l.jobResults = src }
}

// toolGetJob is the MCP tool's own name: the surface-neutral name every
// surface records for a Job read, on the same precedent as toolDescribeNode.
const toolGetJob = "get_job"

// JobResult is one Job and every one of its Tasks, as stored.
//
// Output is NOT stripped here, unlike QueryTasks: this is the result-retrieval
// read that exists to return what ran, and a read's output is held only in its
// Task row (EX-45). Rendering and truncation stay with the adapters
// (controlplane.RenderTaskResult).
type JobResult struct {
	Job   jobs.Job
	Tasks []jobs.Task
}

// GetJob returns a Job's stored result. It records the read before the store
// is consulted and refuses the read if it cannot, or if the lane has no Job
// store or no audit sink.
func (l *ReadLane) GetJob(ctx context.Context, p Principal, jobID string) (JobResult, error) {
	if err := l.jobResultsReadable(); err != nil {
		return JobResult{}, err
	}
	// Bounded before the record so an oversized probe cannot use the trail as
	// storage. Answered as not found: no Job id the Relay issues can be this
	// long, and the route publishes no 400. An empty id is recorded, then
	// reported not found.
	if len(jobID) > maxJobIDBytes {
		return JobResult{}, fmt.Errorf("get job: job id exceeds %d bytes: %w", maxJobIDBytes, jobs.ErrJobNotFound)
	}
	if err := l.recordQueryRead(ctx, p, toolGetJob, "", "", jobID); err != nil {
		return JobResult{}, err
	}
	job, err := l.jobResults.GetJob(ctx, jobID)
	if err != nil {
		return JobResult{}, fmt.Errorf("get job %q: %w", jobID, err)
	}
	tasks, err := l.jobResults.TasksByJob(ctx, jobID)
	if err != nil {
		return JobResult{}, fmt.Errorf("list tasks for job %q: %w", jobID, err)
	}
	return JobResult{Job: job, Tasks: tasks}, nil
}

// jobResultsReadable refuses a lane with no Job store, then one that cannot
// audit, exactly as registryReadable does for Node reads.
func (l *ReadLane) jobResultsReadable() error {
	if l.jobResults == nil {
		return fmt.Errorf("%w: no Job store is configured on this Relay", ErrQueriesUnavailable)
	}
	return l.auditSinkPresent()
}
