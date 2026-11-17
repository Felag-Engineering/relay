package capability

import (
	"context"
	"time"
)

// outcomeAuditFailureRecorder records on a Job that its outcome audit write failed
// (EX-66). Only the real Job engine implements it; noopDispatcher and the test spies
// record nothing, because they persist no Job.
type outcomeAuditFailureRecorder interface {
	recordOutcomeAuditFailure(ctx context.Context, jobID string) error
}

var _ outcomeAuditFailureRecorder = (*jobEngine)(nil)

func (e *jobEngine) recordOutcomeAuditFailure(ctx context.Context, jobID string) error {
	return e.jobsRepo.RecordOutcomeAuditFailure(ctx, jobID, e.now())
}

// outcomeAuditFailureWriteTimeout bounds the failure record: a local store write,
// bounded so a wedged store cannot hold accounting, and with it Start's Done.
const outcomeAuditFailureWriteTimeout = 5 * time.Second

// recordOutcomeAuditFailure records on the Job that writing its outcome to the audit
// trail failed (EX-66). It runs on a fresh context detached from ctx, so a dropped
// caller cannot strand it. When it fails too, the log holds both failures and the
// job_id, never the entry's arguments, argv or results.
func (s *Execution) recordOutcomeAuditFailure(ctx context.Context, jobID string, auditErr error) {
	if jobID == "" {
		return
	}
	r, ok := s.disp.(outcomeAuditFailureRecorder)
	if !ok {
		return
	}
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), outcomeAuditFailureWriteTimeout)
	defer cancel()
	if err := r.recordOutcomeAuditFailure(wctx, jobID); err != nil {
		s.logger().ErrorContext(wctx, "capability: a Job's outcome audit write failed, and recording that failure on the Job failed too; the Job does not carry the failure",
			"job_id", jobID, "audit_error", auditErr, "record_error", err)
	}
}
