package capability

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/mcptask"
)

// mcptask.go is the capability layer's half of the MCP Tasks extension (#374,
// ADR-0028): minting a task handle when a dispatch parks, resolving one, and
// cancelling one.
//
// It lives HERE rather than in the MCP surface for the ordinary reason
// (invariant 10): resolving a handle reads an approval Request and derives a
// status from it, and cancelling one may cancel a Job. Both are control-plane
// decisions, and a surface that made them would be a second control path — the
// first to be forgotten when a rule changes. The MCP surface renders what this
// returns and decides nothing.
//
// # The security boundary, stated once
//
// Cancelling a task handle NEVER touches the approval Request. That is not a
// convention observed by the code below; it is visible in it — CancelTask reads
// s.approvals.store only to render the answer, and writes to it nowhere. A cancel
// arrives over the MCP session, which is the AI's own channel, and if it could
// withdraw or decide a pending approval the requesting session would hold a
// lever over exactly the decision ADR-0027 exists to keep off that channel: an
// AI-agent could yank a request back the moment it sensed a denial coming, erasing
// the evidence a human was about to rule on.

// MCPTaskStore is the task-handle persistence this layer needs. It mirrors
// mcptask.Repository minus the sweep, which is a background concern rather than
// a control-plane one.
//
// Nil means Tasks are not wired: no handle is ever minted, ParkedError carries
// no task id, and Resolve/Cancel report ErrTasksUnavailable. That is the
// pre-#374 behaviour and it is fully functional — the universal
// `pending_approval` result path (#371) does not involve handles at all, which
// is ADR-0028's requirement that the shim be deletable without loss.
type MCPTaskStore interface {
	Create(ctx context.Context, h mcptask.Handle) error
	Get(ctx context.Context, id, accountID string) (mcptask.Handle, error)
	ByApprovalRequest(ctx context.Context, approvalRequestID string) (mcptask.Handle, error)
	BindJob(ctx context.Context, id, jobID string, status mcptask.Status, now time.Time) error
	RecordStatus(ctx context.Context, id string, status mcptask.Status, now time.Time) error
	Cancel(ctx context.Context, id, accountID string, now time.Time) (mcptask.Handle, error)
}

// ErrTasksUnavailable is returned when a task-handle operation is attempted on
// a Relay that has not wired the handle store.
var ErrTasksUnavailable = errors.New("capability: MCP task handles are not enabled on this Relay")

// TaskView is one resolved task handle: everything a surface needs to render
// SEP-2663's task shape, with nothing left for it to derive.
//
// Status in particular is computed here, from the approval Request read fresh
// on this call. A surface handed the stored column and asked to work out what
// it meant would be a surface that could get it wrong.
type TaskView struct {
	TaskID string
	Status mcptask.Status

	// ApprovalRequestID and JobID are the two bindings. JobID is empty until an
	// approved dispatch has actually run.
	ApprovalRequestID string
	JobID             string

	// Summary is the Relay-authored description of what is waiting — the same
	// text the approver sees, never anything the requesting AI-agent wrote.
	Summary string

	// PlanHash lets a caller correlate the handle with the parked dispatch and
	// with any decision made about it.
	PlanHash string

	CreatedAt     time.Time
	LastUpdatedAt time.Time
	ExpiresAt     time.Time
}

// mintTaskHandle attaches a task handle to a parked dispatch, returning its ID.
//
// FAILURE HERE IS NOT FATAL, deliberately, and this is the one place in the
// park path where that is true. A handle is a delivery convenience; the
// guarantee is the park itself, which has already been recorded and audited by
// the time this runs. ADR-0028 requires the universal path to stay fully
// functional with the shim deleted, so a handle store that is down must degrade
// to exactly that path rather than turning a working park into a failed
// dispatch. The caller gets an empty task id and the ordinary
// `pending_approval` result.
func (a *Approvals) mintTaskHandle(ctx context.Context, p Principal, requestID string) (id string, expiresAt time.Time) {
	if a.tasks == nil || a.store == nil || requestID == "" {
		return "", time.Time{}
	}

	// A re-drive of an already-parked dispatch must re-attach to the existing
	// handle rather than mint a second one for the same wait: one handle per
	// parked dispatch is the mapping ADR-0028 fixes, and two handles pointing at
	// one Request would let a client believe it had two things to wait for.
	if existing, err := a.tasks.ByApprovalRequest(ctx, requestID); err == nil {
		return existing.ID, existing.ExpiresAt
	} else if !errors.Is(err, mcptask.ErrNotFound) {
		return "", time.Time{}
	}

	req, err := a.store.Get(ctx, requestID)
	if err != nil {
		return "", time.Time{}
	}
	mint := a.newApprovalID
	if mint == nil {
		mint = defaultID
	}
	id, err = mint()
	if err != nil {
		return "", time.Time{}
	}

	h := mcptask.NewHandle(id, req, p.AccountID, p.Account, a.clock())
	if err := a.tasks.Create(ctx, h); err != nil {
		// Lost a race with a concurrent re-drive: the unique index refused the
		// second handle, so the first one is the answer.
		if existing, getErr := a.tasks.ByApprovalRequest(ctx, requestID); getErr == nil {
			return existing.ID, existing.ExpiresAt
		}
		return "", time.Time{}
	}
	return h.ID, h.ExpiresAt
}

// bindTaskHandleJob records the Job an approved dispatch produced against the
// handle that was waiting for it, so a poll after the release reports
// `completed` and can render the results.
//
// Non-fatal for the same reason mintTaskHandle is: the dispatch has already
// happened and is already audited. A missed binding costs a client a stale
// `working` until the handle expires; it costs the fleet nothing.
func (a *Approvals) bindTaskHandleJob(ctx context.Context, requestID, jobID string) {
	if a.tasks == nil || requestID == "" || jobID == "" {
		return
	}
	h, err := a.tasks.ByApprovalRequest(ctx, requestID)
	if err != nil {
		return
	}
	if err := a.tasks.BindJob(ctx, h.ID, jobID, mcptask.StatusCompleted, a.clock()); err != nil {
		// Still non-fatal — see the doc comment above — but a client left
		// polling a handle that never reports its Job is a symptom an
		// operator should be able to find, so it goes to the log rather
		// than vanishing the way it did before.
		a.rec.logger().WarnContext(ctx, "capability: binding the MCP task handle to its Job failed",
			"job_id", jobID, "approval_id", requestID, "error", err)
	}
}

// ResolveTask answers "what is this task handle doing now?" for p.
//
// p's Account is passed to the store rather than checked here, so the ownership
// rule is enforced in the query: a handle belonging to somebody else is
// indistinguishable from one that never existed (see mcptask.ErrNotFound). That
// matters more for this method than it looks, because resolving is not merely a
// read — it is the entry point [4/6] extends to hand a stored call back through
// the dispatch path.
func (s *Service) ResolveTask(ctx context.Context, p Principal, taskID string) (TaskView, error) {
	if s.approvals.tasks == nil || s.approvals.store == nil {
		return TaskView{}, ErrTasksUnavailable
	}

	h, err := s.approvals.tasks.Get(ctx, taskID, p.AccountID)
	if err != nil {
		return TaskView{}, err
	}
	req, err := s.approvals.store.Get(ctx, h.ApprovalRequestID)
	if err != nil {
		return TaskView{}, fmt.Errorf("capability: read approval request for task handle %q: %w", taskID, err)
	}

	now := s.clock()
	view := taskView(h, req, now)

	// Record what we are about to tell the client, but only when it CHANGED.
	// Writing on every poll would make a read-shaped, high-frequency operation
	// a write on the hot path; writing never would lose the record of what a
	// client was actually told, which is the column's only purpose. A failure
	// here does fail the call: an unrecordable status change is the one case
	// where the bookkeeping and the answer disagree, and this Relay's posture
	// on that is to stop rather than to answer invisibly.
	if view.Status != h.LastStatus {
		if err := s.approvals.tasks.RecordStatus(ctx, h.ID, view.Status, now); err != nil {
			return TaskView{}, fmt.Errorf("capability: record task handle status: %w", err)
		}
	}
	return view, nil
}

// CancelTask ends p's interest in a task handle.
//
// The two cases, and why they are different:
//
//   - A Job exists, so an approved dispatch is or was running. Cancelling goes
//     through the ORDINARY CancelJob path, unchanged — same honest-cancel
//     semantics (ADR-0013: a Task that already finished reports its real
//     outcome, never a fabricated `cancelled`), same audit record, and it
//     INHERITS CancelJob's operator floor (#595) and its machine-Account
//     scoping (#614, owner decision 2026-09-17): p must satisfy
//     AuthorizeControl(ControlCancelJob), and — if p is a machine Account —
//     the Job's recorded requester must be p, or this returns that refusal
//     before the handle itself is touched. The requester is recorded on the
//     Job at creation (#616), so a machine Account's own still-running Task
//     can cancel itself through this path.
//   - Still parked, so there is nothing running to stop and CancelJob is never
//     called. Only the handle is marked, and that stays owner-scoped and
//     UNGATED by role: s.approvals.tasks.Get already requires p.AccountID to own the
//     handle, and there is no Job for AuthorizeControl to gate. The approval
//     Request is left exactly as it was: pending, visible in the queue,
//     decidable by a human, and re-attachable by a re-drive of the same Plan.
//
// The second case is the security boundary this method exists to hold. See the
// file header: nothing below writes to s.approvals.store, and that absence is the
// enforcement.
func (s *Service) CancelTask(ctx context.Context, p Principal, taskID string) (TaskView, error) {
	if s.approvals.tasks == nil || s.approvals.store == nil {
		return TaskView{}, ErrTasksUnavailable
	}

	h, err := s.approvals.tasks.Get(ctx, taskID, p.AccountID)
	if err != nil {
		return TaskView{}, err
	}

	// Cancel the real work FIRST. If that fails the handle stays live, so the
	// client learns its cancel did not take rather than being told the task is
	// cancelled while Tasks keep running on the fleet.
	if h.JobID != "" {
		if err := s.CancelJob(ctx, p, h.JobID); err != nil {
			return TaskView{}, err
		}
	}

	now := s.clock()
	cancelled, err := s.approvals.tasks.Cancel(ctx, taskID, p.AccountID, now)
	if err != nil {
		return TaskView{}, err
	}
	req, err := s.approvals.store.Get(ctx, cancelled.ApprovalRequestID)
	if err != nil {
		return TaskView{}, fmt.Errorf("capability: read approval request for task handle %q: %w", taskID, err)
	}
	return taskView(cancelled, req, now), nil
}

// taskView renders a handle and its live approval Request into the surface's
// view. The status is computed by the domain, never assembled here.
func taskView(h mcptask.Handle, req approval.Request, now time.Time) TaskView {
	return TaskView{
		TaskID:            h.ID,
		Status:            h.Status(req, now),
		ApprovalRequestID: h.ApprovalRequestID,
		JobID:             h.JobID,
		Summary:           req.Summary,
		PlanHash:          req.PlanHash,
		CreatedAt:         h.CreatedAt,
		LastUpdatedAt:     h.LastUpdatedAt,
		ExpiresAt:         h.ExpiresAt,
	}
}
