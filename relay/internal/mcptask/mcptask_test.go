package mcptask

import (
	"errors"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

var now = time.Date(2026, 8, 17, 9, 0, 0, 0, time.UTC)

func parkedRequest() approval.Request {
	return approval.NewRequest("req-1", "hash-1", "acct-g", "gleipnir-prod",
		jobs.Action{Kind: jobs.ActionOperation, OperationName: "service.restart", RiskClass: jobs.RiskClassMutate},
		[]string{"node-a"}, approval.SelectorShape{}, []string{"prod-mutates"},
		approval.Requirement{Count: 1, Channel: approval.ChannelOutOfBand, TTL: time.Hour},
		now)
}

func mintedHandle() Handle {
	return NewHandle("task-1", parkedRequest(), "acct-g", "gleipnir-prod", now)
}

// TestStatusFollowsTheApprovalRequest is the acceptance criterion "status is
// derived from approval/Job state in a test that mutates the underlying state
// and re-reads the handle".
//
// The handle is created ONCE and never written to between cases: every
// different answer below comes from the Request changing underneath it. That is
// the property — a stored status column could not produce these results without
// something remembering to update it, and the thing that changes the Request
// (a decision on the Control API, the expiry sweeper) does not know handles
// exist.
func TestStatusFollowsTheApprovalRequest(t *testing.T) {
	h := mintedHandle()

	approved := parkedRequest()
	approved.State = approval.StateApproved
	denied := parkedRequest()
	denied.State = approval.StateDenied
	expiredState := parkedRequest()
	expiredState.State = approval.StateExpired

	cases := []struct {
		name string
		req  approval.Request
		at   time.Time
		want Status
	}{
		{"pending is working", parkedRequest(), now, StatusWorking},
		{"approved but not yet run is still working", approved, now, StatusWorking},
		{"denied is failed", denied, now, StatusFailed},
		{"expired is failed", expiredState, now, StatusFailed},
		{
			// A Request past its deadline but still Pending in the store reads
			// as expired to every other caller, so it must read that way here
			// — otherwise a sweeper outage leaves handles cheerfully reporting
			// `working` for requests nothing can decide.
			"past its deadline while still pending is failed",
			parkedRequest(), now.Add(2 * time.Hour), StatusFailed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.Status(tc.req, tc.at); got != tc.want {
				t.Errorf("Status = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestStatusCompletedOnceAJobIsBound: a bound Job means the approved dispatch
// ran. Service.Run is synchronous, so there is no in-between.
func TestStatusCompletedOnceAJobIsBound(t *testing.T) {
	h := mintedHandle()
	h.JobID = "job-1"

	approved := parkedRequest()
	approved.State = approval.StateApproved

	if got := h.Status(approved, now); got != StatusCompleted {
		t.Errorf("Status = %v, want completed", got)
	}
}

// TestCancellationOutranksEverything: the client asked to stop being told, and
// that answer does not depend on what the humans are doing.
func TestCancellationOutranksEverything(t *testing.T) {
	h := mintedHandle()
	h.CancelledAt = now

	for _, state := range []approval.State{
		approval.StatePending, approval.StateApproved, approval.StateDenied, approval.StateExpired,
	} {
		req := parkedRequest()
		req.State = state
		if got := h.Status(req, now); got != StatusCancelled {
			t.Errorf("state %v: Status = %v, want cancelled", state, got)
		}
	}
}

// TestADecidedRequestOutranksTheHandleDeadline is why the ordering in Status is
// not arbitrary. If the handle's own expiry were checked first, a request a
// human actually DENIED would report as a lapse — losing the single piece of
// information the requester most needs.
func TestADecidedRequestOutranksTheHandleDeadline(t *testing.T) {
	h := mintedHandle()
	h.ExpiresAt = now.Add(-time.Minute) // already lapsed

	denied := parkedRequest()
	denied.State = approval.StateDenied

	if got := h.Status(denied, now); got != StatusFailed {
		t.Fatalf("Status = %v, want failed", got)
	}
	// Both paths render as failed, so prove the ordering directly: a denial
	// must not be reachable only through the expiry branch.
	live := mintedHandle()
	if got := live.Status(denied, now); got != StatusFailed {
		t.Errorf("a denied request on a live handle = %v, want failed", got)
	}
}

// TestHandleNeverOutlivesItsRequest: a handle that could be polled after its
// subject stopped being decidable could only ever report on nothing.
func TestHandleNeverOutlivesItsRequest(t *testing.T) {
	req := parkedRequest() // TTL 1h
	h := NewHandle("task-1", req, "acct-g", "gleipnir-prod", now)

	if h.ExpiresAt.After(req.ExpiresAt) {
		t.Errorf("handle expires %v, after the request's %v", h.ExpiresAt, req.ExpiresAt)
	}

	// And the code ceiling binds even when the request's own TTL is generous —
	// a lenient gate rule must not silently mint week-long poll tokens carrying
	// somebody's plan summary.
	long := parkedRequest()
	long.ExpiresAt = now.Add(30 * 24 * time.Hour)
	capped := NewHandle("task-2", long, "acct-g", "gleipnir-prod", now)
	if capped.ExpiresAt.Sub(now) > MaxTTL {
		t.Errorf("handle lives %v, above the %v maximum", capped.ExpiresAt.Sub(now), MaxTTL)
	}
}

// TestOwnershipIsCheckedByIDNotName: a rename must not hand somebody else's
// handle to whoever inherits the name.
func TestOwnershipIsCheckedByIDNotName(t *testing.T) {
	h := mintedHandle()

	if !h.OwnedBy("acct-g") {
		t.Error("the minting account does not own its own handle")
	}
	if h.OwnedBy("acct-other") {
		t.Error("a different account owns this handle")
	}
	// An empty ID is never an owner — otherwise an unauthenticated path that
	// forgot to populate the account would own everything.
	if h.OwnedBy("") {
		t.Error("the empty account id owns this handle")
	}
}

// TestValidateRefusesAnUnownedOrUnboundedHandle: every branch here is something
// a reader of the table would otherwise have to treat as "maybe".
func TestValidateRefusesAnUnownedOrUnboundedHandle(t *testing.T) {
	cases := map[string]func(*Handle){
		"no id":               func(h *Handle) { h.ID = "" },
		"no approval request": func(h *Handle) { h.ApprovalRequestID = "" },
		"no owner":            func(h *Handle) { h.AccountID = "" },
		"no deadline":         func(h *Handle) { h.ExpiresAt = time.Time{} },
		"deadline before creation": func(h *Handle) {
			h.ExpiresAt = h.CreatedAt.Add(-time.Minute)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := mintedHandle()
			mutate(&h)
			if err := h.Validate(); !errors.Is(err, ErrInvalid) {
				t.Errorf("Validate = %v, want ErrInvalid", err)
			}
		})
	}

	if err := mintedHandle().Validate(); err != nil {
		t.Errorf("a well-formed handle was refused: %v", err)
	}
}

// TestStatusZeroValueIsNotWorking: a forgotten computation must not silently
// read as a live task.
func TestStatusZeroValueIsNotWorking(t *testing.T) {
	var s Status
	if s == StatusWorking {
		t.Fatal("the zero Status is `working`; a missed derivation would read as a live task")
	}
	if s.String() != "unspecified" {
		t.Errorf("zero Status renders as %q, want unspecified", s.String())
	}
	if s.Terminal() {
		t.Error("the zero Status reports terminal")
	}
}

// TestParseStatusRoundTrips: the store writes String() and reads ParseStatus,
// so the two must agree for every value or a handle's recorded history decays
// into "unspecified" on the next read.
func TestParseStatusRoundTrips(t *testing.T) {
	for _, s := range []Status{
		StatusWorking, StatusInputRequired, StatusCompleted, StatusFailed, StatusCancelled,
	} {
		if got := ParseStatus(s.String()); got != s {
			t.Errorf("ParseStatus(%q) = %v, want %v", s.String(), got, s)
		}
	}
	if got := ParseStatus("something-else"); got != StatusUnspecified {
		t.Errorf("ParseStatus(unknown) = %v, want unspecified rather than a guess", got)
	}
}

// TestTTLMillisNeverGoesNegative: SEP-2663's ttlMs on a lapsed handle must be
// zero, not a negative window a client would treat as garbage.
func TestTTLMillisNeverGoesNegative(t *testing.T) {
	h := mintedHandle()
	if got := TTLMillis(h.ExpiresAt, now.Add(2*time.Hour)); got != 0 {
		t.Errorf("TTLMillis on a lapsed handle = %d, want 0", got)
	}
	if got := TTLMillis(h.ExpiresAt, now); got <= 0 {
		t.Errorf("TTLMillis on a live handle = %d, want positive", got)
	}
}
