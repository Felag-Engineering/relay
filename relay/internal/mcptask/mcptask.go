// Package mcptask is the Relay's domain model for the MCP task handle
// (SEP-2663, ADR-0028): the protocol-native envelope a Tasks-capable client
// polls while a gated dispatch waits for a human.
//
// # An MCP task handle is not a Relay Task
//
// A Relay **Task** is one Operation executing on one Node (ADR-0004). An **MCP
// task handle** is a client-polled reference to one outstanding `tools/call`.
// The naming collision is MCP's, not ours; GLOSSARY.md carries both entries and
// the rule that the MCP one is always written in full. This package is named
// `mcptask` so that every reference to it at a call site — `mcptask.Handle` —
// carries that qualification without anyone having to remember to.
//
// # What this package is NOT
//
//   - Not authorization or approval. A handle is a *reference* to a parked
//     dispatch; it can report state and, in [4/6], re-drive the original call
//     through the ordinary capability-layer path. It can never satisfy a
//     Requirement, widen a Policy, or bypass the gate.
//   - Not a bearer capability. Holding the ID is not permission to resolve it;
//     see Repository.Get.
//   - Not the protocol. No MCP types, JSON shapes, SDK, proto or database/sql
//     dependency, so the store swap stays a single-package change and the wire
//     shim ([3/6], [4/6]) stays deletable when go-sdk#626 lands (ADR-0028).
//
// # Status is derived, never stored-and-trusted
//
// A handle's status is computed from the approval Request it points at (see
// Handle.Status), never read back from a column. A stored status is a second
// copy of a fact that changes without this package being told — a decision
// lands, a sweeper expires a Request. The column is an audit record of what was
// last reported, never the answer.
package mcptask

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/approval"
)

// Errors returned by the handle lifecycle.
var (
	// ErrNotFound is returned when no handle with that ID is resolvable BY THIS
	// CALLER — both "no such handle" and "not yours". A distinct "not yours"
	// would confirm an ID exists, leaking that an Account has a fleet action
	// waiting on a human.
	ErrNotFound = errors.New("mcptask: no such task handle")

	// ErrHandleExpired is returned when the owner's handle is past its
	// deadline: "it lapsed", not "it never existed".
	ErrHandleExpired = errors.New("mcptask: task handle has expired")

	// ErrInvalid is returned for a handle that is not well-formed enough to
	// store — no ID, no owner, no subject, or no deadline.
	ErrInvalid = errors.New("mcptask: task handle is invalid")
)

// Status is SEP-2663's task lifecycle, as reported by tasks/get.
//
// The set is the spec's, and the zero value is deliberately invalid: a
// forgotten computation must not silently read as "working".
type Status int

const (
	StatusUnspecified Status = iota

	// StatusWorking: the call is outstanding. For Relay this means the
	// dispatch is parked awaiting a human, or approved and awaiting the
	// re-drive that runs it.
	StatusWorking

	// StatusInputRequired: the server is asking the client for input.
	//
	// Relay NEVER produces this — a security boundary, not an unfinished
	// feature. An `inputRequests` elicitation would be an approval answered over
	// the AI's own session (open question on #272; ADR-0028). Defined only so
	// the vocabulary is complete.
	StatusInputRequired

	// StatusCompleted: the call produced a result. A dispatch that came back
	// with three unreachable Nodes is still COMPLETED: per-Node outcomes are the
	// result's content, not the call's fate.
	StatusCompleted

	// StatusFailed: the call will never produce a result. For Relay this is a
	// denied or expired approval — terminal facts about the request, not
	// transport errors.
	StatusFailed

	// StatusCancelled: the client withdrew its interest via tasks/cancel.
	//
	// Per ADR-0028 the approval Request stays pending until a human decides it
	// or it expires; an AI-agent cannot yank it back.
	StatusCancelled
)

func (s Status) String() string {
	switch s {
	case StatusWorking:
		return "working"
	case StatusInputRequired:
		return "input_required"
	case StatusCompleted:
		return "completed"
	case StatusFailed:
		return "failed"
	case StatusCancelled:
		return "cancelled"
	default:
		return "unspecified"
	}
}

// Terminal reports whether s is an end state — nothing further will change.
func (s Status) Terminal() bool {
	switch s {
	case StatusCompleted, StatusFailed, StatusCancelled:
		return true
	default:
		return false
	}
}

// ParseStatus maps a stored status name back onto the domain value. An
// unrecognized name is StatusUnspecified, never a guess.
func ParseStatus(s string) Status {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "working":
		return StatusWorking
	case "input_required":
		return StatusInputRequired
	case "completed":
		return StatusCompleted
	case "failed":
		return StatusFailed
	case "cancelled":
		return StatusCancelled
	default:
		return StatusUnspecified
	}
}

// MaxTTL bounds how long any handle may be pollable, whatever it points at.
//
// A ceiling in code as well as derived from the Request: a generous approval
// TTL must not mint week-long poll tokens carrying somebody's plan summary.
const MaxTTL = 24 * time.Hour

// Handle is one client-polled reference to one parked dispatch.
//
// The two bindings are separate and both nullable on purpose. SEP-2663 wants a
// task id in the `tools/call` response the instant the dispatch parks, but a
// parked dispatch creates no Job (#269: a restart reconciler would mistake it
// for interrupted work). At mint time there is only an approval Request; the
// Job arrives later or never.
type Handle struct {
	// ID is what the client polls. It is unguessable-by-construction (minted
	// like every other Relay ID) but is NOT a credential — see Repository.Get.
	ID string

	// ApprovalRequestID is the parked Request this handle refers to. Set at
	// mint time and never changed: a handle refers to one dispatch, and
	// re-pointing it would let a client's stored handle silently start
	// reporting on something else.
	ApprovalRequestID string

	// JobID is set once the approval releases a dispatch and it actually runs.
	// Empty means "not yet, or never".
	JobID string

	// AccountID and Account are the minting Account — the verified lane. The ID
	// is what ownership is checked against, so the check survives a rename; the
	// name is what a human reads.
	AccountID string
	Account   string

	// LastStatus is the status most recently REPORTED for this handle.
	//
	// A record, not a source of truth: read Status instead. Stored so an
	// auditor can see what a client was actually told and when, which
	// recomputing from today's state would erase.
	LastStatus Status

	CreatedAt     time.Time
	LastUpdatedAt time.Time

	// ExpiresAt is when the handle stops being pollable. Always at or before
	// the Request's own expiry (see NewHandle): a handle that outlived what it
	// points at could only ever report on something no longer decidable.
	ExpiresAt time.Time

	// CancelledAt is set by tasks/cancel. It ends the client's polling
	// contract and nothing else.
	CancelledAt time.Time
}

// NewHandle mints a handle for a freshly parked dispatch.
//
// The deadline is the earlier of the Request's own expiry and MaxTTL from now.
// The caller supplies neither: a TTL parameter would eventually be generous on
// whichever surface cared least.
func NewHandle(id string, req approval.Request, accountID, account string, now time.Time) Handle {
	expires := now.Add(MaxTTL)
	if !req.ExpiresAt.IsZero() && req.ExpiresAt.Before(expires) {
		expires = req.ExpiresAt
	}
	return Handle{
		ID:                id,
		ApprovalRequestID: req.ID,
		AccountID:         accountID,
		Account:           account,
		LastStatus:        StatusWorking,
		CreatedAt:         now,
		LastUpdatedAt:     now,
		ExpiresAt:         expires,
	}
}

// Validate refuses a handle that is not well-formed enough to store.
//
// An unowned handle has no ownership check to fail, and a deadline-less one is
// pollable forever.
func (h Handle) Validate() error {
	if strings.TrimSpace(h.ID) == "" {
		return fmt.Errorf("%w: handle has no id", ErrInvalid)
	}
	if strings.TrimSpace(h.ApprovalRequestID) == "" {
		return fmt.Errorf("%w: handle %q refers to no approval request", ErrInvalid, h.ID)
	}
	if strings.TrimSpace(h.AccountID) == "" {
		return fmt.Errorf("%w: handle %q has no owning account; a handle is not a bearer capability", ErrInvalid, h.ID)
	}
	if h.ExpiresAt.IsZero() || !h.ExpiresAt.After(h.CreatedAt) {
		return fmt.Errorf("%w: handle %q has no deadline", ErrInvalid, h.ID)
	}
	return nil
}

// OwnedBy reports whether accountID minted this handle.
//
// Checked against the Account ID, not the name, so a rename cannot hand a
// handle to whoever inherits the name.
func (h Handle) OwnedBy(accountID string) bool {
	return accountID != "" && h.AccountID == accountID
}

// Expired reports the clock fact.
func (h Handle) Expired(now time.Time) bool {
	return !h.ExpiresAt.IsZero() && !now.Before(h.ExpiresAt)
}

// Cancelled reports whether the client withdrew interest.
func (h Handle) Cancelled() bool { return !h.CancelledAt.IsZero() }

// Status computes what tasks/get must report, from the live approval Request
// this handle points at.
//
// Every input is the handle's own immutable facts or the Request read fresh, so
// no stale copy can be reported.
//
// Order matters:
//
//  1. Cancellation: the client asked to stop being told.
//  2. The approval's terminal states: a denied or expired Request outranks the
//     handle's clock — reporting `lapsed` for a request a human denied would
//     lose the one thing the requester most needs.
//  3. The handle's own expiry.
//  4. The Job binding.
func (h Handle) Status(req approval.Request, now time.Time) Status {
	if h.Cancelled() {
		return StatusCancelled
	}

	switch req.State {
	case approval.StateDenied, approval.StateExpired:
		return StatusFailed
	}
	// Pending past its deadline reads as expired everywhere else
	// (approval.Request.Expired); a sweeper outage must not leave handles
	// reporting `working` for requests nothing can decide.
	if req.Expired(now) {
		return StatusFailed
	}

	if h.Expired(now) {
		return StatusFailed
	}

	// Execution.Run is synchronous (ADR-0028), so a bound Job is a finished one.
	if h.JobID != "" {
		return StatusCompleted
	}

	// Pending, or approved and awaiting the re-drive that dispatches it.
	return StatusWorking
}

// TTLMillis renders the lifetime remaining until expiresAt for SEP-2663's
// `ttlMs`, floored at zero.
func TTLMillis(expiresAt, now time.Time) int64 {
	remaining := expiresAt.Sub(now)
	if remaining <= 0 {
		return 0
	}
	return remaining.Milliseconds()
}

// Repository persists handles.
//
// Durable storage makes a handle resolvable by ANY Relay instance, which the
// stateless MCP handler (#267) needs and HA (#139) will.
type Repository interface {
	// Create persists a validated handle. Implementations must reject one
	// whose Validate fails rather than trusting the caller.
	Create(ctx context.Context, h Handle) error

	// Get returns a handle by ID, for the Account resolving it.
	//
	// accountID is REQUIRED and checked: in [4/6] resolving a handle can
	// re-drive the stored call, so a second Account resolving it would be an
	// escalation, not a read. Another Account's handle returns ErrNotFound.
	Get(ctx context.Context, id, accountID string) (Handle, error)

	// ByApprovalRequest returns the handle minted for an approval Request, if
	// any, keeping the mapping one-to-one: a re-drive re-attaches rather than
	// minting a second handle for the same wait.
	ByApprovalRequest(ctx context.Context, approvalRequestID string) (Handle, error)

	// BindJob records the Job a released dispatch created, and the status last
	// reported alongside it.
	BindJob(ctx context.Context, id, jobID string, status Status, now time.Time) error

	// RecordStatus updates the last-reported status (see Handle.LastStatus).
	RecordStatus(ctx context.Context, id string, status Status, now time.Time) error

	// Cancel marks a handle cancelled, ending the client's polling contract.
	// It must NOT touch the approval Request (ADR-0028): a cancel arrives over
	// the AI's own session, and approval is reserved for out-of-band humans.
	//
	// Returns ErrNotFound for an unknown or unowned ID. Cancelling an already
	// terminal handle is a no-op, so a retried cancel is not an error.
	Cancel(ctx context.Context, id, accountID string, now time.Time) (Handle, error)

	// DeleteExpired removes handles past their deadline, returning how many.
	// Unlike the audit trail, handles are swept rather than kept.
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}
