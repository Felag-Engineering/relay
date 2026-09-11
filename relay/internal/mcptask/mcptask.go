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
// # What this package deliberately is NOT
//
//   - It is not authorization, and it is not an approval. A handle is a
//     *reference* to a parked dispatch; resolving one can report state and, in
//     [4/6], re-drive the original call through the ordinary capability-layer
//     path — it can never satisfy a Requirement, widen a Policy, or bypass the
//     gate. Everything here is a view.
//   - It is not a bearer capability. Holding the ID is not permission to
//     resolve it; see Repository.Get and the owner-only rule below.
//   - It is not the protocol. No MCP types, no JSON shapes, no SDK dependency.
//     Following the jobs and approval packages' precedent it carries no proto
//     and no database/sql dependency, so the store swap stays a
//     single-package change and the wire shim ([3/6], [4/6]) stays deletable
//     when go-sdk#626 lands (ADR-0028's removal condition).
//
// # Status is derived, never stored-and-trusted
//
// The single most important rule in this package: a handle's status is computed
// from the approval Request it points at (see Handle.Status), never read back
// from a column. A stored status is a second copy of a fact that changes
// without this package being told — a decision lands on the Control API, a
// sweeper expires a Request — and a handle reporting `working` for an approval
// that was denied an hour ago is the approval-view fidelity gap reappearing in
// a new place. The column exists as an audit and debugging record of what was
// last reported; it is never the answer.
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
	// CALLER — which covers both "no such handle" and "not yours".
	//
	// Collapsing the two is deliberate. A distinct "not yours" would confirm
	// that a given handle ID exists, which is exactly the probe a caller who
	// guessed or scraped an ID would run, and existence alone leaks that a
	// particular Account has a fleet action waiting on a human. The owner sees
	// their handle; everyone else sees the same answer they would get for an ID
	// that was never minted.
	ErrNotFound = errors.New("mcptask: no such task handle")

	// ErrHandleExpired is returned when a handle exists and is past its
	// deadline. Distinct from ErrNotFound because it is the OWNER's own handle
	// and the truthful answer to "what happened to my request?" is "it lapsed",
	// not "it never existed".
	ErrHandleExpired = errors.New("mcptask: task handle has expired")

	// ErrInvalid is returned for a handle that is not well-formed enough to
	// store — no ID, no owner, no subject, or no deadline.
	ErrInvalid = errors.New("mcptask: task handle is invalid")
)

// Status is SEP-2663's task lifecycle, as reported by tasks/get.
//
// The set is the spec's, not ours, and the zero value is deliberately not a
// valid one: a status must be computed, and a forgotten computation must not
// silently read as "working".
type Status int

const (
	StatusUnspecified Status = iota

	// StatusWorking: the call is outstanding. For Relay this means the
	// dispatch is parked awaiting a human, or approved and awaiting the
	// re-drive that runs it.
	StatusWorking

	// StatusInputRequired: the server is asking the client for input.
	//
	// Relay NEVER produces this, and that is a security boundary rather than an
	// unfinished feature. It is the shape an `inputRequests` elicitation takes,
	// which would be an approval answered over the AI's own session — the open
	// rung-2 question on #272. ADR-0028 states the boundary; the value is
	// defined here only so the vocabulary is complete and a future
	// implementation is an amendment rather than an invention.
	StatusInputRequired

	// StatusCompleted: the call produced a result.
	//
	// Note what this does NOT mean. A dispatch that ran and came back with
	// three unreachable Nodes is a COMPLETED call carrying a truthful result;
	// per-Node outcomes are the result's content, not the call's fate. Mapping
	// them onto a failed task would tell a client the protocol exchange broke
	// when what actually happened is that it worked and the news was bad.
	StatusCompleted

	// StatusFailed: the call will never produce a result. For Relay this is a
	// denied or expired approval — terminal facts about the request, not
	// transport errors.
	StatusFailed

	// StatusCancelled: the client withdrew its interest via tasks/cancel.
	//
	// Per ADR-0028 this says nothing about the underlying approval Request,
	// which stays pending until a human decides it or it expires. An agent must
	// not be able to yank a request back the moment it senses a denial coming.
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
// A ceiling in code as well as derived from the Request, because a handle is a
// reference the client keeps: an approval configuration with a generous TTL
// should not silently mint week-long poll tokens carrying somebody's plan
// summary.
const MaxTTL = 24 * time.Hour

// Handle is one client-polled reference to one parked dispatch.
//
// The two bindings are separate and both nullable on purpose. SEP-2663 wants a
// task id in the `tools/call` RESPONSE — the instant the dispatch parks — but a
// parked dispatch deliberately creates no Job (#269: parking leaves no Job and
// no Pending Tasks, or a restart reconciler mistakes them for interrupted
// work). So at mint time there is an approval Request and nothing else, and the
// Job arrives later or never. Overloading one ID field to mean "approval now,
// Job later" would have made every reader guess which era it was in.
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
	// It is a record, not a source of truth: read Status instead. It is stored
	// so an auditor can see what a client was actually told and when, which is
	// a fact about the past that recomputing from today's state would erase —
	// the same reasoning that stores Request.Summary rather than re-rendering
	// it.
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
// The deadline is the earlier of the Request's own expiry and MaxTTL from now,
// so the handle can never outlive its subject and can never be long-lived just
// because a gate rule was. The caller supplies neither — a handle whose TTL
// were a parameter would eventually be minted with a generous one by whichever
// surface had the least reason to care.
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
// Every branch is something a reader of the table would otherwise have to treat
// as "maybe": an unowned handle has no ownership check to fail, and a
// deadline-less one is pollable forever.
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
// Ownership is checked against the Account ID rather than the name so a rename
// does not hand somebody else's handle to whoever inherits the name.
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
// This is the function the package exists for. Every input is either the
// handle's own immutable facts or the Request read fresh, so there is no path
// by which a stale copy can be reported — the join IS the status.
//
// Order matters and is not arbitrary:
//
//  1. Cancellation first: the client asked to stop being told, and that answer
//     does not depend on what the humans are doing.
//  2. Then the approval's terminal states, because a denied or expired Request
//     is a settled fact that outranks anything the clock says about the handle.
//  3. Then the handle's own expiry.
//  4. Then the Job binding.
//
// Putting the handle's expiry ahead of the approval's outcome would report
// `failed — lapsed` for a request a human actually denied, which loses the one
// piece of information the requester most needs.
func (h Handle) Status(req approval.Request, now time.Time) Status {
	if h.Cancelled() {
		return StatusCancelled
	}

	switch req.State {
	case approval.StateDenied, approval.StateExpired:
		return StatusFailed
	}
	// A Request past its deadline but still pending in the store reads as
	// expired to every other caller (approval.Request.Expired), so it must read
	// that way here too — otherwise a sweeper outage would leave handles
	// cheerfully reporting `working` for requests nothing can decide.
	if req.Expired(now) {
		return StatusFailed
	}

	if h.Expired(now) {
		return StatusFailed
	}

	// A Job exists, so the approved dispatch ran and produced a result.
	// Service.Run is synchronous (ADR-0028 keeps it that way for this
	// milestone), so a bound Job is a finished one — per-Node outcomes are the
	// result's content, not the call's fate.
	if h.JobID != "" {
		return StatusCompleted
	}

	// Pending, or approved and awaiting the re-drive that dispatches it.
	return StatusWorking
}

// TTLMillis renders the remaining lifetime for SEP-2663's `ttlMs`, floored at
// zero so an expired handle never advertises a negative window.
func (h Handle) TTLMillis(now time.Time) int64 {
	remaining := h.ExpiresAt.Sub(now)
	if remaining <= 0 {
		return 0
	}
	return remaining.Milliseconds()
}

// Repository persists handles.
//
// Durable storage is what makes a handle resolvable by ANY Relay instance,
// which is the property the stateless MCP handler (#267) needs and the one that
// keeps the door open for HA (#139). An in-memory handle map would work
// perfectly on one process and break silently on two.
type Repository interface {
	// Create persists a validated handle. Implementations must reject one
	// whose Validate fails rather than trusting the caller.
	Create(ctx context.Context, h Handle) error

	// Get returns a handle by ID, for the Account resolving it.
	//
	// accountID is REQUIRED and is checked, not advisory: a handle carries the
	// requester's Relay-authored plan summary and, once it has run, points at
	// their results — and in [4/6] resolving one can re-drive the stored call
	// through the capability layer. Letting a second Account resolve it would
	// mean re-driving somebody else's dispatch under their authority, which is
	// an escalation, not a read.
	//
	// A handle that exists but belongs to another Account returns ErrNotFound,
	// deliberately indistinguishable from one that never existed.
	Get(ctx context.Context, id, accountID string) (Handle, error)

	// ByApprovalRequest returns the handle minted for an approval Request, if
	// any. Used to keep the mapping one-to-one: re-driving a parked dispatch
	// must re-attach to the existing handle rather than mint a second one for
	// the same wait.
	ByApprovalRequest(ctx context.Context, approvalRequestID string) (Handle, error)

	// BindJob records the Job a released dispatch created, and the status last
	// reported alongside it.
	BindJob(ctx context.Context, id, jobID string, status Status, now time.Time) error

	// RecordStatus updates the last-reported status. It is bookkeeping for the
	// audit record described on Handle.LastStatus — never the thing a later
	// read derives an answer from.
	RecordStatus(ctx context.Context, id string, status Status, now time.Time) error

	// Cancel marks a handle cancelled, ending the client's polling contract.
	// It must NOT touch the approval Request (ADR-0028): a cancel arrives over
	// the AI's own session, and a lever there over a decision reserved for
	// out-of-band humans is exactly what the callout exists to prevent.
	//
	// Returns ErrNotFound for an unknown or unowned ID. Cancelling an already
	// terminal handle is a no-op rather than an error — a client retrying a
	// cancel it already sent is not making a mistake.
	Cancel(ctx context.Context, id, accountID string, now time.Time) (Handle, error)

	// DeleteExpired removes handles past their deadline, returning how many.
	// Handles are a client convenience with a bounded life, so unlike the audit
	// trail they are swept rather than kept.
	DeleteExpired(ctx context.Context, now time.Time) (int, error)
}
