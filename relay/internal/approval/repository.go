package approval

import (
	"context"
	"time"
)

// Repository persists approval Requests and their Decisions. Like
// freeze.Repository and jobs.JobRepository, the interface lives in the domain
// package and the SQLite implementation lives in internal/store, so a later
// Postgres swap stays a single-package change.
//
// A parked dispatch that a crash forgets is not a park — it is a dispatch that
// quietly never happened, which is the *safe* direction but not an honest one.
// Everything here is durable so the approval queue survives a restart and an
// auditor can still answer "what was asked, and what became of it".
type Repository interface {
	// Create persists a new pending Request.
	Create(ctx context.Context, r Request) error

	// Get returns the Request with the given ID, or ErrNotFound.
	Get(ctx context.Context, id string) (Request, error)

	// ByJob returns the Request bound to jobID, or ErrNotFound. Used to answer
	// "why is this Job waiting?".
	ByJob(ctx context.Context, jobID string) (Request, error)

	// ByPlanHash returns the most recent Request for planHash, or ErrNotFound.
	//
	// This is the dispatch path's lookup, and looking up by plan hash is what
	// makes registry drift re-park automatically: a changed fan-out is a
	// changed hash, so the approval simply is not found for it. There is no
	// separate drift detector to get wrong, and no notion of a "close enough"
	// Plan.
	//
	// Most-recent rather than most-favourable: returning the newest means a
	// Plan that was denied can be re-requested, which is deliberate. A denial
	// is a decision about a moment, not a standing rule — the thing that
	// permanently refuses an action is Node Policy, not an approver's mood.
	// The cost is that a requester can re-ask; the mitigation is that every
	// re-ask is a fresh audited Request with the requester's name on it.
	ByPlanHash(ctx context.Context, planHash string) (Request, error)

	// LastApprovedByShape returns the most recently RESOLVED approved Request
	// whose shape key is shapeKey, excluding excludeID (the record being
	// rendered), or ErrNotFound. It is a lookup, not a scan, so the approval
	// object can answer "what did I approve last time that looked like this?"
	// on the most latency-sensitive screen there is.
	//
	// It is a READ. Nothing about it releases a dispatch: release is by plan
	// hash and by plan hash only (see ByPlanHash). An empty shapeKey, or a
	// LegacyShapeKey, returns ErrNotFound — a record whose shape was never
	// computed has no comparable prior, and manufacturing one would be the
	// "materially different action reads as routine" failure D10 names.
	LastApprovedByShape(ctx context.Context, shapeKey, excludeID string) (Request, error)

	// Pending returns every Request still in StatePending, oldest deadline
	// first. This is both the approval queue's read and the expiry sweeper's
	// scan.
	Pending(ctx context.Context) ([]Request, error)

	// RecordDecision appends d to the Request and persists the resulting state
	// transition atomically. The read-modify-write must happen inside one
	// transaction: two approvers answering a count:2 Request simultaneously
	// must not both read "0 approvals so far" and both append, and a decision
	// must never be recorded without its state change (or vice versa).
	//
	// It returns the updated Request, or one of ErrNotFound, ErrNotPending,
	// ErrRequesterExcluded, ErrNotInAudience, ErrDuplicateDecider,
	// ErrPlanChanged, ErrMachineSelfDecision, or ErrWeakChannel.
	//
	// On a domain eligibility refusal (every error above but ErrNotFound), the
	// returned Request is the one read inside the transaction, unchanged, with
	// nothing persisted — the state the refusal was judged against, not a
	// second, potentially racing, lookup. On ErrNotFound or a store failure it
	// is the zero value.
	RecordDecision(ctx context.Context, id string, d Decision, now time.Time) (Request, error)

	// BindJob is the release claim (AP-77): it binds jobID to the Request with
	// ID id only if the Request is Satisfied at now AND has no Job already
	// bound, atomically. Binding is what joins the approval and the execution
	// it released for audit, and it happens at most once per Request.
	//
	// It returns the updated Request on success, or one of:
	//   - ErrNotFound: no such Request.
	//   - ErrAlreadyReleased: the Request already has a Job bound. The returned
	//     Request is the one read inside the transaction, carrying the bound
	//     JobID, so the caller can re-attach to it.
	//   - ErrNotReleasable: the Request is not Satisfied (pending, denied,
	//     expired, past its deadline, or short of quorum), or jobID is empty.
	//     The returned Request is the one read inside the transaction,
	//     unchanged, mirroring RecordDecision's "refusal returns cur" contract.
	BindJob(ctx context.Context, id, jobID string, now time.Time) (Request, error)

	// ExpirePending moves every pending Request whose deadline has passed to
	// StateExpired, returning those it changed. Callers use the returned set to
	// emit one audit record per expiry — an approval that lapses is a fact the
	// trail must carry, not an absence.
	ExpirePending(ctx context.Context, now time.Time) ([]Request, error)

	// CountWaiting returns how many Requests are StatePending with a deadline
	// after now: the ones an approver can still answer. It is one count, with
	// no Request rows or Decisions loaded, and it backs the approvals-waiting
	// gauge. The boundary is the one PastDeadline and ExpirePending share, so a
	// Request is waiting exactly until the sweeper would retire it.
	CountWaiting(ctx context.Context, now time.Time) (int, error)
}

// GrantRepository persists batch/window Grants (ADR-0027 decision 12).
//
// It is separate from Repository rather than folded into it because the two
// have different lifecycles and different risks: a Request is created, decided
// once, and finished, while a Grant is created once and then CONSUMED
// repeatedly under concurrency. Keeping them apart makes the claim path below
// impossible to confuse with the decision path.
type GrantRepository interface {
	// CreateGrant persists a validated Grant. Implementations must reject one
	// whose Validate fails rather than trusting the caller — an unbounded Grant
	// must be impossible to store.
	CreateGrant(ctx context.Context, g Grant) error

	// GetGrant returns a Grant by ID, or ErrGrantNotFound.
	GetGrant(ctx context.Context, id string) (Grant, error)

	// GrantByRequest returns the Grant that requestID authorized, or
	// ErrGrantNotFound when that Request is not a grant request.
	//
	// It exists because a Request is the only handle a surface has: a Grant's
	// authorizing Request carries no marker saying so (NewGrantRequest sets
	// Request.ID = g.RequestID and nothing else), so "is this Request a Grant
	// request, and what Scope did it authorize?" is otherwise unanswerable from
	// the Request alone.
	//
	// It returns the Grant IN EVERY STATE — revoked, expired, exhausted, or not
	// yet started. That is the whole reason it is not ActiveGrants: the prior
	// Grant an approval screen compares against is usually one of those, and a
	// comparison that silently skipped them would show a human "nothing like
	// this has been approved before" about a window they closed yesterday.
	//
	// It is a READ and a JOIN, never a claim path. Nothing about it releases a
	// dispatch: release is ClaimGrant, and a dispatch is matched by plan hash or
	// by a claimed Grant, by nothing else.
	GrantByRequest(ctx context.Context, requestID string) (Grant, error)

	// ActiveGrants returns every Grant that could still cover something at now,
	// newest first. Used by the queue view; the dispatch path uses ClaimGrant.
	ActiveGrants(ctx context.Context, now time.Time) ([]Grant, error)

	// ClaimGrant atomically finds a Grant covering d and consumes one use,
	// returning it. ok is false when nothing covers d.
	//
	// Find-and-consume is ONE operation on purpose. Separate "find" and
	// "increment" calls would let two concurrent dispatches both observe the
	// last remaining use and both proceed — a grant bounded at 20 releasing 21
	// dispatches. The bound is the whole security argument for grants, so it
	// cannot be enforced outside a transaction. This is the same reasoning that
	// puts quorum arithmetic inside RecordDecision's transaction.
	ClaimGrant(ctx context.Context, d Dispatch, now time.Time) (g Grant, ok bool, err error)

	// RevokeGrant ends a Grant early, attributed to revokedBy with a reason.
	// Returns ErrGrantNotFound for an unknown ID and ErrGrantNotActive for one
	// already revoked or expired — revoking twice is not a silent no-op, since
	// an operator reaching for this is usually in an incident and needs a
	// truthful answer.
	RevokeGrant(ctx context.Context, id, revokedBy, reason string, now time.Time) (Grant, error)
}
