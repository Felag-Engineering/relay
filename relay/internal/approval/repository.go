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

	// Pending returns every Request still in StatePending, oldest deadline
	// first. This is both the approval queue's read and the expiry sweeper's
	// scan.
	Pending(ctx context.Context) ([]Request, error)

	// RecordDecision appends d to the Request and persists the resulting state
	// transition atomically. The read-modify-write must happen inside one
	// transaction: two deciders answering one Request simultaneously must not
	// both read "pending" and both append, and a decision must never be recorded
	// without its state change (or vice versa).
	//
	// It returns the updated Request, or one of ErrNotFound, ErrNotPending,
	// ErrPlanChanged, or ErrMachineSelfDecision.
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
	//     expired, or past its deadline), or jobID is empty.
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
