package capability

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
)

// Start is Run's non-blocking sibling (#895): the same pipeline, returning as
// soon as the Job's Tasks and its dispatch intent are committed. The fan-out and
// the post-dispatch accounting (metrics, the KindDispatch audit record) finish
// in a background goroutine the Service tracks (Drain). A surface that wants the
// outcomes reads the Job back, or waits on StartedJob.Done.
//
// With an idempotency key, a call re-issued after a lost response is answered
// with the Job the first call created and dispatches nothing. Whether a keyed
// Job is persisted, still being created, or was never created is decided here,
// never by an adapter: the adapter only renders what comes back.
//
// An error is a refusal, a park (*ParkedError) or a failure before the Job was
// persisted. On the persisting engine path this call then dispatched nothing; a
// dispatcher without that path (a test spy) runs the call whole, so an error from
// the accounting after it can follow a dispatch.
func (s *Service) Start(ctx context.Context, p Principal, sel Selector, act jobs.Action, o StartOptions) (StartedJob, error) {
	if !s.bgAcquire() {
		return StartedJob{}, s.recordRefusal(ctx, p, sel, act, RefusalInternal, ErrDraining)
	}
	launched := false
	defer func() {
		if !launched {
			s.bg.Done()
		}
	}()

	pr, err := s.prepareDispatch(ctx, p, sel, act, o.IdempotencyKey)
	if err != nil {
		return StartedJob{}, err
	}
	if pr.reattach != nil {
		return StartedJob{JobID: pr.reattach.jobID, Reattached: true, Done: closedChan()}, nil
	}

	st, ok := s.disp.(starter)
	if !ok {
		// A dispatcher that cannot persist ahead of its fan-out (the no-op
		// default, a test spy). prepareDispatch refuses a key for one.
		res, dispatchErr := s.disp.run(ctx, pr.d)
		_, err := s.account(ctx, p, sel, pr, res, dispatchErr, false)
		return StartedJob{JobID: res.jobID, Done: closedChan()}, err
	}

	jobID, finish, err := st.start(ctx, pr.d)
	if err != nil {
		s.releaseClaim(ctx, pr.claim)
		_, err := s.account(ctx, p, sel, pr, dispatchResult{}, err, false)
		return StartedJob{}, err
	}
	s.settle(pr.claim)

	launched = true
	done := make(chan struct{})
	go func() {
		defer s.bg.Done()
		defer close(done)
		res, fanErr := finish()
		// Bounded and detached, for the reason Run's reserved path is: the caller
		// is gone, and the Job has already run.
		acctCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), reservedPostDispatchAccountingTimeout)
		defer cancel()
		// account logs a failed audit write itself (alwaysLog); the returned
		// error has no caller left to go to.
		_, _ = s.account(acctCtx, p, sel, pr, res, fanErr, true)
	}()
	return StartedJob{JobID: jobID, Done: done}, nil
}

// StartOptions carries Start's optional inputs.
type StartOptions struct {
	// IdempotencyKey, when non-empty, makes the call safe to re-issue: see
	// Start. It is scoped to the calling Account.
	IdempotencyKey string
}

// StartedJob is Start's answer.
type StartedJob struct {
	JobID string

	// Reattached is true when this call dispatched nothing and returned the Job
	// an earlier call created (the same idempotency key, or an approval that had
	// already released).
	Reattached bool

	// Done closes after the Job's fan-out and its KindDispatch audit and metrics
	// accounting finish. It is already closed when Reattached is set or nothing
	// ran in the background.
	Done <-chan struct{}
}

func closedChan() <-chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

// Drain waits for every background Job Start launched, or for ctx. It
// dispatches nothing and changes no Job. Once it has been called Start refuses,
// so a late call can never add work after Drain's Wait began, whatever the
// transport does with an in-flight request.
//
// Production does not call Drain yet: cmd/relay has no shutdown path, so only
// test fixtures use it. On process exit a background Job's post-dispatch
// KindDispatch audit record and its metrics can therefore be lost. At-most-once
// still holds: the dispatch intent is persisted before any Task is sent, and the
// daemon dedups by Task ID.
func (s *Service) Drain(ctx context.Context) error {
	s.bgMu.Lock()
	s.draining = true
	s.bgMu.Unlock()

	idle := make(chan struct{})
	go func() {
		s.bg.Wait()
		close(idle)
	}()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) bgAcquire() bool {
	s.bgMu.Lock()
	defer s.bgMu.Unlock()
	if s.draining {
		return false
	}
	s.bg.Add(1)
	return true
}

// WithIdempotency wires the dispatch idempotency-key store (#895). Optional: a
// Service without it refuses a call that carries a key rather than ignoring the
// key, because dispatching a keyed call twice is the very thing the key is for.
func WithIdempotency(repo jobs.IdempotencyRepository) Option {
	if repo == nil {
		panic("capability: WithIdempotency: repository must not be nil")
	}
	return func(s *Service) { s.idem = repo }
}

const (
	// IdempotencyWindow is how long a key binds its Account's request to a Job.
	// A fixed constant: an operator-set window would be configuration surface
	// (invariant 11) this does not need.
	IdempotencyWindow = 24 * time.Hour

	// MaxIdempotencyKeyBytes bounds a key; each byte must be printable ASCII.
	MaxIdempotencyKeyBytes = 128

	// IdempotencyAbandonAfter is how old an unpersisted claim with no live
	// claimer must be before it is called never-created. Persisting is a handful
	// of local SQLite writes under a 5s busy timeout, so ten minutes is far past
	// any claimer that could still commit.
	IdempotencyAbandonAfter = 10 * time.Minute

	defaultReattachPersistWait   = 10 * time.Second
	idempotencyCompensateTimeout = 5 * time.Second

	toolIdempotentReattach  = "idempotent_reattach"
	toolIdempotentPending   = "idempotent_pending"
	toolIdempotentReleased  = "idempotent_released"
	toolIdempotentAbandoned = "idempotent_abandoned"
)

// IdempotencyConflictError is a key reused with different arguments. A new key
// is right here: the earlier request was a different request.
type IdempotencyConflictError struct{}

func (*IdempotencyConflictError) Error() string {
	return "capability: this idempotency key was already used by this Account within 24h with different arguments; " +
		"this call dispatched nothing — use a new key for a new request"
}

// IdempotencyKeyError is a malformed key.
type IdempotencyKeyError struct{ Reason string }

func (e *IdempotencyKeyError) Error() string {
	return "capability: invalid idempotency key (" + e.Reason + "): it must be 1-128 bytes, each printable ASCII " +
		"(0x21-0x7E); this call dispatched nothing"
}

// ErrIdempotencyUnavailable is a key supplied where it cannot be honoured: no
// key store, no verified Account, or a dispatcher that cannot persist first.
var ErrIdempotencyUnavailable = errors.New("capability: this Relay cannot honour an idempotency key here " +
	"(no key store, no verified Account, or no persisting dispatcher); this call dispatched nothing — send it without a key only if a repeat is acceptable")

// ErrDraining is Start refusing because the Service is shutting down.
var ErrDraining = errors.New("capability: the Relay is shutting down; this call dispatched nothing")

// IdempotencyPendingError means an earlier call with this key may still be
// creating its Job. It must never suggest a new key: the earlier call may yet run.
type IdempotencyPendingError struct{ JobID string }

func (e *IdempotencyPendingError) Error() string {
	return "capability: an earlier call with this idempotency key is still creating Job " + e.JobID +
		"; this call dispatched nothing. Poll get_job " + e.JobID +
		", or re-issue this call unchanged with the same key. Do not use a new key: the earlier call may still run"
}

// IdempotencyReleasedError means the earlier call failed before dispatching
// anything and gave its key back.
type IdempotencyReleasedError struct{}

func (*IdempotencyReleasedError) Error() string {
	return "capability: the earlier call with this idempotency key failed before dispatching anything, and nothing ran under it; " +
		"this call dispatched nothing — re-issue this call unchanged with the same key to retry"
}

// IdempotencyAbandonedError is the only outcome that may suggest a new key: the
// claim is old, has no live claimer and no Job, so nothing can still run under it.
type IdempotencyAbandonedError struct {
	JobID     string
	ClaimedAt time.Time
}

func (e *IdempotencyAbandonedError) Error() string {
	return fmt.Sprintf("capability: this idempotency key was bound to Job %s at %s, more than %s ago, and no Job was created under this key, "+
		"so nothing ran under it; this call dispatched nothing — a new key is safe",
		e.JobID, e.ClaimedAt.UTC().Format(time.RFC3339), IdempotencyAbandonAfter)
}

func validateIdempotencyKey(key string) error {
	if len(key) > MaxIdempotencyKeyBytes {
		return &IdempotencyKeyError{Reason: "too long"}
	}
	for i := 0; i < len(key); i++ {
		if key[i] < 0x21 || key[i] > 0x7E {
			return &IdempotencyKeyError{Reason: "unprintable or space byte"}
		}
	}
	return nil
}

// keyClaim is this process's claim on one idempotency key while its claimer
// persists the Job. settled closes once persist has returned, or the claim was
// released or rebound.
type keyClaim struct {
	mapKey    string
	accountID string
	key       string
	jobID     string
	settled   chan struct{}
	once      sync.Once
}

func claimMapKey(accountID, key string) string { return accountID + "\x00" + key }

func (s *Service) registerClaim(accountID, key, jobID string) *keyClaim {
	c := &keyClaim{mapKey: claimMapKey(accountID, key), accountID: accountID, key: key, jobID: jobID, settled: make(chan struct{})}
	s.claimsMu.Lock()
	s.claims[c.mapKey] = c
	s.claimsMu.Unlock()
	return c
}

// settle ends c exactly once. It removes the map entry only if it is still c's:
// a late settle must not close the claim of a later caller that re-claimed the
// key. The entry goes before settled closes, so a waiter woken by the close can
// never find the settled claim through liveClaim.
func (s *Service) settle(c *keyClaim) {
	if c == nil {
		return
	}
	c.once.Do(func() {
		s.claimsMu.Lock()
		if s.claims[c.mapKey] == c {
			delete(s.claims, c.mapKey)
		}
		s.claimsMu.Unlock()
		close(c.settled)
	})
}

// liveClaim returns the unsettled claim naming jobID for (accountID, key).
func (s *Service) liveClaim(accountID, key, jobID string) *keyClaim {
	s.claimsMu.Lock()
	defer s.claimsMu.Unlock()
	if c := s.claims[claimMapKey(accountID, key)]; c != nil && c.jobID == jobID {
		return c
	}
	return nil
}

// releaseClaim gives c's key back, because its Job was never persisted, then
// settles it. Detached and bounded: a dropped stream must not leave a key bound
// for the window to a Job that never existed.
func (s *Service) releaseClaim(ctx context.Context, c *keyClaim) {
	if c == nil {
		return
	}
	cctx, cancel := compensateContext(ctx)
	defer cancel()
	s.logKeyWrite(cctx, "release", s.idem.Release(cctx, c.accountID, c.key, c.jobID))
	s.settle(c)
}

func compensateContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), idempotencyCompensateTimeout)
}

// logKeyWrite logs a failed compensating write. It never names the key.
func (s *Service) logKeyWrite(ctx context.Context, op string, err error) {
	if err != nil {
		s.logger().ErrorContext(ctx, "capability: idempotency key compensating write failed; the key stays bound until its window passes", "op", op, "error", err)
	}
}

// keyedReattach answers a call whose key already has a live record: a conflict
// if the arguments differ, otherwise the Job the record names.
func (s *Service) keyedReattach(ctx context.Context, p Principal, sel Selector, act jobs.Action, digest string, rec jobs.IdempotencyRecord) (prep, error) {
	if rec.RequestDigest != digest {
		return prep{}, s.recordRefusal(ctx, p, sel, act, RefusalMalformed, &IdempotencyConflictError{})
	}
	ra, err := s.resolveKeyedReattach(ctx, p, sel, act, rec)
	if err != nil {
		return prep{}, err
	}
	return prep{reattach: ra}, nil
}

// resolveKeyedReattach decides what a re-issued keyed call is told, in the
// capability layer and never in an adapter. The earlier call may be mid-persist,
// may have failed, or may have died, and only the last of those ever allows a
// new key.
//
// Every outcome that discloses a Job ID is an audited read and fails closed
// (ErrReadUnaudited). None is a refusal metric: none refuses the request.
func (s *Service) resolveKeyedReattach(ctx context.Context, p Principal, sel Selector, act jobs.Action, rec jobs.IdempotencyRecord) (*reattachment, error) {
	st, ok := s.disp.(starter)
	if !ok {
		return nil, s.recordRefusal(ctx, p, sel, act, RefusalInternal, ErrIdempotencyUnavailable)
	}
	internal := func(err error) error {
		return s.recordRefusal(ctx, p, sel, act, RefusalInternal, fmt.Errorf("capability: resolve idempotency key: %w", err))
	}

	if c := s.liveClaim(p.AccountID, rec.Key, rec.JobID); c != nil {
		t := time.NewTimer(s.reattachPersistWait)
		select {
		case <-c.settled:
		case <-t.C:
		case <-ctx.Done():
		}
		t.Stop()
		// The caller went away while waiting. Every read below would fail on the
		// dead context and be recorded as an internal refusal, which a client
		// disconnect is not.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}

	// attach answers with jobID if it is persisted, or reports it is not.
	attach := func(jobID string) (*reattachment, bool, error) {
		persisted, err := st.jobPersisted(ctx, jobID)
		if err != nil {
			return nil, false, internal(err)
		}
		if !persisted {
			return nil, false, nil
		}
		if err := s.recordQueryRead(ctx, p, toolIdempotentReattach, sel.String(), "", jobID); err != nil {
			return nil, false, fmt.Errorf("capability: re-attach to idempotency key's Job: %w", err)
		}
		return &reattachment{jobID: jobID}, true, nil
	}
	pending := func(jobID string) (*reattachment, error) {
		if err := s.recordQueryRead(ctx, p, toolIdempotentPending, sel.String(), "", jobID); err != nil {
			return nil, fmt.Errorf("capability: report pending idempotency key: %w", err)
		}
		return nil, &IdempotencyPendingError{JobID: jobID}
	}

	if ra, ok, err := attach(rec.JobID); err != nil || ok {
		return ra, err
	}
	if s.liveClaim(p.AccountID, rec.Key, rec.JobID) != nil {
		return pending(rec.JobID)
	}

	// Not persisted, and nobody in this process is persisting it.
	now := s.clock()
	cur, found, err := s.idem.Lookup(ctx, p.AccountID, rec.Key, now.Add(-IdempotencyWindow))
	if err != nil {
		return nil, internal(err)
	}
	if !found {
		if err := s.recordQueryRead(ctx, p, toolIdempotentReleased, sel.String(), "", ""); err != nil {
			return nil, fmt.Errorf("capability: report released idempotency key: %w", err)
		}
		return nil, &IdempotencyReleasedError{}
	}
	if cur.JobID != rec.JobID {
		// Rebound to the Job an approval released (AP-77). Look once more.
		if ra, ok, err := attach(cur.JobID); err != nil || ok {
			return ra, err
		}
		return pending(cur.JobID)
	}
	if now.Sub(cur.CreatedAt) < IdempotencyAbandonAfter {
		return pending(cur.JobID)
	}
	if err := s.recordQueryRead(ctx, p, toolIdempotentAbandoned, sel.String(), "", cur.JobID); err != nil {
		return nil, fmt.Errorf("capability: report abandoned idempotency key: %w", err)
	}
	return nil, &IdempotencyAbandonedError{JobID: cur.JobID, ClaimedAt: cur.CreatedAt}
}
