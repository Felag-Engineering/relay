package approval

import (
	"context"
	"time"
)

// DefaultSweepInterval is how often the Sweeper retires lapsed Requests.
//
// The interval is a cleanup cadence, NOT the expiry guarantee. Expiry is
// enforced by the clock at read time — Request.PastDeadline — so a Request is
// undecidable and unredeemable the moment its deadline passes, whether or not
// the Sweeper has run. If the guarantee depended on the Sweeper, an outage
// would leave stale approvals redeemable, which is precisely the failure a TTL
// exists to prevent. What the Sweeper adds is a truthful stored state and an
// audit record, so a lapsed request does not sit in the queue looking live.
const DefaultSweepInterval = time.Minute

// Sweeper retires pending Requests whose deadline has passed (ADR-0027's "no
// zombie approvals").
type Sweeper struct {
	repo     Repository
	interval time.Duration
	now      func() time.Time

	// onExpired is called once per retired Request, for the audit record. It is
	// a callback rather than an audit dependency because package approval must
	// stay import-narrow (.golangci.yml's approval-imports rule) — the composition root supplies
	// the sink.
	onExpired func(ctx context.Context, r Request)
}

// NewSweeper builds a Sweeper. A zero interval uses DefaultSweepInterval; a nil
// clock uses time.Now; a nil onExpired means expiries are retired silently,
// which callers should avoid — an approval that lapsed is a fact the audit
// trail should carry, not an absence.
func NewSweeper(repo Repository, interval time.Duration, now func() time.Time, onExpired func(context.Context, Request)) *Sweeper {
	if interval <= 0 {
		interval = DefaultSweepInterval
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Sweeper{repo: repo, interval: interval, now: now, onExpired: onExpired}
}

// Sweep retires everything due once, returning how many Requests it expired.
func (s *Sweeper) Sweep(ctx context.Context) (int, error) {
	expired, err := s.repo.ExpirePending(ctx, s.now())
	if err != nil {
		return 0, err
	}
	for _, r := range expired {
		if s.onExpired != nil {
			s.onExpired(ctx, r)
		}
	}
	return len(expired), nil
}

// Run sweeps until ctx is cancelled.
//
// A sweep error is reported through onError and the loop CONTINUES rather than
// exiting. A store blip must not silently stop expiry for the lifetime of the
// process — and it cannot make anything unsafe either, since the clock, not the
// Sweeper, is what makes a lapsed approval unredeemable.
func (s *Sweeper) Run(ctx context.Context, onError func(error)) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := s.Sweep(ctx); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}
