package consoleauth

import (
	"sync"
	"time"
)

// Throttle slows down repeated failed sign-ins, in two independent lanes
// (docs/design/console/12-login.md).
//
// # Why there is no lockout
//
// The obvious control — disable the Account after N failures — is refused by
// the spec, and the reason is worth restating where the code is: a lockout
// lets an attacker lock the admin out of the Console DURING THE INCIDENT THEY
// ARE CAUSING. Relay's Console is where a fleet gets quarantined and frozen.
// Denying the defender that surface is a worse outcome than the brute force
// the lockout prevents, so this slows attempts down without limit and stops
// none of them.
//
// # Why the per-Account lane is keyed by the SUBMITTED NAME
//
// Not by Account ID, and not only for Accounts that exist. If existing
// Accounts got slower and unknown ones stayed fast, the throttle itself would
// be the user-enumeration oracle the rest of the login path works to avoid —
// a much louder one than a timing difference, since it is measured in whole
// seconds. So the key is whatever the caller typed, normalized.
//
// # Why not reuse internal/ratelimit
//
// That Limiter consumes a token on every CHECK, which is the right shape for
// enrollment (limit requests) and the wrong one here (limit failures). A
// successful sign-in must cost nothing, and a caller must be able to ask "am I
// allowed to try" without spending the budget that answer describes.

// Throttle defaults, per spec 12.
const (
	// DefaultSourceFailuresPerMinute is the sustained failure budget per
	// source address, refilled continuously.
	DefaultSourceFailuresPerMinute = 10.0

	// DefaultSourceBurst is how many failures a source may make back-to-back
	// before the budget bites. Equal to the per-minute rate: ten fat-fingered
	// attempts in a row are a bad morning, the eleventh is a script.
	DefaultSourceBurst = 10.0

	// DefaultAccountBaseDelay is the delay after the first consecutive failure
	// for one submitted name. It doubles per failure from there.
	DefaultAccountBaseDelay = 1 * time.Second

	// DefaultAccountMaxDelay caps the progressive delay. Long enough to make
	// online guessing hopeless (60s per attempt is 1,440 guesses a day),
	// short enough that a real operator who mistyped their password four
	// times is not locked out of an incident.
	DefaultAccountMaxDelay = 60 * time.Second

	// DefaultAccountForget is how long a name's failure streak is remembered
	// with no further attempts. Past it the streak resets, so yesterday's
	// typos do not slow down today's sign-in.
	DefaultAccountForget = 15 * time.Minute
)

// maxTrackedKeys bounds each lane's map. Both are keyed by attacker-supplied
// values — a source address can be spoofed on a UDP-adjacent network and a
// submitted username is free-form — so neither may grow without limit. On
// overflow the lane is cleared rather than the entry refused: forgetting
// resets everyone's streak to zero, which is a throttle that briefly does
// less, whereas refusing to record would be a throttle that silently does
// nothing for the attacker filling the map.
const maxTrackedKeys = 50_000

// sourceBucket is a token bucket of remaining failures for one source.
type sourceBucket struct {
	tokens float64
	last   time.Time
}

// nameStreak is a submitted name's consecutive-failure count and the moment
// its next attempt becomes acceptable.
type nameStreak struct {
	failures  int
	nextAllow time.Time
	last      time.Time
}

// Throttle is the two-lane failed-sign-in governor. The zero value is not
// usable; construct with NewThrottle.
type Throttle struct {
	mu      sync.Mutex
	sources map[string]*sourceBucket
	names   map[string]*nameStreak

	ratePerSecond float64
	burst         float64
	baseDelay     time.Duration
	maxDelay      time.Duration
	forget        time.Duration
	now           func() time.Time
}

// ThrottleOption configures a Throttle.
type ThrottleOption func(*Throttle)

// WithThrottleClock overrides the clock. Tests use it to advance time without
// sleeping.
func WithThrottleClock(now func() time.Time) ThrottleOption {
	return func(t *Throttle) { t.now = now }
}

// WithSourceBudget overrides the per-source failure rate and burst.
// Non-positive values keep the defaults.
func WithSourceBudget(perMinute, burst float64) ThrottleOption {
	return func(t *Throttle) {
		if perMinute > 0 {
			t.ratePerSecond = perMinute / 60
		}
		if burst > 0 {
			t.burst = burst
		}
	}
}

// WithAccountDelays overrides the progressive delay's base and cap.
// Non-positive values keep the defaults.
func WithAccountDelays(base, max time.Duration) ThrottleOption {
	return func(t *Throttle) {
		if base > 0 {
			t.baseDelay = base
		}
		if max > 0 {
			t.maxDelay = max
		}
	}
}

// NewThrottle constructs a Throttle with spec-12 defaults.
func NewThrottle(opts ...ThrottleOption) *Throttle {
	t := &Throttle{
		sources:       make(map[string]*sourceBucket),
		names:         make(map[string]*nameStreak),
		ratePerSecond: DefaultSourceFailuresPerMinute / 60,
		burst:         DefaultSourceBurst,
		baseDelay:     DefaultAccountBaseDelay,
		maxDelay:      DefaultAccountMaxDelay,
		forget:        DefaultAccountForget,
		now:           func() time.Time { return time.Now().UTC() },
	}
	for _, o := range opts {
		o(t)
	}
	return t
}

// Check reports how long the caller must wait before this attempt will be
// considered. Zero means "go ahead"; a positive duration means refuse, and is
// what the Console renders as "try again in N seconds" and what the response's
// Retry-After carries.
//
// Check consumes nothing. Failures are recorded by Fail, successes forgotten
// by Succeed, so asking the question never costs the budget it reports on.
func (t *Throttle) Check(source, name string) time.Duration {
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()

	// The per-name lane first: it is the one whose answer a human sees, and
	// it is the one that says something specific ("this name is being
	// guessed") rather than "this address is busy".
	if st, ok := t.names[name]; ok && now.Before(st.nextAllow) {
		return st.nextAllow.Sub(now)
	}
	if b, ok := t.sources[source]; ok {
		refillSource(b, now, t.ratePerSecond, t.burst)
		if b.tokens < 1 {
			// How long until one token returns.
			return time.Duration((1 - b.tokens) / t.ratePerSecond * float64(time.Second))
		}
	}
	return 0
}

// Fail records one failed attempt: it spends a token from the source's budget
// and lengthens the submitted name's delay.
func (t *Throttle) Fail(source, name string) {
	now := t.now()

	t.mu.Lock()
	defer t.mu.Unlock()

	t.sweepLocked(now)

	b, ok := t.sources[source]
	if !ok {
		b = &sourceBucket{tokens: t.burst, last: now}
		t.sources[source] = b
	}
	refillSource(b, now, t.ratePerSecond, t.burst)
	b.tokens--
	if b.tokens < -t.burst {
		// Floor the debt. Without it a sustained attack accrues an
		// unrecoverable balance and the source is locked out permanently,
		// which is the hard lockout this design refuses — one address behind
		// a NAT is a whole office.
		b.tokens = -t.burst
	}

	st, ok := t.names[name]
	if !ok {
		st = &nameStreak{}
		t.names[name] = st
	}
	st.failures++
	st.last = now
	st.nextAllow = now.Add(t.delayFor(st.failures))
}

// Succeed clears the submitted name's streak. The source's budget is
// deliberately NOT refunded: a success from an address that just made forty
// failures is what a successful brute force looks like, and it should not
// reset the evidence.
func (t *Throttle) Succeed(_, name string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.names, name)
}

// delayFor is the progressive delay for the nth consecutive failure: base,
// doubling, capped.
func (t *Throttle) delayFor(failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	d := t.baseDelay
	for i := 1; i < failures; i++ {
		d *= 2
		if d >= t.maxDelay {
			return t.maxDelay
		}
	}
	if d > t.maxDelay {
		return t.maxDelay
	}
	return d
}

// sweepLocked drops entries that have gone quiet, and clears a lane that has
// grown past the tracking ceiling.
func (t *Throttle) sweepLocked(now time.Time) {
	for name, st := range t.names {
		if now.Sub(st.last) > t.forget && !now.Before(st.nextAllow) {
			delete(t.names, name)
		}
	}
	for source, b := range t.sources {
		if now.Sub(b.last) > t.forget && b.tokens >= t.burst {
			delete(t.sources, source)
		}
	}
	if len(t.names) > maxTrackedKeys {
		clear(t.names)
	}
	if len(t.sources) > maxTrackedKeys {
		clear(t.sources)
	}
}

// refillSource returns tokens accrued since b.last, clamped to burst.
func refillSource(b *sourceBucket, now time.Time, rate, burst float64) {
	b.tokens += now.Sub(b.last).Seconds() * rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now
}
