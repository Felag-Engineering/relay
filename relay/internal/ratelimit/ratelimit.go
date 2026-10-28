// Package ratelimit provides a token-bucket rate limiter for the Relay's
// unauthenticated Enrollment endpoint. It combines a per-IP bucket set and a
// single global bucket so the Relay is protected against both focused floods from
// one source and aggregate throughput spikes across many sources.
//
// The limiter is safe for concurrent use.
package ratelimit

import (
	"sync"
	"time"
)

// The Enrollment limits are built in (RC-38, EN-43); no setting reaches them.
// The per-source rate is high enough that some 200 Nodes behind one NAT address
// join in minutes, and the global limit stays the guard against a flood.
const (
	EnrollmentPerIPRatePerMin  = 60
	EnrollmentPerIPBurst       = 10
	EnrollmentGlobalRatePerMin = 50
	EnrollmentGlobalBurst      = 10
	// EnrollmentMaxTrackedIPs bounds the per-IP map against spoofed-source floods.
	EnrollmentMaxTrackedIPs = 100_000
)

// defaultMaxTrackedIPs is the per-IP map bound used when Config.MaxTrackedIPs
// is non-positive.
const defaultMaxTrackedIPs = EnrollmentMaxTrackedIPs

// Enrollment returns the built-in Enrollment limits (RC-38, EN-43).
func Enrollment() Config {
	return Config{
		PerIPRatePerMin:  EnrollmentPerIPRatePerMin,
		PerIPBurst:       EnrollmentPerIPBurst,
		GlobalRatePerMin: EnrollmentGlobalRatePerMin,
		GlobalBurst:      EnrollmentGlobalBurst,
		MaxTrackedIPs:    EnrollmentMaxTrackedIPs,
	}
}

// Clock returns the current time. Inject a deterministic implementation via
// WithClock in tests to avoid real sleeps.
type Clock func() time.Time

// Config holds rate parameters for New. All rates are specified as tokens per
// minute; the limiter converts them to per-second internally.
type Config struct {
	PerIPRatePerMin  float64 // sustained Enrollment rate per source IP (tokens/min)
	PerIPBurst       float64 // per-IP burst capacity (token-bucket depth)
	GlobalRatePerMin float64 // sustained Enrollment rate across all sources (tokens/min)
	GlobalBurst      float64 // global burst capacity
	MaxTrackedIPs    int     // cap on the per-IP bucket map; prevents spoofed-source memory growth. Non-positive values are clamped to defaultMaxTrackedIPs.
}

// Option is a functional option for New.
type Option func(*Limiter)

// WithClock overrides the clock used by the Limiter. Use this in tests to get
// deterministic behaviour without real time advances (mirrors registry.WithClock).
func WithClock(c Clock) Option {
	return func(l *Limiter) { l.now = c }
}

// WithConfigSource makes the Limiter read its parameters from src on every
// Allow instead of holding the ones it was constructed with, so a reloaded
// configuration applies to the next request (RC-21). src is called under the
// Limiter's lock and must be cheap and must not call back into the Limiter.
// New's cfg is the initial value.
func WithConfigSource(src func() Config) Option {
	return func(l *Limiter) { l.src = src }
}

// bucket is a single token-bucket accumulator.
type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter is a token-bucket rate limiter with independent per-IP and global
// gates. Create one with New; the zero value is not usable.
type Limiter struct {
	mu         sync.Mutex
	perIP      map[string]*bucket
	global     *bucket
	ipRate     float64 // tokens per second (= PerIPRatePerMin / 60)
	ipBurst    float64
	gRate      float64 // tokens per second (= GlobalRatePerMin / 60)
	gBurst     float64
	maxTracked int
	now        Clock
	src        func() Config // when set, read once per Allow
}

// New constructs a Limiter from cfg. Both the per-IP and global buckets start
// full (tokens == burst). opts are applied after construction; use WithClock
// in tests.
func New(cfg Config, opts ...Option) *Limiter {
	l := &Limiter{
		perIP: make(map[string]*bucket),
		now:   time.Now,
	}
	l.apply(cfg)
	for _, o := range opts {
		o(l)
	}
	start := l.now()
	l.global = &bucket{tokens: l.gBurst, last: start}
	return l
}

// apply sets the rate parameters from cfg, clamping MaxTrackedIPs as New
// documents. Must be called with l.mu held, or before the Limiter is shared.
// A lowered burst takes effect through refill's clamp.
func (l *Limiter) apply(cfg Config) {
	l.ipRate = cfg.PerIPRatePerMin / 60.0
	l.ipBurst = cfg.PerIPBurst
	l.gRate = cfg.GlobalRatePerMin / 60.0
	l.gBurst = cfg.GlobalBurst
	l.maxTracked = cfg.MaxTrackedIPs
	if l.maxTracked <= 0 {
		l.maxTracked = defaultMaxTrackedIPs
	}
}

// refill adds tokens that have accumulated since b.last at the given rate,
// clamped to burst, then updates b.last to now.
func refill(b *bucket, now time.Time, rate, burst float64) {
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * rate
	if b.tokens > burst {
		b.tokens = burst
	}
	b.last = now
}

// Allow reports whether an Enrollment request from ip may proceed. It consumes
// one token from both the per-IP and global buckets atomically under a single
// lock, so a global-gate denial never drains the per-IP budget (and vice versa).
// Returns false when either gate is empty.
//
// ip must have the port already stripped so all connections from one host share
// a bucket regardless of the source port.
func (l *Limiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.src != nil {
		l.apply(l.src())
	}
	now := l.now()

	// Check the global gate first. Returning early here means the per-IP map is
	// never touched during a globally-denied flood: no new buckets are created and
	// the O(MaxTrackedIPs) eviction scan in ipBucket cannot be triggered. This caps
	// the scan frequency at the global allow rate rather than the raw arrival rate.
	refill(l.global, now, l.gRate, l.gBurst)
	if l.global.tokens < 1 {
		return false
	}

	// Global gate holds a token. Resolve and check the per-IP gate.
	ipb := l.ipBucket(ip, now)
	refill(ipb, now, l.ipRate, l.ipBurst)

	// Allow only when BOTH gates hold a token. Consume from neither on denial so
	// a per-IP rejection does not spend global budget (and vice versa).
	if ipb.tokens < 1 {
		return false
	}
	ipb.tokens--
	l.global.tokens--
	return true
}

// ipBucket returns (and if necessary creates) the per-IP bucket for ip.
// Must be called with l.mu held.
//
// When the map is at maxTracked capacity, the method first performs an
// O(MaxTrackedIPs) scan to evict fully-refilled (idle) buckets — safe because
// a fully-refilled bucket is indistinguishable from a freshly created one.
// Because Allow calls ipBucket only after the global gate passes, this scan
// runs at most once per globally-allowed token, so its frequency is capped at
// the global allow rate rather than the raw connection arrival rate.
// If every tracked IP is still actively rate-limited after the scan, a transient
// throwaway bucket is returned (not stored), keeping the map hard-bounded while
// the global gate continues to cap aggregate throughput.
func (l *Limiter) ipBucket(ip string, now time.Time) *bucket {
	if b, ok := l.perIP[ip]; ok {
		return b
	}

	if l.maxTracked > 0 && len(l.perIP) >= l.maxTracked {
		// O(MaxTrackedIPs) eviction scan: remove any bucket that has fully
		// refilled since its last use — it is indistinguishable from a fresh one.
		for k, b := range l.perIP {
			refill(b, now, l.ipRate, l.ipBurst)
			if b.tokens >= l.ipBurst {
				delete(l.perIP, k)
			}
		}
		if len(l.perIP) >= l.maxTracked {
			// Still at cap: every tracked IP is actively rate-limited. Return a
			// throwaway bucket (not stored) so the global gate governs this call.
			return &bucket{tokens: l.ipBurst, last: now}
		}
	}

	b := &bucket{tokens: l.ipBurst, last: now}
	l.perIP[ip] = b
	return b
}
