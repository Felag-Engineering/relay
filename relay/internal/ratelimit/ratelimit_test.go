package ratelimit

import (
	"fmt"
	"testing"
	"time"
)

// fixedClock returns a Clock that always returns t.
func fixedClock(t time.Time) Clock {
	return func() time.Time { return t }
}

// advanceable wraps a time.Time pointer so tests can advance the clock
// without closing over the original value.
type advanceable struct{ t time.Time }

func (a *advanceable) clock() time.Time        { return a.t }
func (a *advanceable) advance(d time.Duration) { a.t = a.t.Add(d) }

var base = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// TestAllow_PerIPBurstThenDenied verifies that a per-IP burst of 3 allows
// exactly 3 successive calls and denies the 4th, then allows again after
// enough time has elapsed to refill one token.
func TestAllow_PerIPBurstThenDenied(t *testing.T) {
	clk := &advanceable{t: base}
	l := New(Config{
		PerIPRatePerMin:  60, // 1 token/s
		PerIPBurst:       3,
		GlobalRatePerMin: 6000, // generous — not the bottleneck
		GlobalBurst:      1000,
		MaxTrackedIPs:    100,
	}, WithClock(clk.clock))

	const ip = "10.0.0.1"

	// First 3 calls allowed (burst = 3).
	for i := 1; i <= 3; i++ {
		if !l.Allow(ip) {
			t.Errorf("call %d: want allowed, got denied", i)
		}
	}

	// 4th call denied.
	if l.Allow(ip) {
		t.Error("4th call: want denied, got allowed")
	}

	// Advance by 1 second → exactly 1 new token (rate = 1/s).
	clk.advance(time.Second)

	// Now 1 token available — one more allowed.
	if !l.Allow(ip) {
		t.Error("after 1s refill: want allowed, got denied")
	}
	// And the token is spent again.
	if l.Allow(ip) {
		t.Error("after consuming refilled token: want denied, got allowed")
	}
}

// TestAllow_GlobalCap verifies that the global bucket is an independent gate:
// two distinct IPs can exhaust the global budget, leaving a third IP denied
// even though its per-IP bucket is full.
func TestAllow_GlobalCap(t *testing.T) {
	l := New(Config{
		PerIPRatePerMin:  6000, // generous per-IP
		PerIPBurst:       1000,
		GlobalRatePerMin: 60,
		GlobalBurst:      2, // only 2 global tokens
		MaxTrackedIPs:    100,
	}, WithClock(fixedClock(base)))

	// IP-a consumes 1 global token.
	if !l.Allow("10.0.0.1") {
		t.Fatal("IP-a first call: want allowed")
	}
	// IP-b consumes the last global token.
	if !l.Allow("10.0.0.2") {
		t.Fatal("IP-b first call: want allowed")
	}
	// IP-c denied — global budget exhausted, even though per-IP bucket is full.
	if l.Allow("10.0.0.3") {
		t.Error("IP-c: want denied (global exhausted), got allowed")
	}
}

// TestAllow_IndependentIPsUnderGlobalHeadroom verifies that two distinct IPs
// each get their own per-IP burst allocation while global headroom exists.
func TestAllow_IndependentIPsUnderGlobalHeadroom(t *testing.T) {
	l := New(Config{
		PerIPRatePerMin:  60,
		PerIPBurst:       2,
		GlobalRatePerMin: 6000,
		GlobalBurst:      1000,
		MaxTrackedIPs:    100,
	}, WithClock(fixedClock(base)))

	// Both IPs get their own burst of 2.
	for i, ip := range []string{"192.168.1.1", "192.168.1.2"} {
		if !l.Allow(ip) {
			t.Errorf("IP %d first call: want allowed", i)
		}
		if !l.Allow(ip) {
			t.Errorf("IP %d second call: want allowed", i)
		}
		// Per-IP burst exhausted.
		if l.Allow(ip) {
			t.Errorf("IP %d third call: want denied (per-IP exhausted)", i)
		}
	}
}

// TestAllow_RefillRate verifies that after a full drain, advancing the clock
// by exactly 1/rate seconds yields exactly one more allowed call.
func TestAllow_RefillRate(t *testing.T) {
	// Rate = 60 tokens/min = 1 token/s; burst = 1.
	clk := &advanceable{t: base}
	l := New(Config{
		PerIPRatePerMin:  60,
		PerIPBurst:       1,
		GlobalRatePerMin: 6000,
		GlobalBurst:      1000,
		MaxTrackedIPs:    100,
	}, WithClock(clk.clock))

	const ip = "172.16.0.1"

	// Drain the bucket.
	if !l.Allow(ip) {
		t.Fatal("first call: want allowed")
	}
	if l.Allow(ip) {
		t.Fatal("second call: want denied")
	}

	// Advance by exactly 1 second — should refill 1 token.
	clk.advance(time.Second)
	if !l.Allow(ip) {
		t.Error("after 1s: want allowed (1 refilled token)")
	}
	// Token spent; denied again.
	if l.Allow(ip) {
		t.Error("after spending refilled token: want denied")
	}
}

// TestIPBucket_MapBounded verifies that the per-IP map never exceeds
// MaxTrackedIPs entries, and that fully-refilled (idle) buckets are evicted
// to admit new IPs once the cap is reached.
func TestIPBucket_MapBounded(t *testing.T) {
	const maxIPs = 3

	clk := &advanceable{t: base}
	l := New(Config{
		PerIPRatePerMin:  60, // 1 token/s
		PerIPBurst:       2,
		GlobalRatePerMin: 600000, // effectively unlimited
		GlobalBurst:      1000000,
		MaxTrackedIPs:    maxIPs,
	}, WithClock(clk.clock))

	// Fill the map to capacity with IPs 1-3, each consuming 1 token (not idle).
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
	for _, ip := range ips {
		l.Allow(ip)
	}
	if got := len(l.perIP); got != maxIPs {
		t.Fatalf("after filling: len(perIP) = %d, want %d", got, maxIPs)
	}

	// A 4th distinct IP arrives while all 3 tracked IPs are still sub-full
	// (1 token each, burst=2). Eviction scan finds none idle → throwaway bucket.
	l.Allow("10.0.0.4")
	if got := len(l.perIP); got > maxIPs {
		t.Errorf("after overflow call: len(perIP) = %d, want <= %d", got, maxIPs)
	}

	// Advance clock by 2 seconds → tracked IPs fully refill (2 tokens each, == burst).
	clk.advance(2 * time.Second)

	// Now a call from IP-5: eviction scan finds IPs 1-3 are fully refilled and
	// evicts them all; IP-5 gets stored. Map should drop then admit IP-5.
	l.Allow("10.0.0.5")
	if got := len(l.perIP); got > maxIPs {
		t.Errorf("after eviction: len(perIP) = %d, want <= %d", got, maxIPs)
	}
	// IP-5 must be in the map now.
	if _, ok := l.perIP["10.0.0.5"]; !ok {
		t.Error("IP-5 must be tracked after eviction freed a slot")
	}
}

// TestAllow_GlobalExhausted_PerIPMapUnchanged proves Finding 1 is fixed: when
// the global bucket is empty, Allow must return false immediately without
// creating any per-IP bucket or triggering the O(MaxTrackedIPs) eviction scan.
func TestAllow_GlobalExhausted_PerIPMapUnchanged(t *testing.T) {
	l := New(Config{
		PerIPRatePerMin:  6000, // generous per-IP — not the bottleneck
		PerIPBurst:       100,
		GlobalRatePerMin: 60,
		GlobalBurst:      2, // only 2 global tokens
		MaxTrackedIPs:    1000,
	}, WithClock(fixedClock(base)))

	// Drain the global bucket entirely with two distinct IPs.
	if !l.Allow("10.0.0.1") {
		t.Fatal("first drain: want allowed")
	}
	if !l.Allow("10.0.0.2") {
		t.Fatal("second drain: want allowed")
	}
	// Confirm global is now exhausted.
	if l.Allow("10.0.0.3") {
		t.Fatal("third call: want denied (global exhausted)")
	}

	preFloodSize := len(l.perIP)

	// Flood with 200 distinct new IPs. Because the global bucket is empty,
	// Allow must return false before touching the per-IP map for each call.
	for i := 0; i < 200; i++ {
		ip := fmt.Sprintf("192.168.1.%d", i)
		if l.Allow(ip) {
			t.Errorf("flood call %d: want denied (global exhausted), got allowed", i)
		}
	}

	if got := len(l.perIP); got != preFloodSize {
		t.Errorf("after global-denied flood: len(perIP) = %d, want %d (no new buckets must be created)", got, preFloodSize)
	}
}

// TestNew_MaxTrackedIPsClamp proves Finding 3 is fixed: non-positive
// MaxTrackedIPs values are clamped to defaultMaxTrackedIPs so the per-IP map
// is always bounded.
func TestNew_MaxTrackedIPsClamp(t *testing.T) {
	for _, v := range []int{0, -1, -100} {
		l := New(Config{
			PerIPRatePerMin:  60,
			PerIPBurst:       3,
			GlobalRatePerMin: 60,
			GlobalBurst:      10,
			MaxTrackedIPs:    v,
		})
		if l.maxTracked != defaultMaxTrackedIPs {
			t.Errorf("MaxTrackedIPs=%d: maxTracked = %d, want %d (clamped default)", v, l.maxTracked, defaultMaxTrackedIPs)
		}
	}
}

func TestLimiter_ReadsConfigSourcePerCall(t *testing.T) {
	clk := &advanceable{t: base}
	cfg := Config{PerIPRatePerMin: 0.0001, PerIPBurst: 1, GlobalRatePerMin: 0.0001, GlobalBurst: 100, MaxTrackedIPs: 10}
	l := New(cfg, WithClock(clk.clock), WithConfigSource(func() Config { return cfg }))

	if !l.Allow("10.0.0.1") {
		t.Fatal("first call: want allowed")
	}
	if l.Allow("10.0.0.1") {
		t.Fatal("second call at burst 1: want denied")
	}

	// A larger per-IP rate, applied without rebuilding the limiter, refills the bucket.
	cfg.PerIPRatePerMin = 6000
	cfg.PerIPBurst = 5
	clk.advance(time.Second)
	if !l.Allow("10.0.0.1") {
		t.Fatal("after the source raised the rate: want allowed")
	}

	// A lowered burst clamps the held tokens on the next call.
	cfg.PerIPBurst = 1
	cfg.PerIPRatePerMin = 0.0001
	clk.advance(time.Second)
	if !l.Allow("10.0.0.2") {
		t.Fatal("fresh IP: want allowed")
	}
	if l.Allow("10.0.0.2") {
		t.Fatal("fresh IP second call at lowered burst 1: want denied")
	}
}

// Proves EN-43.
func TestEnrollment_NATBatchJoinsInMinutes(t *testing.T) {
	clk := &advanceable{t: base}
	l := New(Enrollment(), WithClock(clk.clock))

	// Some 200 Nodes behind one address arrive at a steady pace: one attempt per
	// second from that address while the bucket is empty.
	const nodes = 200
	admitted := 0
	for admitted < nodes {
		if l.Allow("203.0.113.7") {
			admitted++
			continue
		}
		clk.advance(time.Second)
		if elapsed := clk.t.Sub(base); elapsed > 5*time.Minute {
			t.Fatalf("only %d of %d admitted after %v", admitted, nodes, elapsed)
		}
	}
}

// Proves EN-43.
func TestEnrollment_PerSourceAdmitsSixtyAMinute(t *testing.T) {
	cfg := Enrollment()
	cfg.GlobalRatePerMin, cfg.GlobalBurst = 1_000_000, 1_000_000 // not the bottleneck
	clk := &advanceable{t: base}
	l := New(cfg, WithClock(clk.clock))
	const ip = "203.0.113.7"

	for i := 0; i < EnrollmentPerIPBurst; i++ {
		if !l.Allow(ip) {
			t.Fatalf("burst call %d denied", i+1)
		}
	}
	if l.Allow(ip) {
		t.Fatal("a call past the burst was admitted")
	}
	for s := 1; s <= 60; s++ {
		clk.advance(time.Second)
		if !l.Allow(ip) {
			t.Fatalf("second %d: the per-source limit admits 60 a minute, got a denial", s)
		}
	}
}

// Proves EN-43.
func TestEnrollment_GlobalStillGuardsAFlood(t *testing.T) {
	clk := &advanceable{t: base}
	l := New(Enrollment(), WithClock(clk.clock))

	// Distinct addresses, so only the global bucket can refuse.
	n := 0
	attempt := func() bool {
		n++
		return l.Allow(fmt.Sprintf("10.%d.%d.%d", n>>16, (n>>8)&255, n&255))
	}

	burst := 0
	for i := 0; i < 1000; i++ {
		if attempt() {
			burst++
		}
	}
	if burst != EnrollmentGlobalBurst {
		t.Fatalf("a flood of distinct addresses at one instant admitted %d, want the global burst %d", burst, EnrollmentGlobalBurst)
	}

	// Twenty fresh addresses every second for ten minutes: sustained admission
	// is held to the global rate.
	const minutes = 10
	admitted := 0
	for s := 0; s < minutes*60; s++ {
		clk.advance(time.Second)
		for i := 0; i < 20; i++ {
			if attempt() {
				admitted++
			}
		}
	}
	want := EnrollmentGlobalRatePerMin * minutes
	if admitted < want-1 || admitted > want+1 {
		t.Fatalf("a sustained flood admitted %d over %d minutes, want about %d", admitted, minutes, want)
	}
}
