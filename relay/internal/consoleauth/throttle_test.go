package consoleauth_test

import (
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
)

func TestThrottle_ClearAtFirst(t *testing.T) {
	t.Parallel()
	th := consoleauth.NewThrottle()
	if wait := th.Check("198.51.100.7", "mike"); wait != 0 {
		t.Errorf("a first attempt is throttled by %s, want 0", wait)
	}
}

func TestThrottle_CheckingCostsNothing(t *testing.T) {
	t.Parallel()
	th := consoleauth.NewThrottle()

	// Asking "am I allowed to try" must never spend the budget that answer
	// describes, or a page refresh would throttle an operator who has not
	// typed a password yet.
	for i := 0; i < 100; i++ {
		if wait := th.Check("198.51.100.7", "mike"); wait != 0 {
			t.Fatalf("Check %d throttled by %s without any failure recorded", i, wait)
		}
	}
}

func TestThrottle_AccountDelayDoublesAndCaps(t *testing.T) {
	t.Parallel()
	c := newClock()
	th := consoleauth.NewThrottle(
		consoleauth.WithThrottleClock(c.now),
		consoleauth.WithAccountDelays(time.Second, 60*time.Second),
		// Take the source lane out of the picture so this measures the
		// per-name progression alone.
		consoleauth.WithSourceBudget(100_000, 100_000),
	)

	want := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		32 * time.Second,
		60 * time.Second, // capped, not 64
		60 * time.Second,
		60 * time.Second,
	}
	for i, expect := range want {
		th.Fail("198.51.100.7", "mike")
		got := th.Check("198.51.100.7", "mike")
		if got != expect {
			t.Errorf("after %d consecutive failures the delay is %s, want %s", i+1, got, expect)
		}
		c.advance(expect) // wait it out, then fail again
	}
}

func TestThrottle_NeverLocksOut(t *testing.T) {
	t.Parallel()
	c := newClock()
	th := consoleauth.NewThrottle(consoleauth.WithThrottleClock(c.now))

	// The control the spec is emphatic about: an attacker must not be able to
	// lock the admin out of the Console during the incident they are causing.
	// However many failures pile up, waiting out the delay must let the real
	// operator back in.
	for i := 0; i < 200; i++ {
		th.Fail("203.0.113.9", "mike")
	}
	c.advance(2 * time.Hour)
	if wait := th.Check("198.51.100.7", "mike"); wait != 0 {
		t.Fatalf("after waiting out 200 failures the admin is still refused for %s", wait)
	}
}

func TestThrottle_SourceBudgetBitesAfterItsBurst(t *testing.T) {
	t.Parallel()
	c := newClock()
	th := consoleauth.NewThrottle(
		consoleauth.WithThrottleClock(c.now),
		consoleauth.WithSourceBudget(10, 10),
		// Take the per-name lane out of the picture: vary the name so no
		// streak accumulates, which is also what a spraying attacker does.
		consoleauth.WithAccountDelays(time.Nanosecond, time.Nanosecond),
	)

	names := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}
	for _, n := range names {
		th.Fail("203.0.113.9", n)
	}
	c.advance(time.Millisecond) // outlast the nanosecond per-name delay
	if wait := th.Check("203.0.113.9", "k"); wait <= 0 {
		t.Fatal("a source that spent its whole failure budget is not throttled")
	}
	// A different source is unaffected: one address behind a NAT must not
	// throttle the whole office's neighbours.
	if wait := th.Check("198.51.100.7", "k"); wait != 0 {
		t.Errorf("an unrelated source is throttled by %s", wait)
	}
}

func TestThrottle_UnknownNamesAreThrottledLikeRealOnes(t *testing.T) {
	t.Parallel()
	c := newClock()
	th := consoleauth.NewThrottle(
		consoleauth.WithThrottleClock(c.now),
		consoleauth.WithSourceBudget(100_000, 100_000),
	)

	// The throttle is keyed by the SUBMITTED name, not by an Account. If
	// existing Accounts got slower and unknown ones stayed fast, the throttle
	// would itself be a user-enumeration oracle — a much louder one than a
	// timing difference, since it is measured in whole seconds.
	th.Fail("198.51.100.7", "definitely-not-an-account")
	th.Fail("198.51.100.7", "definitely-not-an-account")
	th.Fail("198.51.100.7", "mike")
	th.Fail("198.51.100.7", "mike")

	unknown := th.Check("198.51.100.7", "definitely-not-an-account")
	known := th.Check("198.51.100.7", "mike")
	if unknown != known {
		t.Errorf("an unknown name is delayed %s and a real one %s: the throttle enumerates Accounts", unknown, known)
	}
	if unknown == 0 {
		t.Error("neither name is delayed after two failures each")
	}
}

func TestThrottle_SuccessClearsTheNameStreak(t *testing.T) {
	t.Parallel()
	c := newClock()
	th := consoleauth.NewThrottle(
		consoleauth.WithThrottleClock(c.now),
		consoleauth.WithSourceBudget(100_000, 100_000),
	)

	th.Fail("198.51.100.7", "mike")
	th.Fail("198.51.100.7", "mike")
	th.Fail("198.51.100.7", "mike")
	th.Succeed("198.51.100.7", "mike")

	if wait := th.Check("198.51.100.7", "mike"); wait != 0 {
		t.Errorf("a successful sign-in left a %s delay behind", wait)
	}
	// The next failure starts the progression over rather than resuming it.
	th.Fail("198.51.100.7", "mike")
	if got := th.Check("198.51.100.7", "mike"); got != time.Second {
		t.Errorf("the failure after a success is delayed %s, want the base delay of 1s", got)
	}
}

func TestThrottle_StreakIsForgottenWhenAttemptsStop(t *testing.T) {
	t.Parallel()
	c := newClock()
	th := consoleauth.NewThrottle(
		consoleauth.WithThrottleClock(c.now),
		consoleauth.WithSourceBudget(100_000, 100_000),
	)

	th.Fail("198.51.100.7", "mike")
	th.Fail("198.51.100.7", "mike")
	th.Fail("198.51.100.7", "mike")

	// Yesterday's typos must not slow down today's sign-in. The sweep runs on
	// the write path, so a later unrelated failure is what triggers it.
	c.advance(consoleauth.DefaultAccountForget + time.Minute)
	th.Fail("198.51.100.7", "someone-else")

	if wait := th.Check("198.51.100.7", "mike"); wait != 0 {
		t.Errorf("a streak from %s ago still delays by %s", consoleauth.DefaultAccountForget, wait)
	}
}
