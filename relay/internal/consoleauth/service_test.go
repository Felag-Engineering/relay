package consoleauth_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

// recorder captures LoginEvents. failWith makes RecordLogin fail, which the
// service must treat as fatal to the sign-in.
type recorder struct {
	mu       sync.Mutex
	events   []consoleauth.LoginEvent
	failWith error
	// failKind, when set, narrows failWith to events of that Kind.
	failKind string
}

func (r *recorder) RecordLogin(_ context.Context, e consoleauth.LoginEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failWith != nil && (r.failKind == "" || r.failKind == e.Kind) {
		return r.failWith
	}
	r.events = append(r.events, e)
	return nil
}

func (r *recorder) all() []consoleauth.LoginEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]consoleauth.LoginEvent(nil), r.events...)
}

func (r *recorder) last() consoleauth.LoginEvent {
	all := r.all()
	if len(all) == 0 {
		return consoleauth.LoginEvent{}
	}
	return all[len(all)-1]
}

const testPassword = "a console password"

// fixture builds a Service over a real SQLite store, with one enabled human
// admin ("mike") holding testPassword.
type fixture struct {
	svc      *consoleauth.Service
	sessions *consoleauth.Store
	audit    *recorder
	accounts accounts.Repository
	mike     accounts.Account

	// clk drives the session store, the throttle and (through the store) the
	// Service. One clock for all three, deliberately: the production code
	// reads a single clock for the same reason.
	clk *clock
}

// countingAccounts counts GetByName calls, so a test can pin how many
// existence lookups a sign-in makes.
type countingAccounts struct {
	accounts.Repository
	mu     sync.Mutex
	byName int
}

func (c *countingAccounts) GetByName(ctx context.Context, name string) (accounts.Account, error) {
	c.mu.Lock()
	c.byName++
	c.mu.Unlock()
	return c.Repository.GetByName(ctx, name)
}

func (c *countingAccounts) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.byName
}

func newFixture(t *testing.T, opts ...consoleauth.ServiceOption) *fixture {
	t.Helper()
	return buildFixture(t, nil, opts...)
}

func newFixtureCounting(t *testing.T) (*fixture, *countingAccounts) {
	t.Helper()
	var counter *countingAccounts
	f := buildFixture(t, func(r accounts.Repository) accounts.Repository {
		counter = &countingAccounts{Repository: r}
		return counter
	})
	return f, counter
}

// buildFixture is newFixture's body; wrap, when set, decorates the Account
// repository the Service reads.
func buildFixture(t *testing.T, wrap func(accounts.Repository) accounts.Repository, opts ...consoleauth.ServiceOption) *fixture {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	mike, err := st.Accounts().Create(ctx, accounts.Account{
		Name: "mike", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create account: %v", err)
	}
	hash, err := accounts.HashPassword(accounts.NewPassword(testPassword))
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if err := st.Passwords().SetPassword(ctx, mike.ID, hash); err != nil {
		t.Fatalf("set password: %v", err)
	}

	rec := &recorder{}
	clk := newClock()
	sessions := consoleauth.NewStore(consoleauth.WithClock(clk.now))
	throttle := consoleauth.NewThrottle(consoleauth.WithThrottleClock(clk.now))
	repo := accounts.Repository(st.Accounts())
	if wrap != nil {
		repo = wrap(repo)
	}
	return &fixture{
		svc:      consoleauth.NewService(repo, st.Passwords(), sessions, throttle, rec, opts...),
		sessions: sessions,
		audit:    rec,
		accounts: st.Accounts(),
		mike:     mike,
		clk:      clk,
	}
}

func attempt(name, password string) consoleauth.Attempt {
	return consoleauth.Attempt{
		Name:     name,
		Password: accounts.NewPassword(password),
		Source:   "198.51.100.7",
	}
}

func TestLogin_Succeeds(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	id, sess, err := f.svc.Login(context.Background(), attempt("mike", testPassword))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if id.IsZero() {
		t.Fatal("Login returned no session identifier")
	}
	if sess.Account != "mike" || sess.Role != accounts.RoleAdmin {
		t.Errorf("Login returned %+v, want mike:admin", sess)
	}
	if _, err := f.sessions.Lookup(id); err != nil {
		t.Errorf("the issued session does not resolve: %v", err)
	}
}

// failingTouch fails every last-seen update.
type failingTouch struct{ accounts.Repository }

func (failingTouch) TouchLastSeen(context.Context, string, time.Time) error {
	return errors.New("disk full")
}

func TestLogin_LastSeenFailureIsLoggedNotFatal(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	f := buildFixture(t, func(r accounts.Repository) accounts.Repository {
		return failingTouch{r}
	}, consoleauth.WithLogger(logger))

	if _, _, err := f.svc.Login(context.Background(), attempt("mike", testPassword)); err != nil {
		t.Fatalf("Login: %v, want success despite the last-seen failure", err)
	}
	if out := logs.String(); !strings.Contains(out, "last-seen update failed") || !strings.Contains(out, "disk full") {
		t.Errorf("last-seen failure not logged; got %q", out)
	}
}

func TestLogin_NameIsNormalized(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	// An audit trail must never face two Accounts distinguishable only by
	// case, and neither must a sign-in form.
	if _, _, err := f.svc.Login(context.Background(), attempt("  MIKE ", testPassword)); err != nil {
		t.Errorf("Login with a differently-cased name: %v", err)
	}
}

// The headline no-enumeration property, asserted over every way a sign-in can
// fail: they must all be the SAME error.
func TestLogin_EveryFailureIsIndistinguishable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// Each case gets its own fixture so one case's failures cannot throttle
	// the next.
	//
	// wantName is what the record keeps of the typed name (D19): the name of
	// any existing Account, whatever its kind or state, else nothing.
	cases := map[string]struct {
		setup    func(t *testing.T, f *fixture) consoleauth.Attempt
		wantName string
	}{
		"an unknown username": {func(_ *testing.T, _ *fixture) consoleauth.Attempt {
			return attempt("no-such-person", testPassword)
		}, ""},
		"a wrong password": {func(_ *testing.T, _ *fixture) consoleauth.Attempt {
			return attempt("mike", "not the password")
		}, "mike"},
		"an empty password": {func(_ *testing.T, _ *fixture) consoleauth.Attempt {
			return attempt("mike", "")
		}, "mike"},
		"a disabled Account": {func(t *testing.T, f *fixture) consoleauth.Attempt {
			// A second enabled admin, so disabling mike below does not trip
			// the last-enabled-admin guard (#653) this test is not about —
			// it is about a disabled Account's login failing indistinguishably.
			if _, err := f.accounts.Create(ctx, accounts.Account{
				Name: "other-admin", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
			}); err != nil {
				t.Fatalf("create other admin: %v", err)
			}
			if err := f.accounts.SetEnabled(ctx, f.mike.ID, false); err != nil {
				t.Fatalf("disable account: %v", err)
			}
			return attempt("mike", testPassword)
		}, "mike"},
		"an Account with no local password": {func(t *testing.T, f *fixture) consoleauth.Attempt {
			other, err := f.accounts.Create(ctx, accounts.Account{
				Name: "passwordless", Kind: accounts.KindHuman, Role: accounts.RoleViewer, Enabled: true,
			})
			if err != nil {
				t.Fatalf("create account: %v", err)
			}
			_ = other
			return attempt("passwordless", testPassword)
		}, "passwordless"},
		"a machine Account": {func(t *testing.T, f *fixture) consoleauth.Attempt {
			// The Console establishes a per-HUMAN identity. A machine Account
			// has no business holding a browser session even if a password
			// somehow exists for it.
			bot, err := f.accounts.Create(ctx, accounts.Account{
				Name: "gleipnir", Kind: accounts.KindMachine, Role: accounts.RoleOperator, Enabled: true,
			})
			if err != nil {
				t.Fatalf("create account: %v", err)
			}
			_ = bot
			return attempt("gleipnir", testPassword)
		}, "gleipnir"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			a := tc.setup(t, f)

			_, _, err := f.svc.Login(ctx, a)
			if !errors.Is(err, consoleauth.ErrBadCredentials) {
				t.Fatalf("Login = %v, want ErrBadCredentials (every failure must be indistinguishable)", err)
			}
			// The response is one refusal. The record is not: it keeps the
			// typed name only when it is a real Account's (D19), its reader
			// being an admin who already sees every Account.
			last := f.audit.last()
			if last.Kind != audit.KindLoginFailed {
				t.Errorf("audited kind = %q, want %q", last.Kind, audit.KindLoginFailed)
			}
			if last.Account != "" || last.AccountID != "" {
				t.Errorf("a failed sign-in named an Account: %+v", last)
			}
			if last.Reason != "invalid credentials" {
				t.Errorf("audited reason = %q, want the one non-oracular reason", last.Reason)
			}
			if last.SubmittedName != tc.wantName {
				t.Errorf("audited submitted name = %q, want %q", last.SubmittedName, tc.wantName)
			}
		})
	}
}

// A failed sign-in records the typed name only when it is an existing
// Account's (D19): a name box can hold a password, so text that matches no
// Account is never stored.
func TestLogin_AFailedSignInRecordsTheNameOnlyWhenItIsAnAccounts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("a password-like string typed as the name is not recorded", func(t *testing.T) {
		f := newFixture(t)
		const typed = "correct horse battery staple"
		if _, _, err := f.svc.Login(ctx, attempt(typed, "whatever")); !errors.Is(err, consoleauth.ErrBadCredentials) {
			t.Fatalf("Login = %v, want ErrBadCredentials", err)
		}
		if got := f.audit.last().SubmittedName; got != "" {
			t.Errorf("SubmittedName = %q, want no typed text for a name that is not an Account", got)
		}
	})

	t.Run("a real Account's name is recorded as the Account's own", func(t *testing.T) {
		f := newFixture(t)
		if _, _, err := f.svc.Login(ctx, attempt("  MIKE ", "wrong")); !errors.Is(err, consoleauth.ErrBadCredentials) {
			t.Fatalf("Login = %v, want ErrBadCredentials", err)
		}
		if got := f.audit.last().SubmittedName; got != "mike" {
			t.Errorf("SubmittedName = %q, want the Account's name %q, not the typed bytes", got, "mike")
		}
	})
}

// A throttled attempt follows the same rule, and is still never counted as a
// guess: deciding that a name is real is a registry lookup, not a credential
// comparison.
func TestLogin_AThrottledSignInRecordsTheNameOnlyWhenItIsAnAccounts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, tc := range []struct{ typed, want string }{
		{"no-such-person", ""},
		{"mike", "mike"},
	} {
		t.Run(tc.typed, func(t *testing.T) {
			f := newFixture(t)
			if _, _, err := f.svc.Login(ctx, attempt(tc.typed, "wrong")); !errors.Is(err, consoleauth.ErrBadCredentials) {
				t.Fatalf("first Login = %v, want ErrBadCredentials", err)
			}
			_, _, err := f.svc.Login(ctx, attempt(tc.typed, "wrong"))
			var throttled *consoleauth.ThrottledError
			if !errors.As(err, &throttled) {
				t.Fatalf("immediate retry = %v, want a ThrottledError", err)
			}
			last := f.audit.last()
			if last.Kind != audit.KindLoginThrottled {
				t.Fatalf("audited kind = %q, want %q", last.Kind, audit.KindLoginThrottled)
			}
			if last.SubmittedName != tc.want {
				t.Errorf("SubmittedName = %q, want %q", last.SubmittedName, tc.want)
			}
			failed := 0
			for _, e := range f.audit.all() {
				if e.Kind == audit.KindLoginFailed {
					failed++
				}
			}
			if failed != 1 {
				t.Errorf("%d login_failed records, want 1: a throttled attempt is not a guess", failed)
			}
		})
	}
}

// The existence lookup D19 adds must run once on every attempt, before
// anything branches on its result, so its cost cannot depend on whether the
// name is an Account. It is pinned as a call count rather than a wall-clock
// measurement: timing is flaky on shared CI (precedent: accounts'
// TestVerifyNothing_DoesTheSameWorkAsARealVerification), and the KDF burn
// (VerifyNothing) remains what equalises the failed path's credential work.
//
// This does NOT claim the whole failed path is work-identical: the
// GetPassword read happens only for an enabled human Account, which is
// outside this test's scope. The throttled branch's timing is padded to a
// floor instead; see TestLogin_AThrottledRefusalWaitsOutTheSameFloorWhateverTheName.
func TestLogin_TheExistenceLookupIsUnconditional(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	tests := map[string]func(f *fixture) error{
		"unknown name, failed": func(f *fixture) error {
			_, _, err := f.svc.Login(ctx, attempt("no-such-person", "wrong"))
			return err
		},
		"real name, wrong password": func(f *fixture) error {
			_, _, err := f.svc.Login(ctx, attempt("mike", "wrong"))
			return err
		},
		"unknown name, throttled": func(f *fixture) error {
			_, _, _ = f.svc.Login(ctx, attempt("no-such-person", "wrong"))
			_, _, err := f.svc.Login(ctx, attempt("no-such-person", "wrong"))
			return err
		},
		"real name, throttled": func(f *fixture) error {
			_, _, _ = f.svc.Login(ctx, attempt("mike", "wrong"))
			_, _, err := f.svc.Login(ctx, attempt("mike", "wrong"))
			return err
		},
		"real name, success": func(f *fixture) error {
			_, _, err := f.svc.Login(ctx, attempt("mike", testPassword))
			return err
		},
	}
	wantThrottled := map[string]bool{
		"unknown name, throttled": true,
		"real name, throttled":    true,
	}
	// Attempts made before the measured one in a case, so its delta is the
	// last Login only.
	priorAttempts := map[string]int{
		"unknown name, throttled": 1,
		"real name, throttled":    1,
	}

	for name, run := range tests {
		t.Run(name, func(t *testing.T) {
			f, counter := newFixtureCounting(t)
			before := counter.count()
			err := run(f)
			var throttled *consoleauth.ThrottledError
			switch {
			case wantThrottled[name]:
				if !errors.As(err, &throttled) {
					t.Errorf("Login = %v, want a ThrottledError", err)
				}
			case name == "real name, success":
				if err != nil {
					t.Errorf("Login = %v, want success", err)
				}
			default:
				if !errors.Is(err, consoleauth.ErrBadCredentials) {
					t.Errorf("Login = %v, want ErrBadCredentials", err)
				}
			}
			if got, want := counter.count()-before, 1+priorAttempts[name]; got != want {
				t.Errorf("GetByName ran %d times, want exactly one per attempt (%d)", got, want)
			}
		})
	}
}

// On the throttled branch the lookup is the only Account-dependent work, so a
// found row could be told from no row by 429 latency. The refusal is padded to
// ThrottledFloor from the start of Login whatever the lookup found. The sleeper
// is injected, so nothing here waits for real; the fixture clock does not
// advance, so the whole floor is owed. A non-throttled attempt pays no floor:
// its time is the KDF's.
func TestLogin_AThrottledRefusalWaitsOutTheSameFloorWhateverTheName(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	for _, name := range []string{"mike", "no-such-person"} {
		t.Run(name, func(t *testing.T) {
			var waits []time.Duration
			f := newFixture(t, consoleauth.WithThrottledSleep(func(_ context.Context, d time.Duration) error {
				waits = append(waits, d)
				return nil
			}))

			if _, _, err := f.svc.Login(ctx, attempt(name, "wrong")); !errors.Is(err, consoleauth.ErrBadCredentials) {
				t.Fatalf("first Login = %v, want ErrBadCredentials", err)
			}
			if len(waits) != 0 {
				t.Fatalf("a failed (not throttled) attempt waited %v, want no floor", waits)
			}

			_, _, err := f.svc.Login(ctx, attempt(name, "wrong"))
			var throttled *consoleauth.ThrottledError
			if !errors.As(err, &throttled) {
				t.Fatalf("second Login = %v, want a ThrottledError", err)
			}
			if len(waits) != 1 || waits[0] != consoleauth.ThrottledFloor {
				t.Errorf("throttled refusal waited %v, want exactly [%v]", waits, consoleauth.ThrottledFloor)
			}
		})
	}
}

// A success records what was typed, as it always has; D19 changes only what a
// failure keeps.
func TestLogin_ASuccessfulSignInStillRecordsWhatWasTyped(t *testing.T) {
	t.Parallel()
	f := newFixture(t)

	if _, _, err := f.svc.Login(context.Background(), attempt("  MIKE ", testPassword)); err != nil {
		t.Fatalf("Login: %v", err)
	}
	last := f.audit.last()
	if last.Kind != audit.KindLoginSucceeded {
		t.Fatalf("audited kind = %q, want %q", last.Kind, audit.KindLoginSucceeded)
	}
	if last.SubmittedName != "  MIKE " {
		t.Errorf("SubmittedName = %q, want what was typed", last.SubmittedName)
	}
}

func TestLogin_AuditsEveryAttemptWithSourceAndMethod(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	if _, _, err := f.svc.Login(ctx, attempt("mike", "wrong")); err == nil {
		t.Fatal("a wrong password succeeded")
	}
	// Wait out the progressive delay the failure just earned, so this test
	// measures the audit trail rather than the throttle.
	f.clk.advance(consoleauth.DefaultAccountBaseDelay)
	if _, _, err := f.svc.Login(ctx, attempt("mike", testPassword)); err != nil {
		t.Fatalf("Login: %v", err)
	}

	events := f.audit.all()
	if len(events) != 2 {
		t.Fatalf("recorded %d events, want one per attempt", len(events))
	}
	for i, e := range events {
		if e.Source != "198.51.100.7" {
			t.Errorf("event %d has source %q, want the attempt's source", i, e.Source)
		}
		if e.Method != consoleauth.MethodPassword {
			t.Errorf("event %d has method %q, want %q", i, e.Method, consoleauth.MethodPassword)
		}
		if e.SubmittedName != "mike" {
			t.Errorf("event %d has submitted name %q", i, e.SubmittedName)
		}
	}
	if events[0].Kind != audit.KindLoginFailed || events[1].Kind != audit.KindLoginSucceeded {
		t.Errorf("kinds are %q then %q, want failed then succeeded", events[0].Kind, events[1].Kind)
	}
	// Only the successful one names the Account.
	if events[1].Account != "mike" || events[1].AccountID != f.mike.ID || events[1].Role != "admin" {
		t.Errorf("the successful sign-in is not attributed: %+v", events[1])
	}
}

func TestLogin_AnUnauditableSignInIsRefused(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.audit.failWith = errors.New("the audit store is unreachable")

	// An action that cannot be recorded does not happen. A Console session
	// nobody can account for is worse than a failed sign-in on a surface that
	// reaches fleet execution.
	id, _, err := f.svc.Login(context.Background(), attempt("mike", testPassword))
	if err == nil {
		t.Fatal("a sign-in that could not be audited succeeded")
	}
	if !id.IsZero() {
		t.Error("a session identifier was returned despite the failure")
	}
	if got := f.sessions.Len(); got != 0 {
		t.Errorf("%d sessions survive an unauditable sign-in, want 0", got)
	}
}

func TestLogin_RotatesAPresentedIdentifier(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	// A session identifier the browser already holds may have been planted
	// before the authentication boundary — by a link, by a shared machine, by
	// an attacker who set the cookie themselves.
	planted, err := f.sessions.Issue(consoleauth.Session{AccountID: "acct-x", Account: "victim"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	a := attempt("mike", testPassword)
	a.Existing = planted
	fresh, _, err := f.svc.Login(ctx, a)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if fresh.Reveal() == planted.Reveal() {
		t.Fatal("the sign-in reused the presented identifier: session fixation is open")
	}
	if _, err := f.sessions.Lookup(planted); err != consoleauth.ErrNoSession {
		t.Errorf("the planted identifier still resolves after the sign-in: %v", err)
	}
}

func TestLogin_ThrottleIsReportedAsAThrottleAndNotAsAFailure(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	if _, _, err := f.svc.Login(ctx, attempt("mike", "wrong")); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("first failure = %v", err)
	}
	// The immediate retry lands inside the progressive delay.
	_, _, err := f.svc.Login(ctx, attempt("mike", testPassword))
	wait, throttled := consoleauth.Throttled(err)
	if !throttled {
		t.Fatalf("an attempt inside the delay window returned %v, want a ThrottledError", err)
	}
	if wait <= 0 {
		t.Errorf("the throttle reported a wait of %s; a human needs to be told when to try again", wait)
	}
	// Never dressed up as a wrong password: a throttle disguised as a failure
	// teaches operators the product is flaky.
	if errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Error("a throttled attempt was reported as invalid credentials")
	}
	if got := f.audit.last().Kind; got != audit.KindLoginThrottled {
		t.Errorf("audited kind = %q, want %q — nothing was checked", got, audit.KindLoginThrottled)
	}
}

// TestLogin_ThrottledAuditStatesTheWaitRoundedUp (#640, item 4): a sub-second
// wait used to be rounded to NEAREST (time.Duration.Round), so a 400ms wait
// audited as "accepted in 0s" — a lie about a real, non-zero wait, and one
// that disagreed with both the page's own copy and the Retry-After header
// (which both use the ceiling). The audit reason must round up instead, so
// every surface names the same number.
func TestLogin_ThrottledAuditStatesTheWaitRoundedUp(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	// The first failure earns the base delay (1s, DefaultAccountBaseDelay).
	if _, _, err := f.svc.Login(ctx, attempt("mike", "wrong")); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("first failure = %v", err)
	}
	f.clk.advance(600 * time.Millisecond)

	_, _, err := f.svc.Login(ctx, attempt("mike", testPassword))
	wait, throttled := consoleauth.Throttled(err)
	if !throttled {
		t.Fatalf("an attempt 600ms into a 1s delay = %v, want a ThrottledError", err)
	}
	if wait != 400*time.Millisecond {
		t.Fatalf("wait = %s, want 400ms", wait)
	}

	reason := f.audit.last().Reason
	if !strings.Contains(reason, "accepted in 1s") {
		t.Errorf("reason = %q, want it to name the wait rounded UP to 1s", reason)
	}
	if strings.Contains(reason, "in 0s") {
		t.Errorf("reason = %q, rounds a real 400ms wait down to nothing", reason)
	}
	if want := int(math.Ceil(wait.Seconds())); !strings.Contains(reason, strconv.Itoa(want)+"s") {
		t.Errorf("reason = %q, does not name %ds — the same ceiling Retry-After uses", reason, want)
	}
}

func TestResolve_ReadsTheAccountFreshOnEveryCall(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	id, _, err := f.svc.Login(ctx, attempt("mike", testPassword))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// A second enabled admin, so demoting mike below does not trip the
	// last-enabled-admin guard (#653) this test is not about.
	if _, err := f.accounts.Create(ctx, accounts.Account{
		Name: "other-admin", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
	}); err != nil {
		t.Fatalf("create other admin: %v", err)
	}

	// A demotion must take effect on the very next click, not at the next
	// sign-in. The session's own snapshot still says admin; the resolved
	// Account is what authorization uses.
	if err := f.accounts.SetRole(ctx, f.mike.ID, accounts.RoleAdmin, accounts.RoleViewer); err != nil {
		t.Fatalf("SetRole: %v", err)
	}
	_, acct, err := f.svc.Resolve(ctx, id)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if acct.Role != accounts.RoleViewer {
		t.Errorf("Resolve returned role %q, want the demoted role", acct.Role)
	}
}

func TestResolve_DisablingAnAccountCutsSessionsAlreadyInFlight(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	id, _, err := f.svc.Login(ctx, attempt("mike", testPassword))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	// A second enabled admin, so disabling mike below does not trip the
	// last-enabled-admin guard (#653) this test is not about.
	if _, err := f.accounts.Create(ctx, accounts.Account{
		Name: "other-admin", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
	}); err != nil {
		t.Fatalf("create other admin: %v", err)
	}
	if err := f.accounts.SetEnabled(ctx, f.mike.ID, false); err != nil {
		t.Fatalf("SetEnabled: %v", err)
	}

	// The durable off-switch has to reach in-flight sessions, or a disabled
	// human keeps their Console until the session lapses on its own.
	if _, _, err := f.svc.Resolve(ctx, id); !errors.Is(err, consoleauth.ErrNoSession) {
		t.Fatalf("Resolve for a disabled Account = %v, want ErrNoSession", err)
	}
	if got := f.sessions.Len(); got != 0 {
		t.Errorf("%d sessions survive disabling the Account, want 0", got)
	}
}

func TestStepUp_RefreshesPresenceOnlyWithACredential(t *testing.T) {
	t.Parallel()
	f := newFixture(t, consoleauth.WithStepUpWindow(5*time.Minute))
	ctx := context.Background()

	id, _, err := f.svc.Login(ctx, attempt("mike", testPassword))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	// Sign-in alone does NOT prove presence for an act: step-up does.
	if err := f.svc.RequireStepUp(id); !errors.Is(err, consoleauth.ErrStepUpRequired) {
		t.Fatalf("RequireStepUp after a bare sign-in = %v, want ErrStepUpRequired", err)
	}

	// A wrong password must not stamp it.
	if _, err := f.svc.StepUp(ctx, id, accounts.NewPassword("wrong"), "198.51.100.7"); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("StepUp with a wrong password = %v, want ErrBadCredentials", err)
	}
	if err := f.svc.RequireStepUp(id); !errors.Is(err, consoleauth.ErrStepUpRequired) {
		t.Error("a refused step-up stamped the proof of presence")
	}

	// Past the throttle's delay, a correct password stamps the ROTATED id.
	f.clk.advance(10 * time.Second)
	newID, err := f.svc.StepUp(ctx, id, accounts.NewPassword(testPassword), "198.51.100.7")
	if err != nil {
		t.Fatalf("StepUp: %v", err)
	}
	if err := f.svc.RequireStepUp(newID); err != nil {
		t.Errorf("RequireStepUp after a step-up = %v, want nil", err)
	}
	if err := f.svc.RequireStepUp(id); !errors.Is(err, consoleauth.ErrNoSession) {
		t.Errorf("RequireStepUp on the pre-step-up id = %v, want ErrNoSession", err)
	}

	f.clk.advance(6 * time.Minute)
	if err := f.svc.RequireStepUp(newID); !errors.Is(err, consoleauth.ErrStepUpRequired) {
		t.Fatalf("RequireStepUp past the window = %v, want ErrStepUpRequired", err)
	}
}

func TestStepUp_RotatesTheSessionIdentifier(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	id, _, err := f.svc.Login(ctx, attempt("mike", testPassword))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	newID, err := f.svc.StepUp(ctx, id, accounts.NewPassword(testPassword), "198.51.100.7")
	if err != nil {
		t.Fatalf("StepUp: %v", err)
	}
	if newID.IsZero() || newID.Reveal() == id.Reveal() {
		t.Fatal("StepUp did not return a fresh identifier")
	}
	if f.svc.CSRFToken(newID).Reveal() == f.svc.CSRFToken(id).Reveal() {
		t.Error("the CSRF token did not change with the identifier")
	}
	if _, _, err := f.svc.Resolve(ctx, newID); err != nil {
		t.Errorf("the rotated session does not resolve: %v", err)
	}
}

// TestStepUp_AnUnauditableStepUpStampsNothing: a stamp left behind by a
// step-up the trail never heard of would be an unaudited window.
func TestStepUp_AnUnauditableStepUpStampsNothing(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	id, _, err := f.svc.Login(ctx, attempt("mike", testPassword))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	f.audit.failWith = errors.New("the audit store is unreachable")
	f.audit.failKind = audit.KindStepUp

	newID, err := f.svc.StepUp(ctx, id, accounts.NewPassword(testPassword), "198.51.100.7")
	if err == nil {
		t.Fatal("an unauditable step-up returned no error")
	}
	if !newID.IsZero() {
		t.Error("a failed step-up returned an identifier")
	}
	if err := f.svc.RequireStepUp(id); !errors.Is(err, consoleauth.ErrStepUpRequired) {
		t.Errorf("RequireStepUp(old) = %v, want ErrStepUpRequired: the stamp must not exist", err)
	}
	if _, _, err := f.svc.Resolve(ctx, id); err != nil {
		t.Errorf("the old id stopped resolving though nothing rotated: %v", err)
	}
}

func TestStepUp_AStampIsPerSession(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	a, _, err := f.svc.Login(ctx, attempt("mike", testPassword))
	if err != nil {
		t.Fatalf("Login A: %v", err)
	}
	f.clk.advance(10 * time.Second)
	b, _, err := f.svc.Login(ctx, attempt("mike", testPassword))
	if err != nil {
		t.Fatalf("Login B: %v", err)
	}
	f.clk.advance(10 * time.Second)
	if _, err := f.svc.StepUp(ctx, a, accounts.NewPassword(testPassword), "198.51.100.7"); err != nil {
		t.Fatalf("StepUp A: %v", err)
	}
	if err := f.svc.RequireStepUp(b); !errors.Is(err, consoleauth.ErrStepUpRequired) {
		t.Errorf("RequireStepUp(B) = %v, want ErrStepUpRequired: A's step-up leaked", err)
	}
}

func TestWithStepUpWindow_ClampsToTheMaximum(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"above the maximum", 2 * time.Hour, consoleauth.MaxStepUpWindow},
		{"within it", 3 * time.Minute, 3 * time.Minute},
		{"zero is the default", 0, consoleauth.DefaultStepUpWindow},
		{"negative is the default", -time.Minute, consoleauth.DefaultStepUpWindow},
	} {
		f := newFixture(t, consoleauth.WithStepUpWindow(tc.in))
		if got := f.svc.StepUpWindow(); got != tc.want {
			t.Errorf("%s: window = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestStepUp_IsNotACheaperCheckThanTheSignIn(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	id, _, err := f.svc.Login(ctx, attempt("mike", testPassword))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	// Step-up runs the same throttle as a sign-in. It is the strongest
	// per-action credential in the system; it must never be the easiest one
	// to grind against.
	if _, err := f.svc.StepUp(ctx, id, accounts.NewPassword("wrong"), "198.51.100.7"); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("StepUp: %v", err)
	}
	_, err = f.svc.StepUp(ctx, id, accounts.NewPassword(testPassword), "198.51.100.7")
	if _, throttled := consoleauth.Throttled(err); !throttled {
		t.Fatalf("an immediate step-up retry = %v, want a ThrottledError", err)
	}
}

// TestStepUp_AThrottledStepUpIsAudited is the bug the issue reported: a
// throttled step-up returned ThrottledError without recordLogin, so the
// throttle simply never reached the trail. Contrast Login's throttle branch,
// which always has.
func TestStepUp_AThrottledStepUpIsAudited(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	id, _, err := f.svc.Login(ctx, attempt("mike", testPassword))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := f.svc.StepUp(ctx, id, accounts.NewPassword("wrong"), "198.51.100.7"); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("StepUp with a wrong password = %v, want ErrBadCredentials", err)
	}
	afterFailure := len(f.audit.all())

	// 600ms into the 1s delay the failure above just earned, so the wait is
	// a sub-second 400ms — the exact case that used to round to "0s"
	// (time.Duration.Round) instead of up to "1s" (#640, item 4).
	f.clk.advance(600 * time.Millisecond)
	_, err = f.svc.StepUp(ctx, id, accounts.NewPassword(testPassword), "198.51.100.7")
	wait, throttled := consoleauth.Throttled(err)
	if !throttled {
		t.Fatalf("StepUp inside the delay window = %v, want a ThrottledError", err)
	}

	events := f.audit.all()
	// Exactly one new event: the count is what stops this test passing on
	// today's bug, where the throttle records nothing and the last event
	// stays the earlier failure.
	if got, want := len(events), afterFailure+1; got != want {
		t.Fatalf("recorded %d events after the throttled attempt, want %d", got, want)
	}
	last := events[len(events)-1]
	if last.Kind != audit.KindStepUpThrottled {
		t.Errorf("audited kind = %q, want %q", last.Kind, audit.KindStepUpThrottled)
	}
	if !strings.Contains(last.Reason, "step-up") {
		t.Errorf("reason = %q, does not name the step-up", last.Reason)
	}
	// The CEILING, agreeing with Retry-After — not time.Duration.Round, which
	// would round this 400ms wait down to "0s".
	ceiling := time.Duration(math.Ceil(wait.Seconds())) * time.Second
	if !strings.Contains(last.Reason, ceiling.String()) {
		t.Errorf("reason = %q, does not name the wait %s", last.Reason, ceiling)
	}
	if strings.Contains(last.Reason, "in 0s") {
		t.Errorf("reason = %q, rounds a real wait down to nothing", last.Reason)
	}
}

// TestStepUp_AnUnauditableThrottleIsNotSilentlyAThrottle: an audit failure on
// the throttle branch must fail closed exactly like every other exit of
// StepUp, not be swallowed so the caller still sees a plain ThrottledError.
func TestStepUp_AnUnauditableThrottleIsNotSilentlyAThrottle(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	id, _, err := f.svc.Login(ctx, attempt("mike", testPassword))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := f.svc.StepUp(ctx, id, accounts.NewPassword("wrong"), "198.51.100.7"); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("StepUp with a wrong password = %v, want ErrBadCredentials", err)
	}

	f.audit.failWith = errors.New("the audit store is unreachable")
	_, err = f.svc.StepUp(ctx, id, accounts.NewPassword(testPassword), "198.51.100.7")
	if err == nil {
		t.Fatal("an unauditable throttled step-up returned no error")
	}
	if _, throttled := consoleauth.Throttled(err); throttled {
		t.Errorf("an unauditable throttle was reported as an ordinary ThrottledError: %v", err)
	}
}

// TestStepUp_SucceedsUnderItsOwnAuditKind pins the fix for the issue's second
// bug: a successful step-up must be its own Kind, not indistinguishable from
// an ordinary sign-in.
func TestStepUp_SucceedsUnderItsOwnAuditKind(t *testing.T) {
	t.Parallel()
	f := newFixture(t, consoleauth.WithStepUpWindow(5*time.Minute))
	ctx := context.Background()

	id, _, err := f.svc.Login(ctx, attempt("mike", testPassword))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	// Past both the step-up window and the throttle's progressive delay.
	f.clk.advance(6 * time.Minute)

	if _, err := f.svc.StepUp(ctx, id, accounts.NewPassword(testPassword), "198.51.100.7"); err != nil {
		t.Fatalf("StepUp: %v", err)
	}

	events := f.audit.all()
	if len(events) != 2 {
		t.Fatalf("recorded %d events, want sign-in then step-up: %+v", len(events), events)
	}
	if events[0].Kind != audit.KindLoginSucceeded {
		t.Errorf("first event kind = %q, want %q", events[0].Kind, audit.KindLoginSucceeded)
	}
	last := events[len(events)-1]
	if last.Kind != audit.KindStepUp {
		t.Errorf("a successful step-up was recorded as %q, want %q", last.Kind, audit.KindStepUp)
	}
	if last.Account != "mike" || last.AccountID != f.mike.ID || last.Role != string(accounts.RoleAdmin) {
		t.Errorf("the successful step-up is not attributed: %+v", last)
	}
}

// TestStepUp_ARefusedStepUpIsNotASignInFailure pins the amendment: the
// step-up door's refusal must not be filed under the sign-in door's failure
// kind, even though that line "already worked" before this change.
func TestStepUp_ARefusedStepUpIsNotASignInFailure(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	id, _, err := f.svc.Login(ctx, attempt("mike", testPassword))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := f.svc.StepUp(ctx, id, accounts.NewPassword("wrong"), "198.51.100.7"); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("StepUp: %v", err)
	}

	last := f.audit.last()
	if last.Kind == audit.KindLoginFailed {
		t.Error("a refused step-up was filed under the sign-in door's failure kind — a consumer " +
			"watching login_failed would never see a session grinding at the step-up prompt")
	}
	if last.Kind != audit.KindStepUpFailed {
		t.Errorf("audited kind = %q, want %q", last.Kind, audit.KindStepUpFailed)
	}
}

// TestStepUp_RefusedAndThrottledStepUpsNameNoAccount holds LoginEvent's
// anti-enumeration rule (the verified lane is empty on every non-success
// record, ALWAYS) across the step-up door too. A step-up runs against an
// Account the Relay already knows, which makes filling the verified lane
// tempting — but doing so would break the very rule the pooling cost in the
// amendment's rationale depends on.
func TestStepUp_RefusedAndThrottledStepUpsNameNoAccount(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	id, _, err := f.svc.Login(ctx, attempt("mike", testPassword))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if _, err := f.svc.StepUp(ctx, id, accounts.NewPassword("wrong"), "198.51.100.7"); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("StepUp: %v", err)
	}
	refused := f.audit.last()
	if refused.Account != "" || refused.AccountID != "" {
		t.Errorf("a refused step-up named an Account: %+v", refused)
	}

	// The immediate retry lands inside the delay the refusal above earned.
	_, err = f.svc.StepUp(ctx, id, accounts.NewPassword(testPassword), "198.51.100.7")
	if _, throttled := consoleauth.Throttled(err); !throttled {
		t.Fatalf("StepUp inside the delay window = %v, want a ThrottledError", err)
	}
	throttledEvent := f.audit.last()
	if throttledEvent.Account != "" || throttledEvent.AccountID != "" {
		t.Errorf("a throttled step-up named an Account: %+v", throttledEvent)
	}
}

func TestLogout_EndsTheSessionAndRecordsIt(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	id, _, err := f.svc.Login(ctx, attempt("mike", testPassword))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if err := f.svc.Logout(ctx, id, "198.51.100.7"); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := f.sessions.Lookup(id); !errors.Is(err, consoleauth.ErrNoSession) {
		t.Errorf("the session survived sign-out: %v", err)
	}
	// The trail should say when someone stopped being able to act, not only
	// when they started.
	last := f.audit.last()
	if last.Kind != audit.KindLogout || last.Account != "mike" {
		t.Errorf("sign-out was recorded as %+v", last)
	}
	// Signing out twice is not an error.
	if err := f.svc.Logout(ctx, id, "198.51.100.7"); err != nil {
		t.Errorf("a second Logout: %v", err)
	}
}
