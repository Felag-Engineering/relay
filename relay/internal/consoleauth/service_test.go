package consoleauth_test

import (
	"context"
	"errors"
	"path/filepath"
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
}

func (r *recorder) RecordLogin(_ context.Context, e consoleauth.LoginEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failWith != nil {
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

func newFixture(t *testing.T, opts ...consoleauth.ServiceOption) *fixture {
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
	return &fixture{
		svc:      consoleauth.NewService(st.Accounts(), st.Passwords(), sessions, throttle, rec, opts...),
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
	cases := map[string]func(t *testing.T, f *fixture) consoleauth.Attempt{
		"an unknown username": func(_ *testing.T, _ *fixture) consoleauth.Attempt {
			return attempt("no-such-person", testPassword)
		},
		"a wrong password": func(_ *testing.T, _ *fixture) consoleauth.Attempt {
			return attempt("mike", "not the password")
		},
		"an empty password": func(_ *testing.T, _ *fixture) consoleauth.Attempt {
			return attempt("mike", "")
		},
		"a disabled Account": func(t *testing.T, f *fixture) consoleauth.Attempt {
			if err := f.accounts.SetEnabled(ctx, f.mike.ID, false); err != nil {
				t.Fatalf("disable account: %v", err)
			}
			return attempt("mike", testPassword)
		},
		"an Account with no local password": func(t *testing.T, f *fixture) consoleauth.Attempt {
			other, err := f.accounts.Create(ctx, accounts.Account{
				Name: "passwordless", Kind: accounts.KindHuman, Role: accounts.RoleViewer, Enabled: true,
			})
			if err != nil {
				t.Fatalf("create account: %v", err)
			}
			_ = other
			return attempt("passwordless", testPassword)
		},
		"a machine Account": func(t *testing.T, f *fixture) consoleauth.Attempt {
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
		},
	}

	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			a := setup(t, f)

			_, _, err := f.svc.Login(ctx, a)
			if !errors.Is(err, consoleauth.ErrBadCredentials) {
				t.Fatalf("Login = %v, want ErrBadCredentials (every failure must be indistinguishable)", err)
			}
			// And the audit record must not say which half was wrong either:
			// a trail readable by every viewer is an enumeration oracle too.
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
		})
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

func TestResolve_ReadsTheAccountFreshOnEveryCall(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx := context.Background()

	id, _, err := f.svc.Login(ctx, attempt("mike", testPassword))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// A demotion must take effect on the very next click, not at the next
	// sign-in. The session's own snapshot still says admin; the resolved
	// Account is what authorization uses.
	if err := f.accounts.SetRole(ctx, f.mike.ID, accounts.RoleViewer); err != nil {
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
	// Sign-in itself proves presence.
	if err := f.svc.RequireStepUp(id); err != nil {
		t.Errorf("a fresh sign-in does not satisfy step-up: %v", err)
	}

	f.clk.advance(6 * time.Minute)
	if err := f.svc.RequireStepUp(id); !errors.Is(err, consoleauth.ErrStepUpRequired) {
		t.Fatalf("RequireStepUp past the window = %v, want ErrStepUpRequired", err)
	}

	// A wrong password must not refresh it.
	if err := f.svc.StepUp(ctx, id, accounts.NewPassword("wrong"), "198.51.100.7"); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("StepUp with a wrong password = %v, want ErrBadCredentials", err)
	}
	if err := f.svc.RequireStepUp(id); !errors.Is(err, consoleauth.ErrStepUpRequired) {
		t.Error("a refused step-up refreshed the proof of presence")
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
	if err := f.svc.StepUp(ctx, id, accounts.NewPassword("wrong"), "198.51.100.7"); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("StepUp: %v", err)
	}
	err = f.svc.StepUp(ctx, id, accounts.NewPassword(testPassword), "198.51.100.7")
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
	if err := f.svc.StepUp(ctx, id, accounts.NewPassword("wrong"), "198.51.100.7"); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("StepUp with a wrong password = %v, want ErrBadCredentials", err)
	}
	afterFailure := len(f.audit.all())

	// The immediate retry lands inside the progressive delay the failure
	// above just earned.
	err = f.svc.StepUp(ctx, id, accounts.NewPassword(testPassword), "198.51.100.7")
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
	if !strings.Contains(last.Reason, wait.Round(time.Second).String()) {
		t.Errorf("reason = %q, does not name the wait %s", last.Reason, wait.Round(time.Second))
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
	if err := f.svc.StepUp(ctx, id, accounts.NewPassword("wrong"), "198.51.100.7"); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("StepUp with a wrong password = %v, want ErrBadCredentials", err)
	}

	f.audit.failWith = errors.New("the audit store is unreachable")
	err = f.svc.StepUp(ctx, id, accounts.NewPassword(testPassword), "198.51.100.7")
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

	if err := f.svc.StepUp(ctx, id, accounts.NewPassword(testPassword), "198.51.100.7"); err != nil {
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
	if err := f.svc.StepUp(ctx, id, accounts.NewPassword("wrong"), "198.51.100.7"); !errors.Is(err, consoleauth.ErrBadCredentials) {
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

	if err := f.svc.StepUp(ctx, id, accounts.NewPassword("wrong"), "198.51.100.7"); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("StepUp: %v", err)
	}
	refused := f.audit.last()
	if refused.Account != "" || refused.AccountID != "" {
		t.Errorf("a refused step-up named an Account: %+v", refused)
	}

	// The immediate retry lands inside the delay the refusal above earned.
	err = f.svc.StepUp(ctx, id, accounts.NewPassword(testPassword), "198.51.100.7")
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
