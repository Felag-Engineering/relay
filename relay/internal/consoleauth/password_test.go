package consoleauth_test

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

// password_test.go covers ADR-0045's Console passwords on the credential lane:
// the restricted session a temporary password opens, and ChangePassword. They
// run over a real store and the real auditsink, so the password write and its
// record are the production ones, with ONE hand-cranked clock for the session
// store, the throttle, the sink and the temporary password's expiry.

const (
	temporaryPassword = "temporary-password-aaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ownPassword       = "the humans own new password"
)

// changeSpy forwards to the real sink, recording each event, and can fail.
type changeSpy struct {
	next consoleauth.PasswordChangeRecorder

	mu     sync.Mutex
	events []consoleauth.PasswordChangeEvent
	fail   error
}

func (s *changeSpy) RecordPasswordChange(ctx context.Context, e consoleauth.PasswordChangeEvent) error {
	s.mu.Lock()
	s.events = append(s.events, e)
	fail := s.fail
	s.mu.Unlock()
	if fail != nil {
		return fail
	}
	return s.next.RecordPasswordChange(ctx, e)
}

func (s *changeSpy) recorded() []consoleauth.PasswordChangeEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]consoleauth.PasswordChangeEvent(nil), s.events...)
}

type pwFixture struct {
	st       *store.Store
	svc      *consoleauth.Service
	sessions *consoleauth.Store
	spy      *changeSpy
	clk      *clock
	mike     accounts.Account
	bea      accounts.Account
	// current is the password mike signs in with.
	current string
}

// newPWFixture builds mike (admin) with a password that is temporary (set
// through the store's own issue path, expiring after the 72-hour lifetime on
// the fixture clock) or his own, and bea (viewer) as a bystander.
func newPWFixture(t *testing.T, temporary bool) *pwFixture {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()

	mike, err := st.Accounts().Create(ctx, accounts.Account{Name: "mike", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true})
	if err != nil {
		t.Fatalf("create mike: %v", err)
	}
	bea, err := st.Accounts().Create(ctx, accounts.Account{Name: "bea", Kind: accounts.KindHuman, Role: accounts.RoleViewer, Enabled: true})
	if err != nil {
		t.Fatalf("create bea: %v", err)
	}
	for _, a := range []accounts.Account{bea} {
		h, _ := accounts.HashPassword(accounts.NewPassword("bea has her own password"))
		if err := st.Passwords().SetPassword(ctx, a.ID, h); err != nil {
			t.Fatal(err)
		}
	}

	clk := newClock()
	f := &pwFixture{st: st, clk: clk, mike: mike, bea: bea, current: testPassword}
	if temporary {
		f.current = temporaryPassword
		h, err := accounts.HashPassword(accounts.NewPassword(temporaryPassword))
		if err != nil {
			t.Fatal(err)
		}
		app := st.Audit().(audit.PasswordAppender)
		until := clk.now().Add(accounts.TemporaryPasswordLifetime)
		if err := app.AppendWithTemporaryPassword(ctx, mike.ID, h, until, audit.Record{
			ID: "seed-temp", Timestamp: clk.now(), Kind: audit.KindPasswordTemporarySet,
			Principal: "x", Reason: "account_id=" + mike.ID,
		}); err != nil {
			t.Fatalf("issue a temporary password: %v", err)
		}
	} else {
		h, _ := accounts.HashPassword(accounts.NewPassword(testPassword))
		if err := st.Passwords().SetPassword(ctx, mike.ID, h); err != nil {
			t.Fatal(err)
		}
	}

	sink := auditsink.New(st.Audit(), auditsink.WithClock(clk.now))
	f.spy = &changeSpy{next: sink}
	f.sessions = consoleauth.NewStore(consoleauth.WithClock(clk.now))
	f.svc = consoleauth.NewService(st.Accounts(), st.Passwords(), f.sessions,
		consoleauth.NewThrottle(consoleauth.WithThrottleClock(clk.now)), sink,
		consoleauth.WithPasswordChanges(f.spy))
	return f
}

// reissueTemporary replaces mike's temporary password, with the same value,
// by one that expires at until.
func (f *pwFixture) reissueTemporary(t *testing.T, until time.Time) {
	t.Helper()
	h, err := accounts.HashPassword(accounts.NewPassword(temporaryPassword))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.st.Audit().(audit.PasswordAppender).AppendWithTemporaryPassword(context.Background(), f.mike.ID, h, until, audit.Record{
		ID: "seed-reissue", Timestamp: f.clk.now(), Kind: audit.KindPasswordTemporarySet,
		Principal: "x", Reason: "account_id=" + f.mike.ID,
	}); err != nil {
		t.Fatalf("re-issue: %v", err)
	}
}

func (f *pwFixture) login(t *testing.T, name, password string) (consoleauth.SessionID, consoleauth.Session) {
	t.Helper()
	id, sess, err := f.svc.Login(context.Background(), attempt(name, password))
	if err != nil {
		t.Fatalf("Login(%s): %v", name, err)
	}
	return id, sess
}

func (f *pwFixture) kinds(t *testing.T) []string {
	t.Helper()
	recs, err := f.st.Audit().List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range recs {
		out = append(out, r.Kind)
	}
	return out
}

func (f *pwFixture) change(id consoleauth.SessionID, current, next, confirm string) (consoleauth.SessionID, error) {
	return f.svc.ChangePassword(context.Background(), id, consoleauth.PasswordChange{
		Current: accounts.NewPassword(current),
		New:     accounts.NewPassword(next),
		Confirm: accounts.NewPassword(confirm),
		Source:  "198.51.100.7",
	})
}

func countOf(kinds []string, want string) int {
	n := 0
	for _, k := range kinds {
		if k == want {
			n++
		}
	}
	return n
}

// --- the restricted session ---------------------------------------------

func TestLogin_TemporaryPasswordOpensARestrictedSession(t *testing.T) {
	t.Parallel()
	f := newPWFixture(t, true)

	_, sess := f.login(t, "mike", temporaryPassword)
	if !sess.Restricted {
		t.Error("a sign-in with a temporary password opened an unrestricted session")
	}

	own := newPWFixture(t, false)
	if _, sess := own.login(t, "mike", testPassword); sess.Restricted {
		t.Error("a sign-in with the human's own password opened a restricted session")
	}
}

func TestLogin_ExpiredTemporaryPasswordIsTheOneRefusal(t *testing.T) {
	t.Parallel()
	f := newPWFixture(t, true)
	ctx := context.Background()

	// One instant before expiry it still signs in; at expiry it is refused
	// exactly as a wrong password is: the same error and the same record.
	f.clk.advance(accounts.TemporaryPasswordLifetime - time.Nanosecond)
	if _, _, err := f.svc.Login(ctx, attempt("mike", temporaryPassword)); err != nil {
		t.Fatalf("Login one instant before expiry: %v", err)
	}
	f.clk.advance(time.Nanosecond)
	_, _, expiredErr := f.svc.Login(ctx, attempt("mike", temporaryPassword))
	if !errors.Is(expiredErr, consoleauth.ErrBadCredentials) {
		t.Fatalf("Login at expiry = %v, want ErrBadCredentials", expiredErr)
	}
	f.clk.advance(time.Minute)
	_, _, wrongErr := f.svc.Login(ctx, attempt("mike", "not the password at all"))
	if expiredErr.Error() != wrongErr.Error() {
		t.Errorf("an expired temporary password is refused as %q, a wrong password as %q", expiredErr, wrongErr)
	}

	recs, err := f.st.Audit().List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var failed []audit.Record
	for _, r := range recs {
		if r.Kind == audit.KindLoginFailed {
			failed = append(failed, r)
		}
	}
	if len(failed) != 2 {
		t.Fatalf("%d login_failed records, want 2 (expired and wrong)", len(failed))
	}
	if failed[0].Reason != failed[1].Reason {
		t.Errorf("an expired temporary password's record reads %q, a wrong password's %q: they must be one refusal", failed[0].Reason, failed[1].Reason)
	}
}

func TestStepUp_RefusedOnARestrictedSession(t *testing.T) {
	t.Parallel()
	f := newPWFixture(t, true)
	id, _ := f.login(t, "mike", temporaryPassword)
	before := len(f.kinds(t))

	_, err := f.svc.StepUp(context.Background(), id, accounts.NewPassword(temporaryPassword), "198.51.100.7")
	if !errors.Is(err, consoleauth.ErrPasswordChangeRequired) {
		t.Fatalf("StepUp on a restricted session = %v, want ErrPasswordChangeRequired", err)
	}
	if got := len(f.kinds(t)); got != before {
		t.Errorf("a refused step-up wrote %d records; nothing was compared, so nothing is recorded", got-before)
	}
	if err := f.svc.RequireStepUp(id); !errors.Is(err, consoleauth.ErrStepUpRequired) {
		t.Errorf("a restricted session was stamped: RequireStepUp = %v", err)
	}
}

// --- ChangePassword -----------------------------------------------------

func TestChangePassword_EndsOtherSessionsAndRotatesThisOne(t *testing.T) {
	t.Parallel()
	f := newPWFixture(t, true)
	ctx := context.Background()

	a1, _ := f.login(t, "mike", temporaryPassword)
	a2, _ := f.login(t, "mike", temporaryPassword)
	a3, _ := f.login(t, "mike", temporaryPassword)
	b1, _ := f.login(t, "bea", "bea has her own password")

	f.clk.advance(10 * time.Minute)
	newID, err := f.change(a1, temporaryPassword, ownPassword, ownPassword)
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	if _, err := f.sessions.Lookup(a1); !errors.Is(err, consoleauth.ErrNoSession) {
		t.Errorf("the pre-change identifier still resolves: %v", err)
	}
	for name, id := range map[string]consoleauth.SessionID{"a2": a2, "a3": a3} {
		if _, err := f.sessions.Lookup(id); !errors.Is(err, consoleauth.ErrNoSession) {
			t.Errorf("another session of the Account (%s) survived the change: %v", name, err)
		}
	}
	if _, err := f.sessions.Lookup(b1); err != nil {
		t.Errorf("another Account's session was ended: %v", err)
	}

	sess, err := f.sessions.Lookup(newID)
	if err != nil {
		t.Fatalf("the rotated identifier does not resolve: %v", err)
	}
	if sess.Restricted {
		t.Error("the session is still restricted after the change")
	}
	// The proof was a step-up, and every step-up stamps (pinned so a reviewer
	// who wants an unstamped session changes one line and this test).
	if !sess.AuthenticatedAt.Equal(f.clk.now()) {
		t.Errorf("AuthenticatedAt = %v, want the change's instant %v", sess.AuthenticatedAt, f.clk.now())
	}
	if err := f.svc.RequireStepUp(newID); err != nil {
		t.Errorf("RequireStepUp after the change = %v, want the stamp", err)
	}

	events := f.spy.recorded()
	if len(events) != 1 {
		t.Fatalf("%d change events, want 1", len(events))
	}
	e := events[0]
	if e.SessionsEnded != 2 || !e.Forced || e.AccountID != f.mike.ID || e.Account != "mike" || e.Source != "198.51.100.7" {
		t.Errorf("event = %+v, want forced, mike, 2 other sessions", e)
	}

	// The temporary password stops being accepted at that moment, and the new
	// one signs in as an ordinary session.
	f.clk.advance(time.Minute)
	if _, _, err := f.svc.Login(ctx, attempt("mike", temporaryPassword)); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Errorf("the redeemed temporary password still signs in: %v", err)
	}
	f.clk.advance(time.Minute) // past the strike that refusal earned
	if _, sess := f.login(t, "mike", ownPassword); sess.Restricted {
		t.Error("the new password opened a restricted session")
	}
}

func TestChangePassword_RecordsAStepUpAndAPasswordChangeNeverThePassword(t *testing.T) {
	t.Parallel()
	f := newPWFixture(t, false)
	id, _ := f.login(t, "mike", testPassword)
	other, _ := f.login(t, "mike", testPassword)
	_ = other

	if _, err := f.change(id, testPassword, ownPassword, ownPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	recs, err := f.st.Audit().List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var stepUp, change *audit.Record
	for i := range recs {
		switch recs[i].Kind {
		case audit.KindStepUp:
			stepUp = &recs[i]
		case audit.KindPasswordChange:
			change = &recs[i]
		}
	}
	if stepUp == nil || change == nil {
		t.Fatalf("the trail has step_up=%v password_change=%v, want both", stepUp != nil, change != nil)
	}
	if want := "account_id=" + f.mike.ID + " forced=false other_sessions_ended=1"; change.Reason != want {
		t.Errorf("password_change Reason = %q, want %q", change.Reason, want)
	}
	if v := change.Attribution.Verified; v.AccountID != f.mike.ID || v.AccountName != "mike" || v.Source != "198.51.100.7" || v.Method != consoleauth.MethodPassword {
		t.Errorf("verified lane = %+v, want mike over console_password from the request's address", v)
	}
	for _, r := range recs {
		for _, field := range []string{r.Reason, r.Principal} {
			for _, secret := range []string{testPassword, ownPassword, "argon2id"} {
				if strings.Contains(field, secret) {
					t.Errorf("record %s carries %q", r.Kind, secret)
				}
			}
		}
	}
}

func TestChangePassword_WrongCurrentIsRefusedAndRecordedAsStepUpFailed(t *testing.T) {
	t.Parallel()
	f := newPWFixture(t, false)
	id, _ := f.login(t, "mike", testPassword)

	_, err := f.change(id, "not my current password", ownPassword, ownPassword)
	if !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("err = %v, want ErrBadCredentials", err)
	}
	if n := len(f.spy.recorded()); n != 0 {
		t.Errorf("the recorder was called %d times for a refused proof", n)
	}
	kinds := f.kinds(t)
	if countOf(kinds, audit.KindStepUpFailed) != 1 || countOf(kinds, audit.KindPasswordChange) != 0 {
		t.Errorf("trail = %v, want one step_up_failed and no password_change: a failed proof is never an account row", kinds)
	}
	// The password is unchanged, the session intact, and a strike was taken.
	if _, _, err := f.svc.Login(context.Background(), attempt("mike", testPassword)); err == nil {
		t.Error("a sign-in straight after a failed proof was not delayed: no throttle strike")
	} else if _, ok := consoleauth.Throttled(err); !ok {
		t.Errorf("err = %v, want the throttle's delay", err)
	}
	if _, err := f.sessions.Lookup(id); err != nil {
		t.Errorf("a refused change ended the session: %v", err)
	}
}

func TestChangePassword_TheWindowNeverSatisfiesIt(t *testing.T) {
	t.Parallel()
	f := newPWFixture(t, false)
	ctx := context.Background()
	id, _ := f.login(t, "mike", testPassword)

	// A freshly stamped session: inside the window an act needs no password.
	stamped, err := f.svc.StepUp(ctx, id, accounts.NewPassword(testPassword), "198.51.100.7")
	if err != nil {
		t.Fatalf("StepUp: %v", err)
	}
	if err := f.svc.RequireStepUp(stamped); err != nil {
		t.Fatalf("the session is not inside the window: %v", err)
	}

	f.clk.advance(time.Minute)
	for name, current := range map[string]string{"wrong": "not my current password", "empty": ""} {
		if _, err := f.change(stamped, current, ownPassword, ownPassword); err == nil {
			t.Fatalf("a %s current password was accepted inside the window", name)
		}
	}
	if n := len(f.spy.recorded()); n != 0 {
		t.Errorf("the recorder was called %d times", n)
	}
	got, _ := f.st.Passwords().GetPassword(ctx, f.mike.ID)
	if !got.Hash.Verify(accounts.NewPassword(testPassword)) {
		t.Error("the password changed without a verified current password")
	}
}

func TestChangePassword_IsThrottledLikeSignIn(t *testing.T) {
	t.Parallel()
	f := newPWFixture(t, false)
	id, _ := f.login(t, "mike", testPassword)

	if _, err := f.change(id, "wrong one", ownPassword, ownPassword); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("first attempt = %v, want ErrBadCredentials", err)
	}
	// Straight away: refused before any credential is compared, even with the
	// right current password.
	_, err := f.change(id, testPassword, ownPassword, ownPassword)
	wait, throttled := consoleauth.Throttled(err)
	if !throttled || wait <= 0 {
		t.Fatalf("second attempt = %v, want a ThrottledError", err)
	}
	kinds := f.kinds(t)
	if countOf(kinds, audit.KindStepUpThrottled) != 1 {
		t.Errorf("trail = %v, want one step_up_throttled", kinds)
	}
	for _, r := range mustList(t, f) {
		if r.Kind == audit.KindStepUpThrottled && !strings.Contains(r.Reason, "password change") {
			t.Errorf("throttled Reason = %q, does not name a password change", r.Reason)
		}
	}
	if n := len(f.spy.recorded()); n != 0 {
		t.Errorf("the recorder was called %d times while throttled", n)
	}

	// After the delay the right password goes through.
	f.clk.advance(wait + time.Second)
	if _, err := f.change(id, testPassword, ownPassword, ownPassword); err != nil {
		t.Fatalf("attempt after the delay: %v", err)
	}
}

func mustList(t *testing.T, f *pwFixture) []audit.Record {
	t.Helper()
	recs, err := f.st.Audit().List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func TestChangePassword_RefusesBadInputBeforeComparingAnything(t *testing.T) {
	t.Parallel()
	f := newPWFixture(t, false)
	id, _ := f.login(t, "mike", testPassword)
	before := len(f.kinds(t))

	long := strings.Repeat("x", accounts.MaxPasswordBytes+1)
	for _, tc := range []struct {
		name                   string
		current, next, confirm string
		want                   error
	}{
		{"no current password", "", ownPassword, ownPassword, consoleauth.ErrCurrentPasswordRequired},
		{"too short", testPassword, "eleven byte", "eleven byte", accounts.ErrPasswordTooShort},
		{"too long", testPassword, long, long, accounts.ErrPasswordTooLong},
		{"confirmation differs", testPassword, ownPassword, ownPassword + "!", consoleauth.ErrPasswordMismatch},
		{"unchanged", testPassword, testPassword + "", testPassword, consoleauth.ErrPasswordUnchanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A wrong current would strike the throttle if it were compared.
			current := tc.current
			if tc.name == "too short" || tc.name == "too long" || tc.name == "confirmation differs" {
				current = "wrong, and never compared"
			}
			if _, err := f.change(id, current, tc.next, tc.confirm); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if got := len(f.kinds(t)); got != before {
		t.Errorf("refused input wrote %d records; nothing was compared, so nothing is recorded", got-before)
	}
	if n := len(f.spy.recorded()); n != 0 {
		t.Errorf("the recorder was called %d times", n)
	}
	// And none of it struck the throttle: the right password goes straight through.
	if _, err := f.change(id, testPassword, ownPassword, ownPassword); err != nil {
		t.Errorf("a valid change after refused input: %v", err)
	}
}

func TestChangePassword_ARecorderFailureChangesNothing(t *testing.T) {
	t.Parallel()
	f := newPWFixture(t, false)
	ctx := context.Background()
	id, _ := f.login(t, "mike", testPassword)
	other, _ := f.login(t, "mike", testPassword)

	f.spy.fail = errors.New("audit store unavailable")
	if _, err := f.change(id, testPassword, ownPassword, ownPassword); err == nil {
		t.Fatal("a change that could not be recorded succeeded")
	}
	for name, s := range map[string]consoleauth.SessionID{"this": id, "other": other} {
		if _, err := f.sessions.Lookup(s); err != nil {
			t.Errorf("a failed change ended the %s session: %v", name, err)
		}
	}
	got, _ := f.st.Passwords().GetPassword(ctx, f.mike.ID)
	if !got.Hash.Verify(accounts.NewPassword(testPassword)) {
		t.Error("the password changed although the change was not recorded")
	}
}

func TestChangePassword_AConcurrentChangeIsRefusedNotOverwritten(t *testing.T) {
	t.Parallel()
	f := newPWFixture(t, false)
	ctx := context.Background()
	id, _ := f.login(t, "mike", testPassword)

	// The stored password changes between the proof and the write: the write's
	// compare-and-set is what notices, so the spy changes it first.
	f.spy.next = swapFirst{inner: f.spy.next, st: f.st, accountID: f.mike.ID}
	_, err := f.change(id, testPassword, ownPassword, ownPassword)
	if !errors.Is(err, accounts.ErrPasswordChanged) {
		t.Fatalf("err = %v, want ErrPasswordChanged", err)
	}
	got, _ := f.st.Passwords().GetPassword(ctx, f.mike.ID)
	if !got.Hash.Verify(accounts.NewPassword("changed by someone else")) {
		t.Error("the stale change overwrote the newer password")
	}
	if _, err := f.sessions.Lookup(id); err != nil {
		t.Errorf("a refused change ended the session: %v", err)
	}
}

// swapFirst changes the stored password just before the real write.
type swapFirst struct {
	inner     consoleauth.PasswordChangeRecorder
	st        *store.Store
	accountID string
}

func (s swapFirst) RecordPasswordChange(ctx context.Context, e consoleauth.PasswordChangeEvent) error {
	h, _ := accounts.HashPassword(accounts.NewPassword("changed by someone else"))
	if err := s.st.Passwords().SetPassword(ctx, s.accountID, h); err != nil {
		return err
	}
	return s.inner.RecordPasswordChange(ctx, e)
}

func TestChangePassword_RefusesWithoutARecorderOrASession(t *testing.T) {
	t.Parallel()
	f := newFixture(t) // no WithPasswordChanges
	id, _, err := f.svc.Login(context.Background(), attempt("mike", testPassword))
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.svc.ChangePassword(context.Background(), id, consoleauth.PasswordChange{
		Current: accounts.NewPassword(testPassword), New: accounts.NewPassword(ownPassword), Confirm: accounts.NewPassword(ownPassword),
	})
	if !errors.Is(err, consoleauth.ErrPasswordChangeUnavailable) {
		t.Errorf("with no recorder = %v, want ErrPasswordChangeUnavailable", err)
	}

	p := newPWFixture(t, false)
	if _, err := p.change(consoleauth.ParseSessionID("no such session"), testPassword, ownPassword, ownPassword); !errors.Is(err, consoleauth.ErrNoSession) {
		t.Errorf("with no session = %v, want ErrNoSession", err)
	}
}

func TestChangePassword_AnExpiredTemporaryPasswordCannotProveItself(t *testing.T) {
	t.Parallel()
	f := newPWFixture(t, true)
	id, _ := f.login(t, "mike", temporaryPassword)

	// The temporary password expires during the restricted session (it was
	// issued with five minutes left): the proof fails as a step_up_failed with
	// the one refusal.
	f.reissueTemporary(t, f.clk.now().Add(5*time.Minute))
	f.clk.advance(6 * time.Minute)
	_, err := f.change(id, temporaryPassword, ownPassword, ownPassword)
	if !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("err = %v, want ErrBadCredentials", err)
	}
	if countOf(f.kinds(t), audit.KindStepUpFailed) != 1 {
		t.Errorf("trail = %v, want one step_up_failed", f.kinds(t))
	}
}

func TestChangePassword_ADisabledAccountsSessionIsRefused(t *testing.T) {
	t.Parallel()
	f := newPWFixture(t, false)
	ctx := context.Background()
	id, _ := f.login(t, "mike", testPassword)
	// Another admin keeps the last-admin guard quiet.
	if _, err := f.st.Accounts().Create(ctx, accounts.Account{Name: "root2", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := f.st.Accounts().SetEnabled(ctx, f.mike.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := f.change(id, testPassword, ownPassword, ownPassword); !errors.Is(err, consoleauth.ErrNoSession) {
		t.Errorf("err = %v, want ErrNoSession for a disabled Account", err)
	}
}
