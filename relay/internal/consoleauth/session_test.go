package consoleauth_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/consoleauth"
)

// clock is a hand-cranked clock so lifetime tests never sleep.
type clock struct{ t time.Time }

func newClock() *clock {
	return &clock{t: time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)}
}
func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func aSession() consoleauth.Session {
	return consoleauth.Session{
		AccountID: "acct-1",
		Account:   "mike",
		Role:      accounts.RoleAdmin,
		Kind:      accounts.KindHuman,
		Method:    consoleauth.MethodPassword,
		Source:    "198.51.100.7",
	}
}

func TestStore_IssueAndLookup(t *testing.T) {
	t.Parallel()
	c := newClock()
	st := consoleauth.NewStore(consoleauth.WithClock(c.now))

	id, err := st.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := st.Lookup(id)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if got.Account != "mike" || got.Role != accounts.RoleAdmin {
		t.Errorf("Lookup returned %+v, want the issued session", got)
	}
	if !got.CreatedAt.Equal(c.now()) || !got.LastSeenAt.Equal(c.now()) {
		t.Error("Issue did not stamp CreatedAt and LastSeenAt from the Store's clock")
	}
	if !got.AuthenticatedAt.IsZero() || got.StepUpFresh(c.now(), consoleauth.DefaultStepUpWindow) {
		t.Error("a fresh session carries a step-up stamp: sign-in must not satisfy step-up")
	}
}

func TestStore_IssueZeroesACallerSuppliedStepUpStamp(t *testing.T) {
	t.Parallel()
	c := newClock()
	st := consoleauth.NewStore(consoleauth.WithClock(c.now))

	sess := aSession()
	sess.AuthenticatedAt = c.now()
	id, err := st.Issue(sess)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := st.Lookup(id)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !got.AuthenticatedAt.IsZero() {
		t.Error("Issue let a caller hand in a pre-stamped session")
	}
}

func TestStore_UnknownIdentifierIsIndistinguishableFromAnEndedOne(t *testing.T) {
	t.Parallel()
	st := consoleauth.NewStore()

	id, err := st.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	st.End(id)

	_, endedErr := st.Lookup(id)
	_, unknownErr := st.Lookup(consoleauth.ParseSessionID("never-existed"))
	_, zeroErr := st.Lookup(consoleauth.SessionID{})

	// One error for all three. An answer that distinguished them would
	// confirm that a guessed identifier had once been real.
	if endedErr != consoleauth.ErrNoSession || unknownErr != consoleauth.ErrNoSession || zeroErr != consoleauth.ErrNoSession {
		t.Errorf("ended=%v unknown=%v zero=%v, want ErrNoSession for all three", endedErr, unknownErr, zeroErr)
	}
}

func TestStore_AbsoluteLifetimeIsNotExtendedByUse(t *testing.T) {
	t.Parallel()
	c := newClock()
	st := consoleauth.NewStore(
		consoleauth.WithClock(c.now),
		consoleauth.WithLifetimes(1*time.Hour, 30*time.Minute),
	)

	id, err := st.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Keep the session busy well inside the idle timeout. The absolute
	// lifetime must still end it: that is what makes a stolen cookie a
	// bounded loss rather than a permanent one.
	for i := 0; i < 5; i++ {
		c.advance(10 * time.Minute)
		if _, err := st.Lookup(id); err != nil {
			t.Fatalf("Lookup at +%dm: %v", (i+1)*10, err)
		}
	}
	c.advance(11 * time.Minute) // now past one hour
	if _, err := st.Lookup(id); err != consoleauth.ErrNoSession {
		t.Fatalf("Lookup past the absolute lifetime = %v, want ErrNoSession", err)
	}
}

func TestStore_IdleTimeoutEndsAnUnusedSession(t *testing.T) {
	t.Parallel()
	c := newClock()
	st := consoleauth.NewStore(
		consoleauth.WithClock(c.now),
		consoleauth.WithLifetimes(12*time.Hour, 30*time.Minute),
	)

	id, err := st.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	c.advance(29 * time.Minute)
	if _, err := st.Lookup(id); err != nil {
		t.Fatalf("Lookup inside the idle timeout: %v", err)
	}
	// That Lookup refreshed the idle clock, so another 29 minutes is fine.
	c.advance(29 * time.Minute)
	if _, err := st.Lookup(id); err != nil {
		t.Fatalf("Lookup after a refresh: %v", err)
	}
	c.advance(31 * time.Minute)
	if _, err := st.Lookup(id); err != consoleauth.ErrNoSession {
		t.Fatalf("Lookup past the idle timeout = %v, want ErrNoSession", err)
	}
}

func TestStore_BrowsingDoesNotRefreshTheStepUpStamp(t *testing.T) {
	t.Parallel()
	c := newClock()
	st := consoleauth.NewStore(consoleauth.WithClock(c.now))

	id, err := st.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	id, err = st.StepUp(id)
	if err != nil {
		t.Fatalf("StepUp: %v", err)
	}
	stampedAt := c.now()

	// Use the session repeatedly. Activity must not extend the proof of human
	// PRESENCE, or the window would measure browsing rather than a person.
	for i := 0; i < 3; i++ {
		c.advance(5 * time.Minute)
		if _, err := st.Lookup(id); err != nil {
			t.Fatalf("Lookup: %v", err)
		}
	}
	got, err := st.Lookup(id)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !got.AuthenticatedAt.Equal(stampedAt) {
		t.Errorf("AuthenticatedAt moved from %v to %v through activity alone", stampedAt, got.AuthenticatedAt)
	}
	if got.StepUpFresh(c.now(), 5*time.Minute) {
		t.Error("a 15-minute-old step-up still counts as fresh for a 5-minute step-up window")
	}

	// Re-authenticating is the only thing that moves it.
	id, err = st.StepUp(id)
	if err != nil {
		t.Fatalf("StepUp: %v", err)
	}
	got, err = st.Lookup(id)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !got.StepUpFresh(c.now(), 5*time.Minute) {
		t.Error("StepUp did not refresh the proof of human presence")
	}
}

func TestStore_RotateRetiresTheOldIdentifier(t *testing.T) {
	t.Parallel()
	st := consoleauth.NewStore()

	oldID, err := st.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	newID, err := st.Rotate(oldID)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newID.Reveal() == oldID.Reveal() {
		t.Fatal("Rotate returned the same identifier: session fixation is not closed")
	}
	// The planted identifier must be dead, not merely superseded.
	if _, err := st.Lookup(oldID); err != consoleauth.ErrNoSession {
		t.Errorf("the pre-rotation identifier still resolves: %v", err)
	}
	got, err := st.Lookup(newID)
	if err != nil {
		t.Fatalf("Lookup(newID): %v", err)
	}
	if got.Account != "mike" {
		t.Errorf("Rotate lost the session's identity: %+v", got)
	}
}

func TestStore_EndAllForCutsSessionsAlreadyInFlight(t *testing.T) {
	t.Parallel()
	st := consoleauth.NewStore()

	var mikes []consoleauth.SessionID
	for i := 0; i < 3; i++ {
		id, err := st.Issue(aSession())
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}
		mikes = append(mikes, id)
	}
	other := aSession()
	other.AccountID, other.Account = "acct-2", "dana"
	otherID, err := st.Issue(other)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if ended := st.EndAllFor("acct-1"); ended != 3 {
		t.Errorf("EndAllFor ended %d sessions, want 3", ended)
	}
	for i, id := range mikes {
		if _, err := st.Lookup(id); err != consoleauth.ErrNoSession {
			t.Errorf("session %d survived EndAllFor: %v", i, err)
		}
	}
	// Someone else's sessions are untouched.
	if _, err := st.Lookup(otherID); err != nil {
		t.Errorf("EndAllFor ended another Account's session: %v", err)
	}
}

func TestStore_EvictsOldestPastTheCeiling(t *testing.T) {
	t.Parallel()
	st := consoleauth.NewStore(consoleauth.WithMaxSessions(3))

	var ids []consoleauth.SessionID
	for i := 0; i < 5; i++ {
		id, err := st.Issue(aSession())
		if err != nil {
			t.Fatalf("Issue %d: %v", i, err)
		}
		ids = append(ids, id)
		time.Sleep(time.Millisecond) // distinct CreatedAt for oldest-first eviction
	}
	if got := st.Len(); got > 3 {
		t.Errorf("store holds %d sessions, want at most 3", got)
	}
	// The newest must survive: an attacker who could evict live operators by
	// filling the table would have a denial-of-service lever on the Console.
	if _, err := st.Lookup(ids[len(ids)-1]); err != nil {
		t.Errorf("the newest session was evicted: %v", err)
	}
}

func TestSessionID_NeverRendersItself(t *testing.T) {
	t.Parallel()
	st := consoleauth.NewStore()

	id, err := st.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	secret := id.Reveal()
	if len(secret) < 40 {
		t.Errorf("session identifier is only %d characters; want at least 256 bits of entropy", len(secret))
	}

	encoded, err := json.Marshal(struct{ ID consoleauth.SessionID }{id})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	// A session identifier is checked by EQUALITY, so a copy in a log line is
	// a working credential — a sharper problem than a leaked password hash.
	for name, rendered := range map[string]string{
		"String": id.String(),
		"%v":     fmt.Sprintf("%v", id),
		"%s":     fmt.Sprintf("%s", id), //nolint:staticcheck // the POINT is that the %s verb is covered: it reaches String() via the Stringer interface, and asserting that is what stops someone "simplifying" the type's redaction away
		"%#v":    fmt.Sprintf("%#v", id),
		"struct": fmt.Sprintf("%v", struct{ ID consoleauth.SessionID }{id}),
		"slog":   id.LogValue().String(),
		"json":   string(encoded),
	} {
		if strings.Contains(rendered, secret) {
			t.Errorf("%s rendered the live session identifier: %q", name, rendered)
		}
	}
}

// --- CSRF token derivation (#460) -------------------------------------------
//
// There is no CSRFSecret type and nothing stored on Session: the token is
// derived fresh, every time, from the Store's process-lifetime pepper and the
// session identifier. See Store.CSRFToken's doc for why an earlier stored-
// secret design was rejected.

func TestCSRFToken_IsStableForOneSession(t *testing.T) {
	t.Parallel()
	st := consoleauth.NewStore()

	id, err := st.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	first := st.CSRFToken(id)
	second := st.CSRFToken(id)
	if first.IsZero() {
		t.Fatal("CSRFToken returned empty for a live session")
	}
	// RED ON: making the token random per call, which would break every form
	// — a token rendered into a page has to still be valid by the time the
	// browser submits it.
	if first != second {
		t.Errorf("CSRFToken(%v) = %q then %q; want the same value both times", id, first, second)
	}
}

func TestCSRFToken_DiffersBetweenSessions(t *testing.T) {
	t.Parallel()
	st := consoleauth.NewStore()

	id1, err := st.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	id2, err := st.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// RED ON: keying the HMAC on anything but the identifier (e.g. the
	// Account), which would let one session's rendered token validate
	// another's request.
	if st.CSRFToken(id1) == st.CSRFToken(id2) {
		t.Error("two distinct sessions derived the same CSRF token")
	}
}

func TestCSRFToken_DiffersAcrossStores(t *testing.T) {
	t.Parallel()
	c := newClock()
	st1 := consoleauth.NewStore(consoleauth.WithClock(c.now))
	st2 := consoleauth.NewStore(consoleauth.WithClock(c.now))

	// The identifier is a 256-bit CSPRNG value; the only way two Stores can
	// be asked about "the same id" in a test is to hand each the very same
	// SessionID rather than to Issue twice and hope for a collision.
	id, err := st1.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	// RED ON: a package-level or hard-coded pepper, which would make one
	// Relay's rendered tokens valid against a different Relay's sessions —
	// exactly the exposure a per-process pepper exists to prevent.
	if st1.CSRFToken(id) == st2.CSRFToken(id) {
		t.Error("two different Stores derived the same CSRF token for the same identifier")
	}
}

func TestCSRFToken_ChangesWhenTheIdentifierDoes(t *testing.T) {
	t.Parallel()
	st := consoleauth.NewStore()

	oldID, err := st.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	before := st.CSRFToken(oldID)

	newID, err := st.Rotate(oldID)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	after := st.CSRFToken(newID)

	// This pins that CSRF rotation is STRUCTURAL, not a line someone has to
	// add to Rotate: the new session's token differs from the old one purely
	// because the derivation is keyed on the identifier, and Rotate already
	// mints a fresh identifier for the session-fixation control. Nothing in
	// Rotate itself needs to know about CSRF at all — which is the point:
	// this test exists so a later reader who thinks CSRF rotation logic is
	// MISSING from Rotate finds this test instead of adding one.
	//
	// The pre-rotation identifier is deliberately not re-derived here: it no
	// longer resolves to any live session (TestStore_RotateRetiresTheOldIdentifier
	// pins that), so nothing checks a submitted token against it again — the
	// derivation being a pure function of oldID is harmless, not a residual
	// hazard.
	if before == after {
		t.Error("the CSRF token survived Rotate unchanged; rotation must be automatic under derivation")
	}
}

func TestCSRFToken_ZeroIdentifierYieldsNoToken(t *testing.T) {
	t.Parallel()
	st := consoleauth.NewStore()

	if got := st.CSRFToken(consoleauth.SessionID{}); !got.IsZero() {
		t.Errorf("CSRFToken(zero) = %q, want the zero token", got.Reveal())
	}
}

func TestCSRFTokensEqual_RefusesEmptiesAndZero(t *testing.T) {
	t.Parallel()
	st := consoleauth.NewStore()

	id, err := st.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	token := st.CSRFToken(id)
	if token.IsZero() {
		t.Fatal("CSRFToken returned empty for a live session")
	}

	// RED ON: dropping the empty guard and trusting
	// subtle.ConstantTimeCompare("", "") == 1 — which is exactly true, and
	// exactly the bypass this guard exists to close.
	cases := []struct {
		name            string
		held, submitted string
	}{
		{"empty held, empty submitted", "", ""},
		{"empty held, real submitted", "", token.Reveal()},
		{"real held, empty submitted", token.Reveal(), ""},
	}
	for _, c := range cases {
		if consoleauth.CSRFTokensEqual(c.held, c.submitted) {
			t.Errorf("%s: CSRFTokensEqual(%q, %q) = true, want false", c.name, c.held, c.submitted)
		}
	}
	if !consoleauth.CSRFTokensEqual(token.Reveal(), token.Reveal()) {
		t.Error("CSRFTokensEqual refused a token compared against itself")
	}
}

// TestCSRFToken_IsNotLoggable pins that the derived token never rides on
// Session at all — trivially true today because there is no field to log,
// but asserted anyway so a future refactor that adds one back (to "cache" the
// derivation, say) is caught by a test rather than by a security review.
func TestCSRFToken_IsNotLoggable(t *testing.T) {
	t.Parallel()
	st := consoleauth.NewStore()

	id, err := st.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	sess, err := st.Lookup(id)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	token := st.CSRFToken(id)

	rendered := fmt.Sprintf("%+v", sess)
	if strings.Contains(rendered, token.Reveal()) {
		t.Errorf("%%+v of a Session contains the derived CSRF token %q — it must not be a field on Session", token.Reveal())
	}
}

func TestStore_IdentifiersAreUnique(t *testing.T) {
	t.Parallel()
	st := consoleauth.NewStore(consoleauth.WithMaxSessions(1000))

	seen := make(map[string]bool)
	for i := 0; i < 500; i++ {
		id, err := st.Issue(aSession())
		if err != nil {
			t.Fatalf("Issue %d: %v", i, err)
		}
		if seen[id.Reveal()] {
			t.Fatalf("Issue produced a duplicate identifier at iteration %d", i)
		}
		seen[id.Reveal()] = true
	}
}

// TestCSRFToken_RefusesAnIdentifierThatIsNotLive pins finding 3 of #460's
// security review: CSRFToken must not be a forgery oracle for any identifier a
// caller can name.
//
// Without a liveness check the method hands back a permanently-valid token for
// a session the caller does not own, and nothing in the signature warns them.
// Today's only caller has already resolved the session, so the check is
// redundant TODAY — which is precisely the kind of safety that stops holding
// when a second caller appears. #428's step-up POST is the expected one, and
// like handleLoginSubmit it reads the raw cookie rather than a resolved session.
//
// *Fails if*: the liveness lookup is removed and the method derives from shape
// alone.
func TestCSRFToken_RefusesAnIdentifierThatIsNotLive(t *testing.T) {
	t.Parallel()
	st := consoleauth.NewStore()

	// Never issued: the shape is plausible, the session does not exist.
	invented := consoleauth.ParseSessionID("0000000000000000000000000000000000000000000")
	if got := st.CSRFToken(invented); !got.IsZero() {
		t.Errorf("CSRFToken(never-issued) = %q, want the zero token", got.Reveal())
	}

	// Issued and then ended: the identifier was real and must stop deriving.
	id, err := st.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if st.CSRFToken(id).IsZero() {
		t.Fatal("CSRFToken returned nothing for a live session")
	}
	st.End(id)
	if got := st.CSRFToken(id); !got.IsZero() {
		t.Errorf("CSRFToken(ended session) = %q, want the zero token — the token must die with the session", got.Reveal())
	}
}

// TestCSRFToken_AZeroStorePanicsRatherThanForging pins finding 4: a Store built
// without NewStore would derive under a nil HMAC key, producing a value anyone
// knowing the raw identifier can recompute, identical in every process.
//
// No construction path produces one today, which is why this is loud rather
// than silent: the single way to obtain a universally-forgeable token should
// fail the way NewStore fails on a broken entropy source, not return quietly.
func TestCSRFToken_AZeroStorePanicsRatherThanForging(t *testing.T) {
	t.Parallel()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("a zero-value Store derived a token instead of panicking")
		}
		// The MESSAGE is the assertion, not merely that something panicked. A
		// zero Store also has a nil clock, so removing the pepper guard still
		// panics — one frame deeper, on calling s.now(). An assertion that only
		// checked "it panicked" would therefore pass with the guard deleted,
		// which a coordinator mutation pass confirmed. Naming the guard's own
		// message is what makes this test about the guard.
		msg := fmt.Sprint(r)
		if !strings.Contains(msg, "NewStore") {
			t.Errorf("panic = %q, want the pepper guard's message naming NewStore; "+
				"a panic from somewhere else means the guard is gone", msg)
		}
	}()
	var st consoleauth.Store
	_ = st.CSRFToken(consoleauth.ParseSessionID("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
}

func TestStore_StepUpRotatesAndStampsAtomically(t *testing.T) {
	t.Parallel()
	c := newClock()
	st := consoleauth.NewStore(consoleauth.WithClock(c.now))

	oldID, err := st.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	created := c.now()
	c.advance(time.Minute)

	newID, err := st.StepUp(oldID)
	if err != nil {
		t.Fatalf("StepUp: %v", err)
	}
	if newID.Reveal() == oldID.Reveal() {
		t.Fatal("StepUp returned the same identifier: a privilege change did not rotate the session")
	}
	if _, err := st.Lookup(oldID); err != consoleauth.ErrNoSession {
		t.Errorf("the pre-step-up identifier still resolves: %v", err)
	}
	got, err := st.Lookup(newID)
	if err != nil {
		t.Fatalf("Lookup(newID): %v", err)
	}
	if got.Account != "mike" || !got.CreatedAt.Equal(created) {
		t.Errorf("StepUp lost the session's identity or absolute clock: %+v", got)
	}
	if !got.AuthenticatedAt.Equal(c.now()) {
		t.Errorf("AuthenticatedAt = %v, want %v", got.AuthenticatedAt, c.now())
	}
}

func TestStore_ConcurrentStepUpsOfOneIdentifierYieldExactlyOneWinner(t *testing.T) {
	t.Parallel()
	st := consoleauth.NewStore()
	oldID, err := st.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	const n = 16
	results := make(chan consoleauth.SessionID, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, err := st.StepUp(oldID)
			results <- id
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)

	winners := 0
	for id := range results {
		if !id.IsZero() {
			winners++
		}
	}
	for err := range errs {
		if err != nil && err != consoleauth.ErrNoSession {
			t.Errorf("a losing StepUp returned %v, want ErrNoSession", err)
		}
	}
	if winners != 1 {
		t.Errorf("%d StepUps won, want exactly one", winners)
	}
	if st.Len() != 1 {
		t.Errorf("Len = %d, want 1", st.Len())
	}
}

func TestStore_StepUpRefusesAnExpiredSession(t *testing.T) {
	t.Parallel()
	c := newClock()
	st := consoleauth.NewStore(consoleauth.WithClock(c.now))
	id, err := st.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	c.advance(consoleauth.DefaultIdleTimeout + time.Minute)

	if _, err := st.StepUp(id); err != consoleauth.ErrNoSession {
		t.Errorf("StepUp past the idle timeout = %v, want ErrNoSession", err)
	}
	if st.Len() != 0 {
		t.Errorf("Len = %d, want the expired session evicted", st.Len())
	}
}

func TestStore_RotateRefusesAnExpiredSession(t *testing.T) {
	t.Parallel()
	c := newClock()
	st := consoleauth.NewStore(consoleauth.WithClock(c.now))
	id, err := st.Issue(aSession())
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	c.advance(consoleauth.DefaultIdleTimeout + time.Minute)

	if _, err := st.Rotate(id); err != consoleauth.ErrNoSession {
		t.Errorf("Rotate past the idle timeout = %v, want ErrNoSession", err)
	}
	if st.Len() != 0 {
		t.Errorf("Len = %d, want the expired session evicted", st.Len())
	}
}

func TestClampStepUpWindow(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in      time.Duration
		want    time.Duration
		clamped bool
	}{
		{2 * time.Hour, consoleauth.MaxStepUpWindow, true},
		{consoleauth.MaxStepUpWindow + time.Nanosecond, consoleauth.MaxStepUpWindow, true},
		{consoleauth.MaxStepUpWindow, consoleauth.MaxStepUpWindow, false},
		{3 * time.Minute, 3 * time.Minute, false},
		{0, 0, false},
		{-time.Minute, -time.Minute, false},
	} {
		got, clamped := consoleauth.ClampStepUpWindow(tc.in)
		if got != tc.want || clamped != tc.clamped {
			t.Errorf("ClampStepUpWindow(%v) = (%v, %v), want (%v, %v)", tc.in, got, clamped, tc.want, tc.clamped)
		}
	}
}
