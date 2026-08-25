package consoleauth_test

import (
	"encoding/json"
	"fmt"
	"strings"
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
	if !got.CreatedAt.Equal(c.now()) || !got.AuthenticatedAt.Equal(c.now()) {
		t.Error("Issue did not stamp CreatedAt and AuthenticatedAt from the Store's clock")
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
	issuedAt := c.now()

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
	if !got.AuthenticatedAt.Equal(issuedAt) {
		t.Errorf("AuthenticatedAt moved from %v to %v through activity alone", issuedAt, got.AuthenticatedAt)
	}
	if got.StepUpFresh(c.now(), 5*time.Minute) {
		t.Error("a 15-minute-old sign-in still counts as fresh for a 5-minute step-up window")
	}

	// Re-authenticating is the only thing that moves it.
	if err := st.StepUp(id); err != nil {
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
		"%s":     fmt.Sprintf("%s", id), //nolint:gosimple,staticcheck // the POINT is that the %s verb is covered: it reaches String() via the Stringer interface, and asserting that is what stops someone "simplifying" the type's redaction away
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
