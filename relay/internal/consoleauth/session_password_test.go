package consoleauth_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
)

func sessionOf(account string) consoleauth.Session {
	s := aSession()
	s.AccountID = account
	return s
}

func TestStore_IssueKeepsRestrictedAndStillZeroesTheStamp(t *testing.T) {
	t.Parallel()
	st := consoleauth.NewStore(consoleauth.WithClock(newClock().now))

	s := aSession()
	s.Restricted = true
	s.AuthenticatedAt = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	id, err := st.Issue(s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.Lookup(id)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Restricted {
		t.Error("Issue dropped Restricted")
	}
	if !got.AuthenticatedAt.IsZero() {
		t.Error("Issue accepted a caller-supplied step-up stamp")
	}
}

func TestStore_CountOthers(t *testing.T) {
	t.Parallel()
	c := newClock()
	st := consoleauth.NewStore(consoleauth.WithClock(c.now), consoleauth.WithLifetimes(time.Hour, 5*time.Minute))

	a1, _ := st.Issue(sessionOf("acct-a"))
	_, _ = st.Issue(sessionOf("acct-a"))
	_, _ = st.Issue(sessionOf("acct-b"))
	if got := st.CountOthers("acct-a", a1); got != 1 {
		t.Errorf("CountOthers = %d, want 1 (the other session of A; B's is not A's)", got)
	}

	// An expired session is not live and is not counted.
	c.advance(10 * time.Minute)
	if got := st.CountOthers("acct-a", a1); got != 0 {
		t.Errorf("CountOthers over expired sessions = %d, want 0", got)
	}
}

func TestStore_CompletePasswordChange(t *testing.T) {
	t.Parallel()
	c := newClock()
	st := consoleauth.NewStore(consoleauth.WithClock(c.now))

	restricted := aSession()
	restricted.Restricted = true
	mine, _ := st.Issue(restricted)
	other, _ := st.Issue(sessionOf("acct-1"))
	bystander, _ := st.Issue(sessionOf("acct-2"))

	c.advance(time.Minute)
	newID, ended, err := st.CompletePasswordChange(mine)
	if err != nil {
		t.Fatalf("CompletePasswordChange: %v", err)
	}
	if ended != 1 {
		t.Errorf("ended = %d, want 1", ended)
	}
	if _, err := st.Lookup(mine); !errors.Is(err, consoleauth.ErrNoSession) {
		t.Errorf("the old identifier still resolves: %v", err)
	}
	if _, err := st.Lookup(other); !errors.Is(err, consoleauth.ErrNoSession) {
		t.Errorf("another session of the Account survived: %v", err)
	}
	if _, err := st.Lookup(bystander); err != nil {
		t.Errorf("another Account's session was ended: %v", err)
	}
	got, err := st.Lookup(newID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Restricted || !got.AuthenticatedAt.Equal(c.now()) {
		t.Errorf("the rotated session is %+v, want unrestricted and stamped now", got)
	}

	// A gone session changes and ends nothing.
	if _, ended, err := st.CompletePasswordChange(mine); !errors.Is(err, consoleauth.ErrNoSession) || ended != 0 {
		t.Errorf("CompletePasswordChange on a dead id = %d, %v; want 0, ErrNoSession", ended, err)
	}
	if _, err := st.Lookup(bystander); err != nil {
		t.Errorf("a failed change ended a bystander: %v", err)
	}
}
