package consoleauth_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
)

func TestStore_IssueAtRefusesOnceTheAccountsSessionsWereEnded(t *testing.T) {
	t.Parallel()
	ends := map[string]func(t *testing.T, st *consoleauth.Store, kept consoleauth.SessionID){
		"a completed password change": func(t *testing.T, st *consoleauth.Store, kept consoleauth.SessionID) {
			if _, _, err := st.CompletePasswordChange(kept); err != nil {
				t.Fatal(err)
			}
		},
		"EndAllFor": func(_ *testing.T, st *consoleauth.Store, _ consoleauth.SessionID) { st.EndAllFor("acct-a") },
	}
	for name, end := range ends {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			st := consoleauth.NewStore(consoleauth.WithClock(newClock().now))
			kept, _ := st.Issue(sessionOf("acct-a"))

			epoch := st.CredentialEpoch("acct-a")
			if _, err := st.IssueAt(sessionOf("acct-a"), epoch); err != nil {
				t.Fatalf("IssueAt at the current epoch: %v", err)
			}
			end(t, st, kept)

			before := st.Len()
			if _, err := st.IssueAt(sessionOf("acct-a"), epoch); !errors.Is(err, consoleauth.ErrCredentialChanged) {
				t.Fatalf("IssueAt with a stale epoch = %v, want ErrCredentialChanged", err)
			}
			if st.Len() != before {
				t.Error("a refused IssueAt still stored a session")
			}
			if _, err := st.IssueAt(sessionOf("acct-b"), st.CredentialEpoch("acct-b")); err != nil {
				t.Errorf("another Account's sign-in was refused: %v", err)
			}
		})
	}
}

// afterRead runs hook once, right after the first stored-password read for
// accountID returns, so a test can complete a password change between a
// sign-in's credential check and its session issue.
type afterRead struct {
	accounts.PasswordRepository
	accountID string
	hook      func()
	once      sync.Once
}

func (r *afterRead) GetPassword(ctx context.Context, accountID string) (accounts.StoredPassword, error) {
	stored, err := r.PasswordRepository.GetPassword(ctx, accountID)
	if accountID == r.accountID {
		r.once.Do(r.hook)
	}
	return stored, err
}

func TestLogin_ASignInRacingAPasswordChangeIsRefusedAndLeavesNoSession(t *testing.T) {
	t.Parallel()
	f := newPWFixture(t, false)
	victim, _ := f.login(t, "mike", testPassword)

	// The attacker knows the old password. Their sign-in reads the old hash,
	// then the victim's change completes, then their session would be issued.
	racing := &afterRead{PasswordRepository: f.st.Passwords(), accountID: f.mike.ID}
	var changed consoleauth.SessionID
	racing.hook = func() {
		id, err := f.change(victim, testPassword, ownPassword, ownPassword)
		if err != nil {
			t.Errorf("the racing change: %v", err)
		}
		changed = id
	}
	sink := auditsink.New(f.st.Audit(), auditsink.WithClock(f.clk.now))
	attacker := consoleauth.NewService(f.st.Accounts(), racing, f.sessions,
		consoleauth.NewThrottle(consoleauth.WithThrottleClock(f.clk.now)), sink)

	if _, _, err := attacker.Login(context.Background(), attempt("mike", testPassword)); !errors.Is(err, consoleauth.ErrBadCredentials) {
		t.Fatalf("a sign-in that raced the change = %v, want the one ErrBadCredentials", err)
	}
	if got := f.sessions.Len(); got != 1 {
		t.Errorf("%d live sessions, want only the changing session", got)
	}
	if _, err := f.sessions.Lookup(changed); err != nil {
		t.Errorf("the changing session was lost: %v", err)
	}
	if got := countOf(f.kinds(t), "login_failed"); got != 1 {
		t.Errorf("%d login_failed records, want the racing sign-in's 1", got)
	}
}
