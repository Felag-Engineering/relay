package capability

import (
	"context"
	"errors"
	"testing"
)

type spySessionEnder struct{ ended []string }

func (s *spySessionEnder) EndAllFor(accountID string) int {
	s.ended = append(s.ended, accountID)
	return 1
}

func TestTemporaryPasswords_AReissueEndsTheTargetsSessionsOnlyOnSuccess(t *testing.T) {
	f := newTempFixture(t)
	spy := &spySessionEnder{}
	f.t.EndSessionsWith(spy)

	if _, err := f.t.IssueTemporaryPassword(context.Background(), tpAdmin, "acct-9"); err != nil {
		t.Fatal(err)
	}
	if len(spy.ended) != 1 || spy.ended[0] != "acct-9" {
		t.Errorf("sessions ended for %v, want exactly acct-9", spy.ended)
	}

	f.sink.recordErr = errors.New("audit store unavailable")
	if _, err := f.t.IssueTemporaryPassword(context.Background(), tpAdmin, "acct-8"); err == nil {
		t.Fatal("a failed record issued anyway")
	}
	if len(spy.ended) != 1 {
		t.Errorf("a refused re-issue ended sessions: %v", spy.ended)
	}
}

func TestTemporaryPasswords_AReissueWithoutASessionEnderIsRefusedAndWritesNothing(t *testing.T) {
	f := newTempFixture(t)
	f.t.sessions = nil

	_, err := f.t.IssueTemporaryPassword(context.Background(), tpAdmin, "acct-9")
	if !errors.Is(err, ErrTemporaryPasswordsUnavailable) {
		t.Fatalf("IssueTemporaryPassword = %v, want ErrTemporaryPasswordsUnavailable", err)
	}
	if len(f.sink.entries) != 0 {
		t.Errorf("a refused re-issue wrote %d records", len(f.sink.entries))
	}
}
