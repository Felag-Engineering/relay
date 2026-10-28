package auditsink

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

var tempAdmin = capability.Principal{
	AccountID: "acct-1", Account: "ada", Role: "admin", Kind: capability.PrincipalKindHuman,
	AuthMethod: capability.AuthMethodConsoleSession, Source: "10.0.0.9",
}

func realTemporaryPasswords(t *testing.T, st *store.Store, sink *Sink) *capability.TemporaryPasswords {
	t.Helper()
	ctl := capability.NewControl(capability.NewRecorder(sink, nil, nil), authz.NewRoleGate(), neverFrozen{})
	tp := capability.NewTemporaryPasswords(ctl, st.PasswordStatuses())
	tp.EndSessionsWith(noSessions{})
	return tp
}

// noSessions stands in for the Console session store: these tests hold no sessions.
type noSessions struct{}

func (noSessions) EndAllFor(string) int { return 0 }

func recordsOfKind(t *testing.T, repo audit.Repository, kinds ...string) []audit.Record {
	t.Helper()
	all, err := repo.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Record
	for _, r := range all {
		for _, k := range kinds {
			if r.Kind == k {
				out = append(out, r)
			}
		}
	}
	return out
}

func TestSink_TemporaryPasswordRecords(t *testing.T) {
	st, repo, _ := openSinkStore(t)
	sink := New(repo)
	tp := realTemporaryPasswords(t, st, sink)
	ctx := context.Background()

	created, issued, err := tp.CreateHumanAccount(ctx, tempAdmin, accounts.Account{
		Name: "newbie", Kind: accounts.KindHuman, Role: accounts.RoleViewer, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateHumanAccount: %v", err)
	}
	reissued, err := tp.IssueTemporaryPassword(ctx, tempAdmin, created.ID)
	if err != nil {
		t.Fatalf("IssueTemporaryPassword: %v", err)
	}

	creates := recordsOfKind(t, repo, audit.KindAccountCreate)
	issues := recordsOfKind(t, repo, audit.KindPasswordTemporarySet)
	if len(creates) != 1 || len(issues) != 2 {
		t.Fatalf("trail has %d account_create and %d password_temporary_set, want 1 and 2", len(creates), len(issues))
	}

	// account_create is byte-identical to the Control API's.
	wantCreate := accountAdminReason(capability.AccountAdminEvent{
		Kind: capability.AccountAdminCreate, AccountID: created.ID, AccountName: "newbie",
		AccountKind: "human", Role: "viewer",
	})
	if creates[0].Reason != wantCreate {
		t.Errorf("account_create Reason = %q, want %q", creates[0].Reason, wantCreate)
	}
	wantIssue := fmt.Sprintf("account_id=%s name=newbie expires_at=%s", created.ID, issued.ExpiresAt.UTC().Format(time.RFC3339))
	if issues[0].Reason != wantIssue {
		t.Errorf("create-time password_temporary_set Reason = %q, want %q", issues[0].Reason, wantIssue)
	}
	wantReissue := fmt.Sprintf("account_id=%s expires_at=%s", created.ID, reissued.ExpiresAt.UTC().Format(time.RFC3339))
	if issues[1].Reason != wantReissue {
		t.Errorf("re-issue password_temporary_set Reason = %q, want %q", issues[1].Reason, wantReissue)
	}

	for _, r := range append(creates, issues...) {
		if v := r.Attribution.Verified; v.AccountID != tempAdmin.AccountID || v.AccountName != "ada" || v.Source != "10.0.0.9" {
			t.Errorf("%s verified lane = %+v, want the admin and the verified source", r.Kind, v)
		}
		if r.Principal != "ada:admin" {
			t.Errorf("%s Principal = %q, want ada:admin", r.Kind, r.Principal)
		}
		if !strings.HasPrefix(r.Reason, "account_id="+created.ID) && r.Kind == audit.KindPasswordTemporarySet {
			t.Errorf("%s Reason %q does not open with account_id=", r.Kind, r.Reason)
		}
		// Never a password or a hash, in any field of any record.
		for _, secret := range []string{issued.Password.Reveal(), reissued.Password.Reveal(), "argon2id"} {
			if strings.Contains(fmt.Sprintf("%+v", r), secret) {
				t.Errorf("%s record carries %q", r.Kind, secret)
			}
		}
	}

	// The create's two records and the Account were one transaction: the
	// stored password is the first issue's until the re-issue replaced it.
	got, err := st.Passwords().GetPassword(ctx, created.ID)
	if err != nil || !got.Temporary() || !got.Hash.Verify(reissued.Password) || got.Hash.Verify(issued.Password) {
		t.Errorf("stored password: temporary=%v err=%v; want only the re-issued one to verify", got.Temporary(), err)
	}
}

func TestSink_TemporaryPasswordRefusesAnUnatomicRepository(t *testing.T) {
	// A Repository that offers no PasswordAppender refuses before an id is
	// minted: nothing is written, and the capability layer's sentinel comes back.
	sink := New(plainRepo{})
	_, err := sink.RecordAccountCreateWithTemporaryPassword(context.Background(), capability.TemporaryPasswordEvent{Principal: tempAdmin}, accounts.Account{})
	if !errors.Is(err, capability.ErrTemporaryPasswordsUnavailable) {
		t.Errorf("create = %v, want ErrTemporaryPasswordsUnavailable", err)
	}
	if err := sink.RecordTemporaryPasswordIssue(context.Background(), capability.TemporaryPasswordEvent{Principal: tempAdmin}); !errors.Is(err, capability.ErrTemporaryPasswordsUnavailable) {
		t.Errorf("issue = %v, want ErrTemporaryPasswordsUnavailable", err)
	}
	if err := sink.RecordPasswordChange(context.Background(), consoleauth.PasswordChangeEvent{}); !errors.Is(err, consoleauth.ErrPasswordChangeUnavailable) {
		t.Errorf("change = %v, want ErrPasswordChangeUnavailable", err)
	}
}

func TestSink_PasswordChangeRecord(t *testing.T) {
	st, repo, _ := openSinkStore(t)
	sink := New(repo)
	ctx := context.Background()

	acct, err := st.Accounts().Create(ctx, accounts.Account{Name: "mike", Kind: accounts.KindHuman, Role: accounts.RoleOperator, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	old, _ := accounts.HashPassword(accounts.NewPassword("the old password!!"))
	if err := st.Passwords().SetPassword(ctx, acct.ID, old); err != nil {
		t.Fatal(err)
	}
	next, _ := accounts.HashPassword(accounts.NewPassword("the new password!!"))

	if err := sink.RecordPasswordChange(ctx, consoleauth.PasswordChangeEvent{
		AccountID: acct.ID, Account: "mike", Role: "operator", Method: consoleauth.MethodPassword,
		Source: "198.51.100.7", Expect: old, New: next, Forced: true, SessionsEnded: 3,
	}); err != nil {
		t.Fatalf("RecordPasswordChange: %v", err)
	}

	recs := recordsOfKind(t, repo, audit.KindPasswordChange)
	if len(recs) != 1 {
		t.Fatalf("%d password_change records, want 1", len(recs))
	}
	r := recs[0]
	if want := "account_id=" + acct.ID + " forced=true other_sessions_ended=3"; r.Reason != want {
		t.Errorf("Reason = %q, want %q", r.Reason, want)
	}
	if r.Principal != "mike:operator" {
		t.Errorf("Principal = %q, want mike:operator", r.Principal)
	}
	if v := r.Attribution.Verified; v.AccountID != acct.ID || v.AccountName != "mike" || v.Role != "operator" ||
		v.Method != consoleauth.MethodPassword || v.Source != "198.51.100.7" {
		t.Errorf("verified lane = %+v", v)
	}
	if fmt.Sprintf("%+v", r) != strings.ReplaceAll(fmt.Sprintf("%+v", r), "argon2id", "") {
		t.Error("the record carries a hash")
	}

	// A stale expectation is the store's refusal, passed through.
	if err := sink.RecordPasswordChange(ctx, consoleauth.PasswordChangeEvent{
		AccountID: acct.ID, Account: "mike", Role: "operator", Expect: old, New: next,
	}); !errors.Is(err, accounts.ErrPasswordChanged) {
		t.Errorf("a stale change = %v, want ErrPasswordChanged", err)
	}
	if got := recordsOfKind(t, repo, audit.KindPasswordChange); len(got) != 1 {
		t.Errorf("a refused change wrote a record: %d", len(got))
	}
}
