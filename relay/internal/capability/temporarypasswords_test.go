package capability

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

var tpAdmin = Principal{AccountID: "acct-1", Account: "ada", Role: "admin", Kind: PrincipalKindHuman, AuthMethod: AuthMethodConsoleSession}

// fakeTempSink is an AuditSink that is also a TemporaryPasswordRecorder. It
// keeps every event so a test can assert what the recorder was handed, and
// can fail.
type fakeTempSink struct {
	*spyAuditSink
	creates   []TemporaryPasswordEvent
	issues    []TemporaryPasswordEvent
	created   accounts.Account
	recordErr error
}

func (f *fakeTempSink) RecordAccountCreateWithTemporaryPassword(_ context.Context, e TemporaryPasswordEvent, a accounts.Account) (accounts.Account, error) {
	if f.recordErr != nil {
		return accounts.Account{}, f.recordErr
	}
	f.creates = append(f.creates, e)
	a.ID = "acct-new"
	f.created = a
	return a, nil
}

func (f *fakeTempSink) RecordTemporaryPasswordIssue(_ context.Context, e TemporaryPasswordEvent) error {
	if f.recordErr != nil {
		return f.recordErr
	}
	f.issues = append(f.issues, e)
	return nil
}

type fakeStatusSource struct {
	status accounts.PasswordStatus
	err    error
}

func (f fakeStatusSource) Status(context.Context, string) (accounts.PasswordStatus, error) {
	return f.status, f.err
}

// denyOne is an Authorizer that refuses exactly one ControlAction and records
// every one it was asked about.
type denyOne struct {
	spyAuthorizer
	deny ControlAction
	err  error
}

func (d *denyOne) AuthorizeControl(ctx context.Context, p Principal, act ControlAction) error {
	_ = d.spyAuthorizer.AuthorizeControl(ctx, p, act)
	if act == d.deny {
		return d.err
	}
	return nil
}

type tempFixture struct {
	t     *TemporaryPasswords
	sink  *fakeTempSink
	authz *spyAuthorizer
	now   time.Time
}

func newTempFixture(t *testing.T) *tempFixture {
	t.Helper()
	authz := &spyAuthorizer{}
	return newTempFixtureWith(t, authz, authz)
}

// newTempFixtureWith builds over authorizer; spy is the one whose calls the
// fixture reports.
func newTempFixtureWith(t *testing.T, authorizer Authorizer, spy *spyAuthorizer) *tempFixture {
	t.Helper()
	sink := &fakeTempSink{spyAuditSink: &spyAuditSink{}}
	control := newControl(NewRecorder(sink, nil, nil), authorizer, noopFreezeStore{})
	tp := NewTemporaryPasswords(control, fakeStatusSource{})
	tp.EndSessionsWith(&spySessionEnder{})
	now := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	tp.now = func() time.Time { return now }
	return &tempFixture{t: tp, sink: sink, authz: spy, now: now}
}

func newHuman(name string) accounts.Account {
	return accounts.Account{Name: name, Kind: accounts.KindHuman, Role: accounts.RoleViewer, Enabled: true}
}

func TestTemporaryPasswords_CreateHumanAccountAuthorizesBothActsAndRecordsOnlyAHash(t *testing.T) {
	f := newTempFixture(t)
	ctx := WithAssertions(context.Background(), Assertions{OnBehalfOf: "bob"})

	created, tp, err := f.t.CreateHumanAccount(ctx, tpAdmin, newHuman("newbie"))
	if err != nil {
		t.Fatalf("CreateHumanAccount: %v", err)
	}
	if created.ID != "acct-new" {
		t.Errorf("created = %+v", created)
	}
	if want := []ControlAction{ControlAccountCreate, ControlTemporaryPasswordIssue}; !reflect.DeepEqual(f.authz.controlCalls, want) {
		t.Errorf("authorized %v, want %v", f.authz.controlCalls, want)
	}
	if want := f.now.Add(accounts.TemporaryPasswordLifetime); !tp.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v (72 hours on the capability's clock)", tp.ExpiresAt, want)
	}

	// The plaintext verifies against exactly the hash the recorder was handed.
	if len(f.sink.creates) != 1 {
		t.Fatalf("%d create events, want 1", len(f.sink.creates))
	}
	e := f.sink.creates[0]
	if !e.Hash.Verify(tp.Password) {
		t.Error("the returned temporary password does not verify against the recorded hash")
	}
	if !e.ExpiresAt.Equal(tp.ExpiresAt) || e.Principal.AccountID != tpAdmin.AccountID || e.Asserted.OnBehalfOf != "bob" {
		t.Errorf("event = %+v", e)
	}
	// The event has no field a plaintext could occupy.
	if strings.Contains(fmt.Sprintf("%+v", e), tp.Password.Reveal()) {
		t.Error("the recorded event carries the temporary password")
	}
	if len(f.sink.entries) != 0 {
		t.Errorf("a successful issue wrote %d refusal entries", len(f.sink.entries))
	}
}

func TestTemporaryPasswords_RefusesBelowAdminAndMachinePrincipals(t *testing.T) {
	for _, tc := range []struct {
		name string
		deny ControlAction
	}{
		{"account create floor", ControlAccountCreate},
		{"temporary password issue floor", ControlTemporaryPasswordIssue},
	} {
		t.Run("create: "+tc.name, func(t *testing.T) {
			refusal := errors.New("denied by the authorizer")
			deny := &denyOne{deny: tc.deny, err: refusal}
			f := newTempFixtureWith(t, deny, &deny.spyAuthorizer)

			_, tp, err := f.t.CreateHumanAccount(context.Background(), tpAdmin, newHuman("newbie"))
			if !errors.Is(err, refusal) {
				t.Fatalf("err = %v, want the authorizer's refusal", err)
			}
			if !tp.Password.IsZero() || !tp.ExpiresAt.IsZero() {
				t.Error("a refused create returned a temporary password")
			}
			if len(f.sink.creates) != 0 {
				t.Error("a refused create reached the recorder")
			}
			if len(f.sink.entries) != 1 || f.sink.entries[0].Kind != AuditKindRefusal {
				t.Errorf("entries = %+v, want exactly one refusal", f.sink.entries)
			}
		})
	}

	t.Run("issue", func(t *testing.T) {
		f := newTempFixture(t)
		refusal := errors.New("denied by the authorizer")
		f.authz.controlErr = refusal
		tp, err := f.t.IssueTemporaryPassword(context.Background(), tpAdmin, "acct-9")
		if !errors.Is(err, refusal) || !tp.Password.IsZero() {
			t.Fatalf("IssueTemporaryPassword = %+v, %v; want the refusal and no password", tp, err)
		}
		if len(f.sink.issues) != 0 || len(f.sink.entries) != 1 {
			t.Errorf("issues = %d, entries = %d; want none and one refusal", len(f.sink.issues), len(f.sink.entries))
		}
	})

	t.Run("status", func(t *testing.T) {
		f := newTempFixture(t)
		f.authz.controlErr = errors.New("denied by the authorizer")
		if _, err := f.t.PasswordStatus(context.Background(), tpAdmin, "acct-9"); err == nil {
			t.Fatal("PasswordStatus succeeded for a refused read")
		}
		if want := []ControlAction{ControlAccountRead}; !reflect.DeepEqual(f.authz.controlCalls, want) {
			t.Errorf("authorized %v, want %v", f.authz.controlCalls, want)
		}
	})
}

func TestTemporaryPasswords_RefusesAMachineKind(t *testing.T) {
	f := newTempFixture(t)
	machine := accounts.Account{Name: "bot", Kind: accounts.KindMachine, Role: accounts.RoleViewer, Enabled: true}

	_, tp, err := f.t.CreateHumanAccount(context.Background(), tpAdmin, machine)
	if !errors.Is(err, accounts.ErrMachinePassword) {
		t.Fatalf("err = %v, want ErrMachinePassword", err)
	}
	if !tp.Password.IsZero() {
		t.Error("a machine create returned a temporary password")
	}
	if len(f.sink.creates) != 0 || len(f.sink.entries) != 0 {
		t.Error("a machine create reached the recorder or wrote a record")
	}
}

func TestTemporaryPasswords_ReturnsNoPlaintextOnRecorderError(t *testing.T) {
	f := newTempFixture(t)
	f.sink.recordErr = errors.New("audit store unavailable")

	_, tp, err := f.t.CreateHumanAccount(context.Background(), tpAdmin, newHuman("newbie"))
	if err == nil || !tp.Password.IsZero() || !tp.ExpiresAt.IsZero() {
		t.Errorf("CreateHumanAccount = %+v, %v; want an error and the zero TemporaryPassword", tp, err)
	}
	tp, err = f.t.IssueTemporaryPassword(context.Background(), tpAdmin, "acct-9")
	if err == nil || !tp.Password.IsZero() || !tp.ExpiresAt.IsZero() {
		t.Errorf("IssueTemporaryPassword = %+v, %v; want an error and the zero TemporaryPassword", tp, err)
	}
}

func TestTemporaryPasswords_IssueBubblesStoreRefusalsUnwrapped(t *testing.T) {
	for _, storeErr := range []error{accounts.ErrPasswordOwned, accounts.ErrMachinePassword, accounts.ErrNotFound} {
		f := newTempFixture(t)
		f.sink.recordErr = storeErr
		_, err := f.t.IssueTemporaryPassword(context.Background(), tpAdmin, "acct-9")
		if !errors.Is(err, storeErr) {
			t.Errorf("err = %v, want %v", err, storeErr)
		}
	}
}

func TestTemporaryPasswords_IssueRecordsTheSubjectAndAHashThatVerifies(t *testing.T) {
	f := newTempFixture(t)
	tp, err := f.t.IssueTemporaryPassword(context.Background(), tpAdmin, "acct-9")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.sink.issues) != 1 {
		t.Fatalf("%d issue events, want 1", len(f.sink.issues))
	}
	e := f.sink.issues[0]
	if e.AccountID != "acct-9" || !e.Hash.Verify(tp.Password) || e.Principal.AccountID != tpAdmin.AccountID {
		t.Errorf("event = %+v", e)
	}
	if want := []ControlAction{ControlTemporaryPasswordIssue}; !reflect.DeepEqual(f.authz.controlCalls, want) {
		t.Errorf("authorized %v, want %v", f.authz.controlCalls, want)
	}
}

func TestTemporaryPasswords_PasswordStatusRecordsNothingOnSuccess(t *testing.T) {
	f := newTempFixture(t)
	want := accounts.PasswordStatus{Own: true}
	f.t.status = fakeStatusSource{status: want}

	got, err := f.t.PasswordStatus(context.Background(), tpAdmin, "acct-9")
	if err != nil || got != want {
		t.Fatalf("PasswordStatus = %+v, %v; want %+v", got, err, want)
	}
	if len(f.sink.entries) != 0 {
		t.Errorf("a successful read wrote %d records", len(f.sink.entries))
	}
}

func TestTemporaryPasswords_UnwiredIsUnavailable(t *testing.T) {
	tp := &TemporaryPasswords{control: newControl(NewRecorder(&spyAuditSink{}, nil, nil), &spyAuthorizer{}, noopFreezeStore{}), now: time.Now}
	if _, _, err := tp.CreateHumanAccount(context.Background(), tpAdmin, newHuman("x")); !errors.Is(err, ErrTemporaryPasswordsUnavailable) {
		t.Errorf("CreateHumanAccount = %v", err)
	}
	if _, err := tp.IssueTemporaryPassword(context.Background(), tpAdmin, "a"); !errors.Is(err, ErrTemporaryPasswordsUnavailable) {
		t.Errorf("IssueTemporaryPassword = %v", err)
	}
	if _, err := tp.PasswordStatus(context.Background(), tpAdmin, "a"); !errors.Is(err, ErrTemporaryPasswordsUnavailable) {
		t.Errorf("PasswordStatus = %v", err)
	}
}

type plainTempSink struct{ *spyAuditSink }

func TestNewTemporaryPasswords_PanicsOnAnUnsafeComposition(t *testing.T) {
	real := &spyAuthorizer{}
	tempSink := &fakeTempSink{spyAuditSink: &spyAuditSink{}}
	good := func(authz Authorizer, sink AuditSink) *Control {
		return newControl(NewRecorder(sink, nil, nil), authz, noopFreezeStore{})
	}
	cases := map[string]func(){
		"nil control":    func() { NewTemporaryPasswords(nil, fakeStatusSource{}) },
		"nil status":     func() { NewTemporaryPasswords(good(real, tempSink), nil) },
		"allow-all":      func() { NewTemporaryPasswords(good(allowAllAuthorizer{}, tempSink), fakeStatusSource{}) },
		"no-op sink":     func() { NewTemporaryPasswords(good(real, noopAuditSink{}), fakeStatusSource{}) },
		"not a recorder": func() { NewTemporaryPasswords(good(real, plainTempSink{&spyAuditSink{}}), fakeStatusSource{}) },
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("did not panic")
				}
			}()
			f()
		})
	}
}
