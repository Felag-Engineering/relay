package capability

import (
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

// -----------------------------------------------------------------------
// Fakes for accountadmin.go's collaborators.
// -----------------------------------------------------------------------

// permissiveControlAuthorizer is an Authorizer whose dispatch half
// (Authorize) always allows — unused by these tests — and whose
// administrative half (AuthorizeControl) records every ControlAction it was
// asked about and returns err (nil by default, meaning "allow").
type permissiveControlAuthorizer struct {
	calls []ControlAction
	err   error
}

func (f *permissiveControlAuthorizer) Authorize(context.Context, Principal, jobs.Action, Selector) error {
	return nil
}

func (f *permissiveControlAuthorizer) AuthorizeControl(_ context.Context, _ Principal, act ControlAction) error {
	f.calls = append(f.calls, act)
	return f.err
}

// fakeAccountStore is an AccountStore fake recording every call.
type fakeAccountStore struct {
	accountsByID  map[string]accounts.Account
	listOut       []accounts.Account
	listErr       error
	getErr        error
	createOut     accounts.Account
	createErr     error
	setRoleErr    error
	setEnabledErr error

	createCalls  []accounts.Account
	setRoleCalls []struct {
		id   string
		role accounts.Role
	}
	setEnabledCalls []struct {
		id      string
		enabled bool
	}
}

func (f *fakeAccountStore) Create(_ context.Context, a accounts.Account) (accounts.Account, error) {
	f.createCalls = append(f.createCalls, a)
	if f.createErr != nil {
		return accounts.Account{}, f.createErr
	}
	return f.createOut, nil
}

func (f *fakeAccountStore) Get(_ context.Context, id string) (accounts.Account, error) {
	if f.getErr != nil {
		return accounts.Account{}, f.getErr
	}
	if a, ok := f.accountsByID[id]; ok {
		return a, nil
	}
	return accounts.Account{}, accounts.ErrNotFound
}

func (f *fakeAccountStore) List(context.Context) ([]accounts.Account, error) {
	return f.listOut, f.listErr
}

func (f *fakeAccountStore) SetRole(_ context.Context, id string, role accounts.Role) error {
	f.setRoleCalls = append(f.setRoleCalls, struct {
		id   string
		role accounts.Role
	}{id, role})
	return f.setRoleErr
}

func (f *fakeAccountStore) SetEnabled(_ context.Context, id string, enabled bool) error {
	f.setEnabledCalls = append(f.setEnabledCalls, struct {
		id      string
		enabled bool
	}{id, enabled})
	return f.setEnabledErr
}

// fakeAPITokenStore is an APITokenStore fake recording every call.
type fakeAPITokenStore struct {
	mintOut       accounts.APIToken
	mintPlaintext accounts.Plaintext
	mintErr       error
	revokeErr     error
	listOut       []accounts.APIToken
	listErr       error

	mintCalls []struct {
		accountID, name string
		ttl             time.Duration
	}
	revokeCalls []string
}

func (f *fakeAPITokenStore) Mint(_ context.Context, accountID, name string, ttl time.Duration) (accounts.APIToken, accounts.Plaintext, error) {
	f.mintCalls = append(f.mintCalls, struct {
		accountID, name string
		ttl             time.Duration
	}{accountID, name, ttl})
	if f.mintErr != nil {
		return accounts.APIToken{}, accounts.Plaintext{}, f.mintErr
	}
	return f.mintOut, f.mintPlaintext, nil
}

func (f *fakeAPITokenStore) Revoke(_ context.Context, id string) error {
	f.revokeCalls = append(f.revokeCalls, id)
	return f.revokeErr
}

func (f *fakeAPITokenStore) List(context.Context, string) ([]accounts.APIToken, error) {
	return f.listOut, f.listErr
}

// newAccountAdminFixture builds a Service with a permissive authorizer, a
// spyAuditSink, and the given fakes wired via WithAccountAdmin.
func newAccountAdminFixture(t *testing.T, authz Authorizer, accountStore AccountStore, tokenStore APITokenStore) (*Service, *spyAuditSink) {
	t.Helper()
	audit := &spyAuditSink{}
	svc := New(registry.NewInMemory(),
		WithAuthorizer(authz),
		WithAuditSink(audit),
		WithAccountAdmin(accountStore, tokenStore),
	)
	return svc, audit
}

// -----------------------------------------------------------------------
// New's fail-open guard for WithAccountAdmin (security review finding 1):
// every sibling guard (TestWithExecutionRefusesDefaultSeams,
// TestWithExecutionRefusesWithoutFreeze, TestWithQueriesRefusesNoopAuditSink)
// has a panic test; this is WithAccountAdmin's.
// -----------------------------------------------------------------------

// TestNewRefusesAccountAdminWithoutARealAuthorizer: a Service built with
// WithAccountAdmin but no WithAuthorizer must panic at construction — an
// allowAllAuthorizer paired with a real account store would answer
// account_role/account_enable/api_token_mint for every role, the identity
// surface's own fail-open.
func TestNewRefusesAccountAdminWithoutARealAuthorizer(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New(reg, WithAccountAdmin(...)) without a real Authorizer should panic")
		}
	}()
	New(registry.NewInMemory(),
		WithAuditSink(&spyAuditSink{}),
		WithAccountAdmin(&fakeAccountStore{}, &fakeAPITokenStore{}),
	)
}

// TestNewRefusesAccountAdminWithoutARealAuditSink: a Service built with
// WithAccountAdmin but no WithAuditSink must panic at construction — every
// Account/API-Token administration act would go unrecorded, exactly the
// "unauditable act succeeded" state ADR-0025 forbids for the read lane.
func TestNewRefusesAccountAdminWithoutARealAuditSink(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("New(reg, WithAccountAdmin(...)) without a real AuditSink should panic")
		}
	}()
	New(registry.NewInMemory(),
		WithAuthorizer(&permissiveControlAuthorizer{}),
		WithAccountAdmin(&fakeAccountStore{}, &fakeAPITokenStore{}),
	)
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

func TestAccountAdmin_SelfRoleChangeIsRefused(t *testing.T) {
	authz := &permissiveControlAuthorizer{}
	accountStore := &fakeAccountStore{}
	svc, audit := newAccountAdminFixture(t, authz, accountStore, &fakeAPITokenStore{})

	p := Principal{AccountID: "acct-1", Account: "me", Role: "admin", Kind: PrincipalKindHuman}
	err := svc.SetAccountRole(context.Background(), p, "acct-1", accounts.RoleViewer)
	if !errors.Is(err, ErrSelfTargeted) {
		t.Fatalf("SetAccountRole(self) = %v, want ErrSelfTargeted", err)
	}
	if len(accountStore.setRoleCalls) != 0 {
		t.Errorf("SetRole was called %d times, want 0 — a refused act must never reach the store", len(accountStore.setRoleCalls))
	}
	if len(audit.entries) != 1 || audit.entries[0].Kind != AuditKindRefusal {
		t.Errorf("audit entries = %+v, want exactly one AuditKindRefusal", audit.entries)
	}
}

func TestAccountAdmin_SelfDisableIsRefused(t *testing.T) {
	authz := &permissiveControlAuthorizer{}
	accountStore := &fakeAccountStore{}
	svc, audit := newAccountAdminFixture(t, authz, accountStore, &fakeAPITokenStore{})

	p := Principal{AccountID: "acct-1", Account: "me", Role: "admin", Kind: PrincipalKindHuman}
	err := svc.SetAccountEnabled(context.Background(), p, "acct-1", false)
	if !errors.Is(err, ErrSelfTargeted) {
		t.Fatalf("SetAccountEnabled(self, false) = %v, want ErrSelfTargeted", err)
	}
	if len(accountStore.setEnabledCalls) != 0 {
		t.Errorf("SetEnabled was called %d times, want 0", len(accountStore.setEnabledCalls))
	}
	if len(audit.entries) != 1 || audit.entries[0].Kind != AuditKindRefusal {
		t.Errorf("audit entries = %+v, want exactly one AuditKindRefusal", audit.entries)
	}

	// Enabling yourself is never a lockout risk and must not be refused.
	if err := svc.SetAccountEnabled(context.Background(), p, "acct-1", true); err != nil {
		t.Errorf("SetAccountEnabled(self, true) = %v, want nil — enabling yourself is never self-targeting-refused", err)
	}
	if len(accountStore.setEnabledCalls) != 1 {
		t.Errorf("SetEnabled(self, true) did not reach the store")
	}
}

func TestAccountAdmin_EveryActRecordsItsPrincipal(t *testing.T) {
	accountStore := &fakeAccountStore{
		createOut: accounts.Account{ID: "acct-new", Name: "new-guy", Role: accounts.RoleViewer},
		listOut:   []accounts.Account{{ID: "acct-1"}},
		accountsByID: map[string]accounts.Account{
			"acct-1": {ID: "acct-1", Name: "one"},
		},
	}
	tokenStore := &fakeAPITokenStore{
		mintOut: accounts.APIToken{ID: "tok-1", AccountID: "acct-1"},
	}
	authz := &permissiveControlAuthorizer{}
	svc, audit := newAccountAdminFixture(t, authz, accountStore, tokenStore)

	p := Principal{AccountID: "acct-admin", Account: "admin", Role: "admin", Kind: PrincipalKindHuman}
	ctx := context.Background()

	if _, err := svc.CreateAccount(ctx, p, accounts.Account{Name: "new-guy"}); err != nil {
		t.Fatalf("CreateAccount: %v", err)
	}
	if err := svc.SetAccountRole(ctx, p, "acct-1", accounts.RoleOperator); err != nil {
		t.Fatalf("SetAccountRole: %v", err)
	}
	if err := svc.SetAccountEnabled(ctx, p, "acct-1", false); err != nil {
		t.Fatalf("SetAccountEnabled(false): %v", err)
	}
	if err := svc.SetAccountEnabled(ctx, p, "acct-1", true); err != nil {
		t.Fatalf("SetAccountEnabled(true): %v", err)
	}
	if _, _, err := svc.MintAPIToken(ctx, p, "acct-1", "ci", time.Hour); err != nil {
		t.Fatalf("MintAPIToken: %v", err)
	}
	if err := svc.RevokeAPIToken(ctx, p, "tok-1"); err != nil {
		t.Fatalf("RevokeAPIToken: %v", err)
	}

	wantKinds := []AccountAdminKind{
		AccountAdminCreate, AccountAdminRole, AccountAdminDisable, AccountAdminEnable,
		AccountAdminTokenMint, AccountAdminTokenRevoke,
	}
	if len(audit.accountAdminCalls) != len(wantKinds) {
		t.Fatalf("recorded %d account-admin events, want %d: %+v", len(audit.accountAdminCalls), len(wantKinds), audit.accountAdminCalls)
	}
	for i, call := range audit.accountAdminCalls {
		if call.Principal != p {
			t.Errorf("event %d: Principal = %+v, want %+v", i, call.Principal, p)
		}
		if call.Event.Kind != wantKinds[i] {
			t.Errorf("event %d: Kind = %v, want %v", i, call.Event.Kind, wantKinds[i])
		}
	}

	// Reads are authorized but record nothing — see accountadmin.go's header.
	if _, err := svc.Accounts(ctx, p); err != nil {
		t.Fatalf("Accounts: %v", err)
	}
	if _, err := svc.Account(ctx, p, "acct-1"); err != nil {
		t.Fatalf("Account: %v", err)
	}
	if _, err := svc.APITokens(ctx, p, "acct-1"); err != nil {
		t.Fatalf("APITokens: %v", err)
	}
	if len(audit.accountAdminCalls) != len(wantKinds) {
		t.Errorf("a successful read recorded an account-admin event: %+v", audit.accountAdminCalls)
	}
}

func TestAccountAdmin_MintAuditRowCarriesNoSecret(t *testing.T) {
	const secret = "glp_deadbeef.super-secret-value"
	tokenStore := &fakeAPITokenStore{
		mintOut:       accounts.APIToken{ID: "tok-1", AccountID: "acct-1"},
		mintPlaintext: accounts.NewPlaintext(secret),
	}
	authz := &permissiveControlAuthorizer{}
	svc, audit := newAccountAdminFixture(t, authz, &fakeAccountStore{}, tokenStore)

	p := Principal{AccountID: "acct-admin", Account: "admin", Role: "admin"}
	tok, plaintext, err := svc.MintAPIToken(context.Background(), p, "acct-1", "ci", time.Hour)
	if err != nil {
		t.Fatalf("MintAPIToken: %v", err)
	}
	if plaintext.Reveal() != secret {
		t.Fatalf("MintAPIToken returned plaintext %q, want the minted secret untouched", plaintext.Reveal())
	}
	if tok.ID != "tok-1" {
		t.Fatalf("MintAPIToken returned token %+v, want the minted token", tok)
	}

	if len(audit.accountAdminCalls) != 1 {
		t.Fatalf("recorded %d events, want 1", len(audit.accountAdminCalls))
	}
	event := audit.accountAdminCalls[0].Event
	if event.TokenID != "tok-1" {
		t.Errorf("event.TokenID = %q, want %q", event.TokenID, "tok-1")
	}

	// No field on the event may carry the secret, whatever its name — walk
	// every string field by reflection rather than trusting the struct
	// definition alone, since a future field addition is exactly what this
	// guards against.
	v := reflect.ValueOf(event)
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if f.Kind() != reflect.String {
			continue
		}
		if strings.Contains(f.String(), secret) {
			t.Errorf("AccountAdminEvent field %q contains the minted secret", v.Type().Field(i).Name)
		}
	}
}

func TestAccountAdmin_BelowAdminIsRefusedAndAudited(t *testing.T) {
	denyErr := errors.New("authz: unauthorized: needs admin")
	authz := &permissiveControlAuthorizer{err: denyErr}
	accountStore := &fakeAccountStore{listOut: []accounts.Account{{ID: "acct-1"}}}
	svc, audit := newAccountAdminFixture(t, authz, accountStore, &fakeAPITokenStore{})

	p := Principal{AccountID: "acct-viewer", Account: "viewer", Role: "viewer"}

	if _, err := svc.Accounts(context.Background(), p); !errors.Is(err, denyErr) {
		t.Errorf("Accounts() below floor = %v, want the denial", err)
	}
	if _, err := svc.CreateAccount(context.Background(), p, accounts.Account{Name: "x"}); !errors.Is(err, denyErr) {
		t.Errorf("CreateAccount() below floor = %v, want the denial", err)
	}
	if len(accountStore.createCalls) != 0 {
		t.Errorf("CreateAccount reached the store despite the denial")
	}

	// Every refusal above is recorded — the acceptance criterion is that
	// refusals are audited, not silent.
	refusals := 0
	for _, e := range audit.entries {
		if e.Kind == AuditKindRefusal {
			refusals++
		}
	}
	if refusals != 2 {
		t.Errorf("recorded %d refusals, want 2", refusals)
	}
	if len(audit.accountAdminCalls) != 0 {
		t.Errorf("a refused call recorded an account-admin event: %+v", audit.accountAdminCalls)
	}
}

// TestAccountAdmin_LastAdminRefusalSurvivesTheRealStore drives a REAL
// store.Open database (suggestion 6, mitigation (a)): store/** and
// accounts/** are not on security-surface.txt, so a later store-only PR
// could weaken the SQL guard unreviewed. This test lives in capability —
// which IS on the surface — so it fails CI if that guard is ever removed,
// from inside a package a reviewer is already required to look at.
func TestAccountAdmin_LastAdminRefusalSurvivesTheRealStore(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck
	ctx := context.Background()

	admin, err := st.Accounts().Create(ctx, accounts.Account{
		Name: "sole-admin", Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
	})
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	tokenSvc := accounts.NewTokenService(st.APITokens(), st.Accounts(), nil)

	authz := &permissiveControlAuthorizer{}
	svc, _ := newAccountAdminFixture(t, authz, st.Accounts(), tokenSvc)

	// A different acting Principal, so the self-target rule does not
	// interfere with what this test is actually proving.
	p := Principal{AccountID: "acct-other-caller", Account: "caller", Role: "admin"}

	if err := svc.SetAccountRole(ctx, p, admin.ID, accounts.RoleViewer); !errors.Is(err, accounts.ErrLastAdmin) {
		t.Errorf("SetAccountRole(the only enabled admin, viewer) = %v, want accounts.ErrLastAdmin", err)
	}
	if err := svc.SetAccountEnabled(ctx, p, admin.ID, false); !errors.Is(err, accounts.ErrLastAdmin) {
		t.Errorf("SetAccountEnabled(the only enabled admin, false) = %v, want accounts.ErrLastAdmin", err)
	}

	got, err := st.Accounts().Get(ctx, admin.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Role != accounts.RoleAdmin || !got.Enabled {
		t.Errorf("admin = %+v after refused calls, want an untouched enabled admin", got)
	}
}

func TestSelfTargeted_RequiresBothSidesNonEmptyAndEqual(t *testing.T) {
	for _, tc := range []struct {
		name      string
		principal string
		id        string
		want      bool
	}{
		{"same account", "acct-1", "acct-1", true},
		{"another account", "acct-1", "acct-2", false},
		{"both empty", "", "", false},
		{"principal without an account", "", "acct-1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SelfTargeted(Principal{AccountID: tc.principal}, tc.id); got != tc.want {
				t.Errorf("SelfTargeted(%q, %q) = %v, want %v", tc.principal, tc.id, got, tc.want)
			}
		})
	}
}
