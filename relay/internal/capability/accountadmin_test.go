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
		id       string
		from, to accounts.Role
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

func (f *fakeAccountStore) SetRole(_ context.Context, id string, from, to accounts.Role) error {
	f.setRoleCalls = append(f.setRoleCalls, struct {
		id       string
		from, to accounts.Role
	}{id, from, to})
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

// newAccountAdminFixture builds an AccountAdmin with a permissive authorizer, a
// spyAuditSink, and the given fakes.
func newAccountAdminFixture(t *testing.T, authz Authorizer, accountStore AccountStore, tokenStore APITokenStore) (*testSvc, *spyAuditSink) {
	t.Helper()
	audit := &spyAuditSink{}
	svc := build(t, seams{reg: registry.NewInMemory(),
		authz:         authz,
		audit:         audit,
		accountsStore: accountStore, apiTokens: tokenStore,
	})
	return svc, audit
}

// -----------------------------------------------------------------------
// NewAccountAdmin's fail-open guard (security review finding 1): every
// sibling guard (TestNewExecutionRefusesDefaultSeams,
// TestNewExecutionRefusesWithoutFreeze, TestNewReadLaneRefusesNoopAuditSink)
// has a panic test; this is AccountAdmin's. Each builds its Control outside the
// recover scope, so only NewAccountAdmin can be the panic under test.
// -----------------------------------------------------------------------

// TestNewRefusesAccountAdminWithoutARealAuthorizer: an AccountAdmin over a
// Control with no real Authorizer must panic at construction — an
// allowAllAuthorizer paired with a real account store would answer
// account_role/account_enable/api_token_mint for every role, the identity
// surface's own fail-open.
func TestNewRefusesAccountAdminWithoutARealAuthorizer(t *testing.T) {
	ctl := NewControl(NewRecorder(&spyAuditSink{}, nil, nil), allowAllAuthorizer{}, &fakeFreezeStore{})
	defer func() {
		if recover() == nil {
			t.Fatal("NewAccountAdmin without a real Authorizer should panic")
		}
	}()
	NewAccountAdmin(ctl, &fakeAccountStore{}, &fakeAPITokenStore{})
}

// TestNewRefusesAccountAdminWithoutARealAuditSink: an AccountAdmin over a
// Control whose Recorder holds the no-op AuditSink must panic at construction —
// every Account/API-Token administration act would go unrecorded, exactly the
// "unauditable act succeeded" state ADR-0025 forbids for the read lane.
func TestNewRefusesAccountAdminWithoutARealAuditSink(t *testing.T) {
	ctl := NewControl(NewRecorder(noopAuditSink{}, nil, nil), &permissiveControlAuthorizer{}, &fakeFreezeStore{})
	defer func() {
		if recover() == nil {
			t.Fatal("NewAccountAdmin without a real AuditSink should panic")
		}
	}()
	NewAccountAdmin(ctl, &fakeAccountStore{}, &fakeAPITokenStore{})
}

// TestNewAccountAdmin_UsesControlsAuthorizerAndTrail: an AccountAdmin shares
// its Control's role floor and its Recorder's trail, so a refusal from the
// Control's Authorizer is audited on the Control's sink.
func TestNewAccountAdmin_UsesControlsAuthorizerAndTrail(t *testing.T) {
	denied := errors.New("denied by the control's authorizer")
	audit := &spyAuditSink{}
	ctl := NewControl(NewRecorder(audit, nil, nil), &permissiveControlAuthorizer{err: denied}, &fakeFreezeStore{})
	acct := NewAccountAdmin(ctl, &fakeAccountStore{}, &fakeAPITokenStore{})

	p := Principal{AccountID: "acct-1", Account: "me", Role: "admin", Kind: PrincipalKindHuman}
	_, err := acct.CreateAccount(context.Background(), p, accounts.Account{Name: "x"})
	if !errors.Is(err, denied) {
		t.Fatalf("CreateAccount error = %v, want the Control's authorizer error", err)
	}
	var refusals int
	for _, e := range audit.entries {
		if e.Kind == AuditKindRefusal && e.Principal.AccountID == p.AccountID {
			refusals++
		}
	}
	if refusals != 1 {
		t.Fatalf("refusal rows on the Control's trail = %d, want 1; entries = %+v", refusals, audit.entries)
	}
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
			"acct-1": {ID: "acct-1", Name: "one", Role: accounts.RoleViewer},
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
// store.Open database (suggestion 6, mitigation (a)): the guard is SQL in
// store/**, and this test pins it from the capability layer, so it fails CI
// if that guard is ever removed, from inside a package a reviewer is already
// required to look at.
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

func TestAccountAdmin_SetAccountRoleFromRecordsTheNewRole(t *testing.T) {
	accountStore := &fakeAccountStore{}
	svc, audit := newAccountAdminFixture(t, &permissiveControlAuthorizer{}, accountStore, &fakeAPITokenStore{})
	p := Principal{AccountID: "acct-admin", Account: "admin", Role: "admin", Kind: PrincipalKindHuman}

	if err := svc.SetAccountRoleFrom(context.Background(), p, "acct-1", accounts.RoleAdmin, accounts.RoleOperator); err != nil {
		t.Fatalf("SetAccountRoleFrom: %v", err)
	}
	if len(accountStore.setRoleCalls) != 1 {
		t.Fatalf("store SetRole calls = %d, want 1", len(accountStore.setRoleCalls))
	}
	if c := accountStore.setRoleCalls[0]; c.id != "acct-1" || c.from != accounts.RoleAdmin || c.to != accounts.RoleOperator {
		t.Errorf("store got %+v, want (acct-1, admin, operator)", c)
	}
	if len(audit.accountAdminCalls) != 1 {
		t.Fatalf("recorded %d events, want 1", len(audit.accountAdminCalls))
	}
	if ev := audit.accountAdminCalls[0].Event; ev.Kind != AccountAdminRole || ev.AccountID != "acct-1" || ev.Role != string(accounts.RoleOperator) {
		t.Errorf("event = %+v, want AccountAdminRole acct-1 with the new role", ev)
	}
}

func TestAccountAdmin_SetAccountRoleFromRefusesSelfBeforeTheStore(t *testing.T) {
	accountStore := &fakeAccountStore{}
	svc, audit := newAccountAdminFixture(t, &permissiveControlAuthorizer{}, accountStore, &fakeAPITokenStore{})
	p := Principal{AccountID: "acct-1", Account: "me", Role: "admin", Kind: PrincipalKindHuman}

	err := svc.SetAccountRoleFrom(context.Background(), p, "acct-1", accounts.RoleAdmin, accounts.RoleViewer)
	if !errors.Is(err, ErrSelfTargeted) {
		t.Fatalf("SetAccountRoleFrom(self) = %v, want ErrSelfTargeted", err)
	}
	if len(accountStore.setRoleCalls) != 0 {
		t.Errorf("SetRole was called %d times, want 0", len(accountStore.setRoleCalls))
	}
	if len(audit.entries) != 1 || audit.entries[0].Kind != AuditKindRefusal {
		t.Errorf("audit entries = %+v, want exactly one AuditKindRefusal", audit.entries)
	}
}

func TestAccountAdmin_SetAccountRoleFromRequiresAdmin(t *testing.T) {
	denyErr := errors.New("authz: unauthorized: needs admin")
	accountStore := &fakeAccountStore{}
	svc, audit := newAccountAdminFixture(t, &permissiveControlAuthorizer{err: denyErr}, accountStore, &fakeAPITokenStore{})
	p := Principal{AccountID: "acct-viewer", Account: "viewer", Role: "viewer"}

	err := svc.SetAccountRoleFrom(context.Background(), p, "acct-1", accounts.RoleViewer, accounts.RoleAdmin)
	if !errors.Is(err, denyErr) {
		t.Fatalf("SetAccountRoleFrom below the floor = %v, want the denial", err)
	}
	if len(accountStore.setRoleCalls) != 0 {
		t.Errorf("SetRole was called %d times, want 0", len(accountStore.setRoleCalls))
	}
	if len(audit.entries) != 1 || audit.entries[0].Kind != AuditKindRefusal {
		t.Errorf("audit entries = %+v, want exactly one AuditKindRefusal", audit.entries)
	}
}

// The unconditional path reads the stored role and passes exactly it as
// `from`, so its write is a compare-and-set on what it just saw.
func TestAccountAdmin_SetAccountRolePassesTheStoredRoleAsFrom(t *testing.T) {
	accountStore := &fakeAccountStore{accountsByID: map[string]accounts.Account{
		"acct-1": {ID: "acct-1", Role: accounts.RoleOperator},
	}}
	svc, _ := newAccountAdminFixture(t, &permissiveControlAuthorizer{}, accountStore, &fakeAPITokenStore{})
	p := Principal{AccountID: "acct-admin", Account: "admin", Role: "admin"}

	if err := svc.SetAccountRole(context.Background(), p, "acct-1", accounts.RoleAdmin); err != nil {
		t.Fatalf("SetAccountRole: %v", err)
	}
	if len(accountStore.setRoleCalls) != 1 {
		t.Fatalf("store SetRole calls = %d, want 1", len(accountStore.setRoleCalls))
	}
	if c := accountStore.setRoleCalls[0]; c.from != accounts.RoleOperator || c.to != accounts.RoleAdmin {
		t.Errorf("store got from=%q to=%q, want from=operator to=admin", c.from, c.to)
	}
}

// TestAccountAdmin_SetAccountRoleFromRefusesAStaleRole is the capability-seam
// half of #912, on a real store: a caller that read X as admin, after a
// second admin demoted X, is refused and writes nothing.
func TestAccountAdmin_SetAccountRoleFromRefusesAStaleRole(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck
	ctx := context.Background()

	var x accounts.Account
	for _, name := range []string{"admin-1", "admin-2", "target"} {
		a, err := st.Accounts().Create(ctx, accounts.Account{
			Name: name, Kind: accounts.KindHuman, Role: accounts.RoleAdmin, Enabled: true,
		})
		if err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
		x = a
	}
	tokenSvc := accounts.NewTokenService(st.APITokens(), st.Accounts(), nil)
	svc, audit := newAccountAdminFixture(t, &permissiveControlAuthorizer{}, st.Accounts(), tokenSvc)

	first := Principal{AccountID: "caller-1", Account: "c1", Role: "admin"}
	second := Principal{AccountID: "caller-2", Account: "c2", Role: "admin"}

	read, err := svc.Account(ctx, first, x.ID)
	if err != nil {
		t.Fatalf("Account: %v", err)
	}
	if err := svc.SetAccountRole(ctx, second, x.ID, accounts.RoleViewer); err != nil {
		t.Fatalf("concurrent demotion: %v", err)
	}

	err = svc.SetAccountRoleFrom(ctx, first, x.ID, read.Role, accounts.RoleOperator)
	if !errors.Is(err, accounts.ErrRoleChanged) {
		t.Fatalf("SetAccountRoleFrom(stale admin) = %v, want accounts.ErrRoleChanged", err)
	}
	got, err := st.Accounts().Get(ctx, x.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Role != accounts.RoleViewer {
		t.Errorf("role = %q, want viewer: the refused write must not land", got.Role)
	}
	if len(audit.accountAdminCalls) != 1 {
		t.Errorf("recorded %d account-admin events, want 1 (the demotion only): %+v", len(audit.accountAdminCalls), audit.accountAdminCalls)
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
