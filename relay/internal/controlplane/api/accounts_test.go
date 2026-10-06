package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/authz"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/store"
)

// -----------------------------------------------------------------------
// Harness: the REAL authenticator over the REAL store and TokenService.
//
// No fakes here on purpose. These tests are about who may do what across the
// authentication boundary, and a fake authenticator or a fake token verifier
// would be testing the fake: the bootstrap credential and every other Account
// token go through exactly the wiring cmd/relay builds.
// -----------------------------------------------------------------------

type identityFixture struct {
	handler http.Handler
	store   *store.Store
	tokens  *accounts.TokenService
	founder accounts.Account
	// bootstrap is the founding admin's credential — the equivalent of
	// `relay bootstrap-token` output, and the only way in before any other
	// Account exists.
	bootstrap string
}

// newIdentityFixture wires the identity routes through a REAL
// *capability.Service (#653), exactly as cmd/relay does: a real RoleGate, a
// real auditsink.Sink over the store's own audit.Repository, and
// WithAccountAdmin(st.Accounts(), tokenSvc). package api's import and
// no-dispatch guards both skip _test.go files, so constructing a real
// *capability.Service here is permitted — no real dispatcher is wired, so
// New's fail-open guard is satisfied by the Authorizer + AuditSink above,
// exactly as WithQueries' guard is satisfied elsewhere without a dispatcher.
//
// CONSEQUENCE: the last-admin SQL guard (internal/store/accounts.go) is
// therefore LIVE in every identity API test. The one place this could bite
// is TestIdentityAPI_SelfDisableAndSelfRoleAreRefused, where the founding
// admin disables the "ops" admin and expects 200 — at that point the
// founding admin and "ops" are both enabled admins, so disabling "ops"
// leaves one and the call still succeeds.
func newIdentityFixture(t *testing.T) *identityFixture {
	t.Helper()
	return newIdentityFixtureWith(t, func(s capability.AccountStore) capability.AccountStore { return s })
}

// newIdentityFixtureWith is newIdentityFixture with the Account store the
// capability layer sees passed through wrap, so a test can inject a store
// fault without a second copy of the wiring.
func newIdentityFixtureWith(t *testing.T, wrap func(capability.AccountStore) capability.AccountStore) *identityFixture {
	t.Helper()

	st, err := store.Open(filepath.Join(t.TempDir(), "relay.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() }) //nolint:errcheck

	ctx := context.Background()
	founder, err := st.Accounts().EnsureFoundingAdmin(ctx)
	if err != nil {
		t.Fatalf("seed founding admin: %v", err)
	}

	tokenSvc := accounts.NewTokenService(st.APITokens(), st.Accounts(), nil)

	// The founding admin's bootstrap credential, minted exactly as
	// `relay bootstrap-token` does — so these tests drive the real credential
	// path end to end rather than a fixture that stands in for one.
	_, bootstrap, err := tokenSvc.Mint(ctx, founder.ID, "bootstrap", time.Hour)
	if err != nil {
		t.Fatalf("mint bootstrap token: %v", err)
	}

	authn := controlplane.NewAuthenticator(tokenSvc)

	// The auditsink.Sink deliberately keeps its OWN default clock
	// (time.Now, nanosecond-precision via RFC3339Nano — internal/store's
	// timeLayout) rather than auditsink.WithClock(fixedNow): two records
	// written under one frozen timestamp tie on the trail's `ORDER BY ts`,
	// and the store gives no secondary sort key to break that tie, so the
	// end-to-end test below (which asserts an exact kind ORDER) would be at
	// the mercy of an unspecified tie-break rather than real insertion order.
	capSvc := capability.New(registry.NewInMemory(),
		capability.WithAuthorizer(authz.NewRoleGate()),
		capability.WithAuditSink(auditsink.New(st.Audit())),
		capability.WithAccountAdmin(wrap(st.Accounts()), tokenSvc))

	mux := http.NewServeMux()
	Register(mux, Deps{
		AccountAdmin: capSvc,
		Audit:        &fakeAuditor{}, // unused by the identity routes; kept so Register never sees a nil Auditor.
		Now:          fixedNow,
	})

	return &identityFixture{
		handler:   authn.Middleware(mux),
		store:     st,
		tokens:    tokenSvc,
		founder:   founder,
		bootstrap: bootstrap.Reveal(),
	}
}

// call issues a request with an explicit credential, so a test can present the
// bootstrap credential, another Account's token, or a bad one.
func (f *identityFixture) call(t *testing.T, credential, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Authorization", "Bearer "+credential)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// mintFor creates an Account with the given role and mints it a credential,
// returning the Account and the plaintext.
func (f *identityFixture) mintFor(t *testing.T, name string, role accounts.Role) (accounts.Account, string) {
	t.Helper()
	ctx := context.Background()
	acct, err := f.store.Accounts().Create(ctx, accounts.Account{
		Name: name, Kind: accounts.KindMachine, Role: role, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create %s account: %v", role, err)
	}
	_, plaintext, err := f.tokens.Mint(ctx, acct.ID, name+"-token", time.Hour)
	if err != nil {
		t.Fatalf("mint token for %s: %v", name, err)
	}
	return acct, plaintext.Reveal()
}

func decodeInto(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
}

// auditRecords returns every Record the real store's audit trail holds,
// ordered by timestamp — re-pointed at f.store.Audit().List (#653) now that
// the identity routes' capability.Service audits through auditsink.Sink onto
// the real store rather than the fakeAuditor.
func (f *identityFixture) auditRecords(t *testing.T) []audit.Record {
	t.Helper()
	records, err := f.store.Audit().List(context.Background())
	if err != nil {
		t.Fatalf("f.store.Audit().List: %v", err)
	}
	return records
}

func (f *identityFixture) auditKinds(t *testing.T) []string {
	var kinds []string
	for _, r := range f.auditRecords(t) {
		kinds = append(kinds, r.Kind)
	}
	return kinds
}

// -----------------------------------------------------------------------
// Acceptance: an admin token creates an operator machine Account and mints
// its token end-to-end over REST.
// -----------------------------------------------------------------------

func TestIdentityAPI_AdminCreatesAccountAndMintsTokenEndToEnd(t *testing.T) {
	f := newIdentityFixture(t)

	// 1. Create the Account with the seeded (founding admin) credential.
	rec := f.call(t, f.bootstrap, http.MethodPost, "/api/v1/accounts", createAccountRequest{
		Name: "gleipnir", Kind: "machine", Role: "operator",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create account: status %d, body %s", rec.Code, rec.Body.String())
	}
	var created accountResponse
	decodeInto(t, rec, &created)
	if created.ID == "" || created.Name != "gleipnir" || created.Role != "operator" || !created.Enabled {
		t.Fatalf("created account = %+v, want an enabled operator machine Account", created)
	}

	// 2. Mint it a credential.
	ttl := int64(3600)
	rec = f.call(t, f.bootstrap, http.MethodPost, "/api/v1/accounts/"+created.ID+"/tokens",
		mintAPITokenRequest{Name: "ci-deploy", TTLSeconds: &ttl})
	if rec.Code != http.StatusCreated {
		t.Fatalf("mint token: status %d, body %s", rec.Code, rec.Body.String())
	}
	var minted mintAPITokenResponse
	decodeInto(t, rec, &minted)
	if !strings.HasPrefix(minted.Token, accounts.TokenPrefix) {
		t.Errorf("minted credential %q lacks the %q prefix", minted.Token, accounts.TokenPrefix)
	}
	if minted.APIToken.ID == "" || minted.APIToken.AccountID != created.ID {
		t.Errorf("minted token metadata = %+v, want it bound to %q", minted.APIToken, created.ID)
	}

	// 3. The new credential authenticates — as the operator Account it belongs
	//    to, which is what makes the whole chain end-to-end rather than three
	//    separate store writes.
	acct, _, err := f.tokens.Verify(context.Background(), minted.Token)
	if err != nil {
		t.Fatalf("verify minted credential: %v", err)
	}
	if acct.ID != created.ID || acct.Role != accounts.RoleOperator {
		t.Errorf("credential authenticated as %+v, want the created operator Account", acct)
	}

	// 4. Both acts are audited and attributed to the founding admin. Reads
	//    write no audit row (accountadmin.go), so this is exactly the two
	//    writes above — no more, no less.
	kinds := f.auditKinds(t)
	if len(kinds) != 2 || kinds[0] != audit.KindAccountCreate || kinds[1] != audit.KindAPITokenMint {
		t.Fatalf("audit kinds = %v, want [%s %s]", kinds, audit.KindAccountCreate, audit.KindAPITokenMint)
	}
	for _, r := range f.auditRecords(t) {
		if !strings.HasPrefix(r.Principal, accounts.FoundingAdminName+":") {
			t.Errorf("audit record %q attributed to %q, want the founding admin Account", r.Kind, r.Principal)
		}
	}
}

// The plaintext is shown at mint and never again — not by the list view, not
// by a re-read. An operator who loses it mints another and revokes this one.
func TestIdentityAPI_PlaintextAppearsOnlyInTheMintResponse(t *testing.T) {
	f := newIdentityFixture(t)
	acct, _ := f.mintFor(t, "ci", accounts.RoleViewer)

	ttl := int64(0)
	rec := f.call(t, f.bootstrap, http.MethodPost, "/api/v1/accounts/"+acct.ID+"/tokens",
		mintAPITokenRequest{Name: "second", TTLSeconds: &ttl})
	if rec.Code != http.StatusCreated {
		t.Fatalf("mint: status %d, body %s", rec.Code, rec.Body.String())
	}
	var minted mintAPITokenResponse
	decodeInto(t, rec, &minted)
	secret := minted.Token

	rec = f.call(t, f.bootstrap, http.MethodGet, "/api/v1/accounts/"+acct.ID+"/tokens", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list tokens: status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatal("the token list response contains the plaintext credential")
	}
	// Not even the hash: an exported hash is an offline-cracking target with
	// no legitimate consumer.
	if strings.Contains(strings.ToLower(rec.Body.String()), "secret_hash") ||
		strings.Contains(strings.ToLower(rec.Body.String()), "hash") {
		t.Errorf("the token list response exposes hash material: %s", rec.Body.String())
	}

	var list listAPITokensResponse
	decodeInto(t, rec, &list)
	if len(list.Tokens) != 2 {
		t.Fatalf("listed %d tokens, want 2", len(list.Tokens))
	}

	// A zero TTL renders as an absent expires_at, not as year 1.
	for _, tok := range list.Tokens {
		if tok.Name == "second" && tok.ExpiresAt != "" {
			t.Errorf("a zero-TTL token rendered expires_at = %q, want it absent", tok.ExpiresAt)
		}
	}

	// The audit record for the mint carries the token's id, never its secret.
	for _, r := range f.auditRecords(t) {
		if strings.Contains(r.Reason, secret) {
			t.Errorf("audit reason %q contains the plaintext credential", r.Reason)
		}
	}
}

// -----------------------------------------------------------------------
// Acceptance: a viewer/operator token is refused these endpoints.
// -----------------------------------------------------------------------

func TestIdentityAPI_NonAdminIsRefusedEveryIdentityEndpoint(t *testing.T) {
	f := newIdentityFixture(t)
	target, _ := f.mintFor(t, "target", accounts.RoleViewer)

	ttl := int64(60)
	routes := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/api/v1/accounts", createAccountRequest{Name: "sneaky", Kind: "machine", Role: "admin"}},
		{http.MethodGet, "/api/v1/accounts", nil},
		{http.MethodGet, "/api/v1/accounts/" + target.ID, nil},
		{http.MethodPost, "/api/v1/accounts/" + target.ID + "/role", setRoleRequest{Role: "admin"}},
		{http.MethodPost, "/api/v1/accounts/" + target.ID + "/enable", nil},
		{http.MethodPost, "/api/v1/accounts/" + target.ID + "/disable", nil},
		{http.MethodPost, "/api/v1/accounts/" + target.ID + "/tokens", mintAPITokenRequest{Name: "x", TTLSeconds: &ttl}},
		{http.MethodGet, "/api/v1/accounts/" + target.ID + "/tokens", nil},
		{http.MethodDelete, "/api/v1/api-tokens/whatever", nil},
	}

	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator} {
		_, credential := f.mintFor(t, "caller-"+string(role), role)
		for _, rt := range routes {
			rec := f.call(t, credential, rt.method, rt.path, rt.body)
			if rec.Code != http.StatusForbidden {
				t.Errorf("[%s] %s %s: status %d, want 403; body %s",
					role, rt.method, rt.path, rec.Code, rec.Body.String())
			}
		}
	}

	// A refused caller changed nothing.
	after, err := f.store.Accounts().Get(context.Background(), target.ID)
	if err != nil {
		t.Fatalf("re-read target: %v", err)
	}
	if after.Role != accounts.RoleViewer || !after.Enabled {
		t.Errorf("target = %+v after refused calls, want an untouched enabled viewer", after)
	}

	// AMENDED AC (coordinator ruling, #653): moving the floor into the
	// capability layer is precisely what makes refusals audited — refuseControl
	// writes an AuditKindRefusal row on every denial (service.go). "want 0"
	// encoded the pre-#653 behaviour; the assertion now proves BOTH that
	// refusals are audited AND that nothing mutated: one refusal row per
	// refused call (2 roles x 9 routes = 18), every one a KindRefusal.
	records := f.auditRecords(t)
	wantRefusals := 2 * len(routes)
	if len(records) != wantRefusals {
		t.Fatalf("%d audit records written for %d refused calls, want %d — refusals are audited", len(records), wantRefusals, wantRefusals)
	}
	for _, r := range records {
		if r.Kind != audit.KindRefusal {
			t.Errorf("audit record kind = %q, want %q for every refused call", r.Kind, audit.KindRefusal)
		}
	}
}

// A privilege escalation attempt is refused at the gate, not merely rejected
// by the store: an operator must not be able to mint themselves an admin.
func TestIdentityAPI_OperatorCannotSelfPromote(t *testing.T) {
	f := newIdentityFixture(t)
	caller, credential := f.mintFor(t, "gleipnir", accounts.RoleOperator)

	rec := f.call(t, credential, http.MethodPost, "/api/v1/accounts/"+caller.ID+"/role",
		setRoleRequest{Role: "admin"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("self-promote: status %d, want 403; body %s", rec.Code, rec.Body.String())
	}
	after, _ := f.store.Accounts().Get(context.Background(), caller.ID)
	if after.Role != accounts.RoleOperator {
		t.Fatalf("role after self-promote attempt = %q, want operator", after.Role)
	}
}

// -----------------------------------------------------------------------
// Acceptance: the existing endpoints authenticate via Account tokens, and the
// founding admin path still works.
// -----------------------------------------------------------------------

func TestIdentityAPI_AccountTokenAuthenticatesAndRevocationCutsAccess(t *testing.T) {
	f := newIdentityFixture(t)

	// An admin Account's token drives the identity endpoints exactly as the
	// bootstrap credential does.
	_, credential := f.mintFor(t, "ops", accounts.RoleAdmin)
	if rec := f.call(t, credential, http.MethodGet, "/api/v1/accounts", nil); rec.Code != http.StatusOK {
		t.Fatalf("admin token list: status %d, body %s", rec.Code, rec.Body.String())
	}

	// Revoking that token cuts access on the very next request — a generic
	// 401, indistinguishable from a credential that was never real.
	list, err := f.tokens.List(context.Background(), mustAccountID(t, f, "ops"))
	if err != nil || len(list) != 1 {
		t.Fatalf("list tokens: %v (%d)", err, len(list))
	}
	if err := f.tokens.Revoke(context.Background(), list[0].ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	rec := f.call(t, credential, http.MethodGet, "/api/v1/accounts", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("after revoke: status %d, want 401", rec.Code)
	}

	// The seeded founding-admin path is unaffected by any of it.
	if rec := f.call(t, f.bootstrap, http.MethodGet, "/api/v1/accounts", nil); rec.Code != http.StatusOK {
		t.Fatalf("founding admin after revoke: status %d, body %s", rec.Code, rec.Body.String())
	}
}

// Disabling an Account cuts every one of its tokens off at once, without
// revoking any of them.
func TestIdentityAPI_DisablingAnAccountCutsItsTokensOff(t *testing.T) {
	f := newIdentityFixture(t)
	acct, credential := f.mintFor(t, "ops", accounts.RoleAdmin)

	if rec := f.call(t, credential, http.MethodGet, "/api/v1/accounts", nil); rec.Code != http.StatusOK {
		t.Fatalf("before disable: status %d", rec.Code)
	}

	rec := f.call(t, f.bootstrap, http.MethodPost, "/api/v1/accounts/"+acct.ID+"/disable", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("disable: status %d, body %s", rec.Code, rec.Body.String())
	}
	var disabled accountResponse
	decodeInto(t, rec, &disabled)
	if disabled.Enabled {
		t.Error("response reports the account still enabled after disable")
	}

	if rec := f.call(t, credential, http.MethodGet, "/api/v1/accounts", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after disable: status %d, want 401", rec.Code)
	}

	// Re-enabling restores it: disablement is an off-switch on the identity,
	// not a destruction of its credentials.
	if rec := f.call(t, f.bootstrap, http.MethodPost, "/api/v1/accounts/"+acct.ID+"/enable", nil); rec.Code != http.StatusOK {
		t.Fatalf("enable: status %d", rec.Code)
	}
	if rec := f.call(t, credential, http.MethodGet, "/api/v1/accounts", nil); rec.Code != http.StatusOK {
		t.Fatalf("after re-enable: status %d, want 200", rec.Code)
	}
}

// A bad credential of either shape gets the same generic 401 — the boundary is
// not an oracle telling a caller which kind of credential it recognized.
func TestIdentityAPI_BadCredentialsAreIndistinguishable(t *testing.T) {
	f := newIdentityFixture(t)

	for _, c := range []struct{ label, credential string }{
		{"not a credential at all", "not-the-credential"},
		{"token-shaped but unknown", accounts.TokenPrefix + "0123456789abcdef.nonsense"},
		{"token prefix only", accounts.TokenPrefix},
		{"empty-ish", " "},
	} {
		rec := f.call(t, c.credential, http.MethodGet, "/api/v1/accounts", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("[%s] status %d, want 401", c.label, rec.Code)
		}
		if strings.Contains(rec.Body.String(), c.credential) && strings.TrimSpace(c.credential) != "" {
			t.Errorf("[%s] the 401 body echoes the presented credential: %s", c.label, rec.Body.String())
		}
	}
}

// -----------------------------------------------------------------------
// Lockout guard and error mapping
// -----------------------------------------------------------------------

// An admin may not disable or re-role their own Account: the last admin
// switching itself off leaves a control plane with no way back in.
func TestIdentityAPI_SelfDisableAndSelfRoleAreRefused(t *testing.T) {
	f := newIdentityFixture(t)
	_, credential := f.mintFor(t, "ops", accounts.RoleAdmin)
	self := mustAccountID(t, f, "ops")

	rec := f.call(t, credential, http.MethodPost, "/api/v1/accounts/"+self+"/disable", nil)
	if rec.Code != http.StatusConflict {
		t.Errorf("self-disable: status %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	rec = f.call(t, credential, http.MethodPost, "/api/v1/accounts/"+self+"/role", setRoleRequest{Role: "viewer"})
	if rec.Code != http.StatusConflict {
		t.Errorf("self-re-role: status %d, want 409; body %s", rec.Code, rec.Body.String())
	}

	after, _ := f.store.Accounts().Get(context.Background(), self)
	if !after.Enabled || after.Role != accounts.RoleAdmin {
		t.Errorf("account = %+v after refused self-targeting, want an untouched enabled admin", after)
	}

	// Another admin can still do it — this is a lockout guard, not a rule that
	// admins are undemotable.
	if rec := f.call(t, f.bootstrap, http.MethodPost, "/api/v1/accounts/"+self+"/disable", nil); rec.Code != http.StatusOK {
		t.Errorf("another admin disabling it: status %d, want 200", rec.Code)
	}
}

// roleChangedStore reports every SetRole as having lost a race (#912).
type roleChangedStore struct{ capability.AccountStore }

func (roleChangedStore) SetRole(context.Context, string, accounts.Role, accounts.Role) error {
	return accounts.ErrRoleChanged
}

// The role route is unconditional, but its store write is a compare-and-set;
// losing that race in the instant after its own read must be a 409, never a
// bare 500.
func TestIdentityAPI_RoleChangedIsAConflict(t *testing.T) {
	f := newIdentityFixtureWith(t, func(s capability.AccountStore) capability.AccountStore {
		return roleChangedStore{s}
	})
	target, _ := f.mintFor(t, "target", accounts.RoleViewer)

	rec := f.call(t, f.bootstrap, http.MethodPost, "/api/v1/accounts/"+target.ID+"/role", setRoleRequest{Role: "operator"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("status %d, want 409; body %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "account changed concurrently") {
		t.Errorf("body %s, want title %q", rec.Body.String(), "account changed concurrently")
	}
}

func TestIdentityAPI_ErrorMapping(t *testing.T) {
	f := newIdentityFixture(t)
	existing, _ := f.mintFor(t, "taken", accounts.RoleViewer)
	ttl := int64(60)

	cases := []struct {
		label        string
		method, path string
		body         any
		want         int
	}{
		{"duplicate name", http.MethodPost, "/api/v1/accounts",
			createAccountRequest{Name: "TAKEN", Kind: "machine", Role: "viewer"}, http.StatusConflict},
		{"reserved name", http.MethodPost, "/api/v1/accounts",
			createAccountRequest{Name: accounts.FoundingAdminName, Kind: "human", Role: "admin"}, http.StatusBadRequest},
		{"malformed name", http.MethodPost, "/api/v1/accounts",
			createAccountRequest{Name: "bad name", Kind: "human", Role: "viewer"}, http.StatusBadRequest},
		{"unknown kind", http.MethodPost, "/api/v1/accounts",
			createAccountRequest{Name: "robot", Kind: "robot", Role: "viewer"}, http.StatusBadRequest},
		{"unknown role", http.MethodPost, "/api/v1/accounts",
			createAccountRequest{Name: "rooty", Kind: "human", Role: "root"}, http.StatusBadRequest},
		{"unknown account", http.MethodGet, "/api/v1/accounts/acct-nope", nil, http.StatusNotFound},
		{"role on unknown account", http.MethodPost, "/api/v1/accounts/acct-nope/role",
			setRoleRequest{Role: "viewer"}, http.StatusNotFound},
		{"invalid role", http.MethodPost, "/api/v1/accounts/" + existing.ID + "/role",
			setRoleRequest{Role: "root"}, http.StatusBadRequest},
		{"mint for unknown account", http.MethodPost, "/api/v1/accounts/acct-nope/tokens",
			mintAPITokenRequest{Name: "x", TTLSeconds: &ttl}, http.StatusNotFound},
		{"revoke unknown token", http.MethodDelete, "/api/v1/api-tokens/nope", nil, http.StatusNotFound},
	}
	for _, c := range cases {
		rec := f.call(t, f.bootstrap, c.method, c.path, c.body)
		if rec.Code != c.want {
			t.Errorf("[%s] status %d, want %d; body %s", c.label, rec.Code, c.want, rec.Body.String())
		}
	}
}

// ttl_seconds must be stated explicitly: 0 (never expires) is legitimate but
// must be asked for, so a forgotten field cannot silently mint an immortal
// credential.
func TestIdentityAPI_MintRequiresExplicitTTL(t *testing.T) {
	f := newIdentityFixture(t)
	acct, _ := f.mintFor(t, "ci", accounts.RoleViewer)
	path := "/api/v1/accounts/" + acct.ID + "/tokens"

	rec := f.call(t, f.bootstrap, http.MethodPost, path, map[string]any{"name": "no-ttl"})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("absent ttl_seconds: status %d, want 400; body %s", rec.Code, rec.Body.String())
	}

	negative := int64(-1)
	rec = f.call(t, f.bootstrap, http.MethodPost, path,
		mintAPITokenRequest{Name: "negative", TTLSeconds: &negative})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("negative ttl_seconds: status %d, want 400", rec.Code)
	}

	huge := int64(maxTTLSeconds + 1)
	rec = f.call(t, f.bootstrap, http.MethodPost, path,
		mintAPITokenRequest{Name: "huge", TTLSeconds: &huge})
	if rec.Code != http.StatusBadRequest {
		t.Errorf("oversized ttl_seconds: status %d, want 400", rec.Code)
	}

	zero := int64(0)
	rec = f.call(t, f.bootstrap, http.MethodPost, path,
		mintAPITokenRequest{Name: "forever", TTLSeconds: &zero})
	if rec.Code != http.StatusCreated {
		t.Errorf("explicit zero ttl_seconds: status %d, want 201; body %s", rec.Code, rec.Body.String())
	}
}

// TestIdentityAPI_AuthorizationIsCheckedAfterRequestValidation pins #653's
// accepted reorder (suggestion 9): AuthorizeControl now runs INSIDE the
// capability call, after decodeJSON and the mint route's TTL/name
// validation, so a below-floor caller sending a malformed body gets 400
// where the deleted requireAdmin used to answer 403. This is accepted
// rather than papered over with a surface-side pre-check, because a
// pre-check would keep a role check in this package's call graph and make
// role_floor_test.go's floorCapability classification false.
//
// The disclosure analysis: every pre-authorization check here (decodeJSON,
// the ttl_seconds bounds, the name length) validates only the CALLER'S OWN
// INPUT and touches no store, so a refused caller learns nothing about any
// Account — a viewer with a valid body gets exactly the same 403 an operator
// with the same body would, and a viewer with an invalid body gets exactly
// the same 400 an admin sending that body would.
func TestIdentityAPI_AuthorizationIsCheckedAfterRequestValidation(t *testing.T) {
	f := newIdentityFixture(t)
	target, _ := f.mintFor(t, "target", accounts.RoleViewer)
	_, viewerCred := f.mintFor(t, "caller-viewer", accounts.RoleViewer)
	path := "/api/v1/accounts/" + target.ID + "/tokens"

	// An invalid body (missing ttl_seconds) fails validation before
	// AuthorizeControl is ever reached — 400, not 403.
	rec := f.call(t, viewerCred, http.MethodPost, path, map[string]any{"name": "no-ttl"})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("viewer with an invalid body: status %d, want 400", rec.Code)
	}

	// A VALID body reaches the capability call, which refuses at the floor —
	// 403, and the target's tokens are untouched.
	ttl := int64(3600)
	rec = f.call(t, viewerCred, http.MethodPost, path, mintAPITokenRequest{Name: "sneaky", TTLSeconds: &ttl})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer with a valid body: status %d, want 403; body %s", rec.Code, rec.Body.String())
	}

	// mintFor above already minted target ONE token (its own credential); a
	// refused mint must not add a second.
	list, err := f.tokens.List(context.Background(), target.ID)
	if err != nil {
		t.Fatalf("list tokens: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("target has %d tokens after a refused mint, want 1 (only mintFor's own)", len(list))
	}

	records := f.auditRecords(t)
	if len(records) != 1 || records[0].Kind != audit.KindRefusal {
		t.Fatalf("audit records = %+v, want exactly one KindRefusal", records)
	}
}

// Minting for a disabled Account is refused rather than producing a credential
// that looks like access but authenticates nowhere.
func TestIdentityAPI_MintForDisabledAccountIsRefused(t *testing.T) {
	f := newIdentityFixture(t)
	acct, _ := f.mintFor(t, "retired", accounts.RoleViewer)
	if err := f.store.Accounts().SetEnabled(context.Background(), acct.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}

	ttl := int64(60)
	rec := f.call(t, f.bootstrap, http.MethodPost, "/api/v1/accounts/"+acct.ID+"/tokens",
		mintAPITokenRequest{Name: "x", TTLSeconds: &ttl})
	if rec.Code != http.StatusConflict {
		t.Fatalf("mint for disabled account: status %d, want 409; body %s", rec.Code, rec.Body.String())
	}
}

// Revoking twice is a no-op (204 both times); an operator racing themselves
// mid-incident should not see a failure.
func TestIdentityAPI_RevokeIsIdempotent(t *testing.T) {
	f := newIdentityFixture(t)
	acct, _ := f.mintFor(t, "ci", accounts.RoleViewer)

	list, err := f.tokens.List(context.Background(), acct.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v (%d)", err, len(list))
	}
	path := "/api/v1/api-tokens/" + list[0].ID
	for i := 0; i < 2; i++ {
		if rec := f.call(t, f.bootstrap, http.MethodDelete, path, nil); rec.Code != http.StatusNoContent {
			t.Fatalf("revoke #%d: status %d", i+1, rec.Code)
		}
	}
	if got := len(f.auditRecords(t)); got != 2 {
		t.Errorf("%d audit records for two revokes, want 2 — each act is recorded", got)
	}
}

func mustAccountID(t *testing.T, f *identityFixture, name string) string {
	t.Helper()
	acct, err := f.store.Accounts().GetByName(context.Background(), name)
	if err != nil {
		t.Fatalf("get account %q: %v", name, err)
	}
	return acct.ID
}
