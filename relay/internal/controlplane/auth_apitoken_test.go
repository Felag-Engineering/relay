package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

// -----------------------------------------------------------------------
// Harness
// -----------------------------------------------------------------------

const testCredential = accounts.TokenPrefix + "0123456789abcdef.a-secret" // test fixture, not a real credential

// fakeVerifier stands in for *accounts.TokenService. It records every
// credential it was asked about, so a test can assert not just the outcome but
// *what reached the verifier at all*.
//
// It models the real service's contract: one indistinguishable error for every
// failure, and the Account read fresh on each call (acct is read at call time,
// so a test can mutate it between requests and see the change take effect).
type fakeVerifier struct {
	acct  accounts.Account
	valid string
	err   error
	seen  []string
}

func (f *fakeVerifier) Verify(_ context.Context, credential string) (accounts.Account, accounts.APIToken, error) {
	f.seen = append(f.seen, credential)
	if f.err != nil {
		return accounts.Account{}, accounts.APIToken{}, f.err
	}
	if credential != f.valid {
		return accounts.Account{}, accounts.APIToken{}, accounts.ErrTokenInvalid
	}
	if !f.acct.Enabled {
		return accounts.Account{}, accounts.APIToken{}, accounts.ErrTokenInvalid
	}
	return f.acct, accounts.APIToken{ID: "tok-1", AccountID: f.acct.ID}, nil
}

// capabilityPrincipal is the flattened Principal a handler saw.
type capabilityPrincipal struct{ ID, Name, Role string }

// authRequest drives one request through the middleware and returns the status
// plus the Principal the handler saw (zero value if it was never reached).
func authRequest(t *testing.T, a *Authenticator, credential string) (int, capabilityPrincipal) {
	t.Helper()
	var seen capabilityPrincipal
	h := a.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFromContext(r.Context())
		if ok {
			seen = capabilityPrincipal{ID: p.AccountID, Name: p.Account, Role: p.Role}
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, seen
}

// testAdminName names the first admin in these tests. No name is reserved, so
// it is an ordinary name.
const testAdminName = "first-admin"

func storedFirstAdmin() accounts.Account {
	return accounts.Account{
		ID:      "acct-first-admin",
		Name:    testAdminName,
		Kind:    accounts.KindHuman,
		Role:    accounts.RoleAdmin,
		Enabled: true,
	}
}

func operatorAccount() accounts.Account {
	return accounts.Account{
		ID:      "acct-gleipnir",
		Name:    "gleipnir",
		Kind:    accounts.KindMachine,
		Role:    accounts.RoleOperator,
		Enabled: true,
	}
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

// A valid API Token authenticates as its Account, carrying the stored ID and
// the role that Account holds right now — not a hardcoded identity, and not a
// role captured when the token was minted.
func TestAuthenticator_APITokenResolvesToItsAccount(t *testing.T) {
	v := &fakeVerifier{acct: operatorAccount(), valid: testCredential}
	a := NewAuthenticator(v)

	code, seen := authRequest(t, a, testCredential)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if seen.ID != "acct-gleipnir" || seen.Name != "gleipnir" || seen.Role != string(accounts.RoleOperator) {
		t.Errorf("principal = %+v, want the token's Account with its stored role", seen)
	}
}

// The founding admin is an Account like any other on this path: its bootstrap
// token resolves to the stored row, so audit attributes it by ID and current
// role rather than as a special case.
func TestAuthenticator_FirstAdminTokenResolvesToTheStoredAccount(t *testing.T) {
	a := NewAuthenticator(&fakeVerifier{acct: storedFirstAdmin(), valid: testCredential})

	code, seen := authRequest(t, a, testCredential)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if seen.ID != "acct-first-admin" || seen.Name != testAdminName || seen.Role != string(accounts.RoleAdmin) {
		t.Errorf("principal = %+v, want the stored founding admin as admin", seen)
	}
}

// A role change takes effect on the next request: the role is read through the
// verifier at authentication time, never cached in the Authenticator.
func TestAuthenticator_RoleChangeTakesEffectImmediately(t *testing.T) {
	v := &fakeVerifier{acct: storedFirstAdmin(), valid: testCredential}
	a := NewAuthenticator(v)

	if _, seen := authRequest(t, a, testCredential); seen.Role != string(accounts.RoleAdmin) {
		t.Fatalf("initial role = %q, want admin", seen.Role)
	}

	v.acct.Role = accounts.RoleViewer // demoted out from under the process
	_, seen := authRequest(t, a, testCredential)
	if seen.Role != string(accounts.RoleViewer) {
		t.Errorf("role after demotion = %q, want viewer without a restart", seen.Role)
	}
}

// Every failure mode produces the same generic 401 and never reaches the
// handler, so the boundary is not an oracle telling a caller which part of
// their credential was wrong — or that it was ever real.
func TestAuthenticator_EveryFailureIsTheSameGeneric401(t *testing.T) {
	valid := &fakeVerifier{acct: storedFirstAdmin(), valid: testCredential}
	disabledAcct := storedFirstAdmin()
	disabledAcct.Enabled = false

	cases := []struct {
		label      string
		verifier   *fakeVerifier
		credential string
	}{
		{"no credential", valid, ""},
		{"wrong credential", valid, accounts.TokenPrefix + "deadbeef.wrong"},
		{"not token-shaped", valid, "not-a-token"},
		{"disabled account", &fakeVerifier{acct: disabledAcct, valid: testCredential}, testCredential},
		{"store unreadable", &fakeVerifier{acct: storedFirstAdmin(), valid: testCredential, err: errors.New("db down")}, testCredential},
	}

	bodies := make(map[string]bool)
	for _, c := range cases {
		a := NewAuthenticator(c.verifier)
		var seen capabilityPrincipal
		h := a.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			p, _ := PrincipalFromContext(r.Context())
			seen = capabilityPrincipal{ID: p.AccountID, Name: p.Account, Role: p.Role}
		}))
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		if c.credential != "" {
			req.Header.Set("Authorization", "Bearer "+c.credential)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("[%s] status = %d, want 401", c.label, rec.Code)
		}
		if seen != (capabilityPrincipal{}) {
			t.Errorf("[%s] handler was reached with %+v", c.label, seen)
		}
		if rec.Header().Get("WWW-Authenticate") != "Bearer" {
			t.Errorf("[%s] missing WWW-Authenticate: Bearer", c.label)
		}
		bodies[rec.Body.String()] = true
	}

	if len(bodies) != 1 {
		t.Errorf("failure bodies differ across cases (%v); every rejection must be byte-identical", bodies)
	}
}

// A malformed Authorization header never reaches the verifier at all — there
// is nothing to check, and consulting the store for it would let an
// unauthenticated caller drive store reads.
func TestAuthenticator_MalformedHeaderNeverReachesTheVerifier(t *testing.T) {
	v := &fakeVerifier{acct: storedFirstAdmin(), valid: testCredential}
	a := NewAuthenticator(v)

	for _, header := range []string{"", "Basic dXNlcjpwYXNz", "Bearer", "Bearer ", "bearer " + testCredential} {
		req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		a.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Errorf("handler reached for header %q", header)
		})).ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("header %q: status = %d, want 401", header, rec.Code)
		}
	}
	if len(v.seen) != 0 {
		t.Errorf("the verifier was consulted for malformed headers: %v", v.seen)
	}
}
