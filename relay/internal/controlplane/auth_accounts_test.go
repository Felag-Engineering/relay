package controlplane

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
)

// fakeAccounts is the narrow AccountReader the authenticator needs.
type fakeAccounts struct {
	acct     accounts.Account
	getErr   error
	touched  []string
	touchErr error
}

func (f *fakeAccounts) GetByName(_ context.Context, name string) (accounts.Account, error) {
	if f.getErr != nil {
		return accounts.Account{}, f.getErr
	}
	if accounts.NormalizeName(name) != accounts.NormalizeName(f.acct.Name) {
		return accounts.Account{}, accounts.ErrNotFound
	}
	return f.acct, nil
}

func (f *fakeAccounts) TouchLastSeen(_ context.Context, id string, _ time.Time) error {
	f.touched = append(f.touched, id)
	return f.touchErr
}

const testCredential = "test-credential"

func digestOf(t *testing.T, s string) []byte {
	t.Helper()
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// authRequest drives one request through the middleware and returns the status
// plus the Principal the handler saw (zero value if it was never reached).
func authRequest(t *testing.T, a *Authenticator, token string) (int, capabilityPrincipal) {
	t.Helper()
	var seen capabilityPrincipal
	h := a.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFromContext(r.Context())
		if ok {
			seen = capabilityPrincipal{ID: p.AccountID, Name: p.Account, Role: p.Role}
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, seen
}

type capabilityPrincipal struct{ ID, Name, Role string }

func enabledFoundingAdmin() accounts.Account {
	return accounts.Account{
		ID:      "acct-founding",
		Name:    accounts.FoundingAdminName,
		Kind:    accounts.KindHuman,
		Role:    accounts.RoleAdmin,
		Enabled: true,
	}
}

// Acceptance: "The seeded credential resolves to the founding admin Account;
// audit shows it as such" — the Principal carries the stored ID and the
// stored role, not a hardcoded string.
func TestAuthenticator_ResolvesToStoredFoundingAdmin(t *testing.T) {
	store := &fakeAccounts{acct: enabledFoundingAdmin()}
	a := NewAuthenticator(digestOf(t, testCredential), WithAccounts(store))

	code, seen := authRequest(t, a, testCredential)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if seen.ID != "acct-founding" {
		t.Errorf("AccountID = %q, want the stored Account's ID", seen.ID)
	}
	if seen.Name != accounts.FoundingAdminName || seen.Role != string(accounts.RoleAdmin) {
		t.Errorf("principal = %+v, want the founding admin as admin", seen)
	}
	if len(store.touched) != 1 || store.touched[0] != "acct-founding" {
		t.Errorf("TouchLastSeen calls = %v, want one for the resolved Account", store.touched)
	}
}

// Acceptance: "a disabled Account authenticates nowhere" — and it fails with
// the SAME generic 401 as a wrong credential, so the response is not an oracle
// telling an attacker their credential is real.
func TestAuthenticator_DisabledAccountIsRefused(t *testing.T) {
	disabled := enabledFoundingAdmin()
	disabled.Enabled = false
	a := NewAuthenticator(digestOf(t, testCredential), WithAccounts(&fakeAccounts{acct: disabled}))

	code, seen := authRequest(t, a, testCredential)
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a disabled Account", code)
	}
	if seen != (capabilityPrincipal{}) {
		t.Errorf("handler was reached with %+v; a disabled Account must never reach the handler", seen)
	}

	// Byte-identical to a wrong credential's rejection.
	wrongCode, _ := authRequest(t, NewAuthenticator(digestOf(t, testCredential)), "not-the-credential")
	if wrongCode != code {
		t.Errorf("disabled-Account status %d != wrong-credential status %d; the two must be indistinguishable", code, wrongCode)
	}
}

// A role change takes effect on the next request: the role is read from the
// store at authentication time, never cached at startup.
func TestAuthenticator_RoleChangeTakesEffectImmediately(t *testing.T) {
	store := &fakeAccounts{acct: enabledFoundingAdmin()}
	a := NewAuthenticator(digestOf(t, testCredential), WithAccounts(store))

	if _, seen := authRequest(t, a, testCredential); seen.Role != string(accounts.RoleAdmin) {
		t.Fatalf("initial role = %q, want admin", seen.Role)
	}

	store.acct.Role = accounts.RoleViewer // demoted out from under the process
	_, seen := authRequest(t, a, testCredential)
	if seen.Role != string(accounts.RoleViewer) {
		t.Errorf("role after demotion = %q, want viewer without a restart", seen.Role)
	}
}

// Fail closed: if the Account cannot be read at all, the request is refused
// rather than falling back to a hardcoded admin identity.
func TestAuthenticator_UnreadableAccountFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		label string
		store *fakeAccounts
	}{
		{"store error", &fakeAccounts{acct: enabledFoundingAdmin(), getErr: errors.New("db down")}},
		{"account missing", &fakeAccounts{acct: accounts.Account{Name: "someone-else", Enabled: true}}},
	} {
		a := NewAuthenticator(digestOf(t, testCredential), WithAccounts(tc.store))
		code, seen := authRequest(t, a, testCredential)
		if code != http.StatusUnauthorized {
			t.Errorf("[%s] status = %d, want 401", tc.label, code)
		}
		if seen != (capabilityPrincipal{}) {
			t.Errorf("[%s] handler reached with %+v, want no principal", tc.label, seen)
		}
	}
}

// A last-seen write failure must never fail the request it accompanies — the
// caller has already authenticated, and last-seen is advisory.
func TestAuthenticator_TouchFailureDoesNotFailTheRequest(t *testing.T) {
	store := &fakeAccounts{acct: enabledFoundingAdmin(), touchErr: errors.New("write failed")}
	a := NewAuthenticator(digestOf(t, testCredential), WithAccounts(store))

	code, seen := authRequest(t, a, testCredential)
	if code != http.StatusOK {
		t.Errorf("status = %d, want 200 despite a last-seen write failure", code)
	}
	if seen.Name != accounts.FoundingAdminName {
		t.Errorf("principal = %+v, want the founding admin", seen)
	}
}

// Without a store wired, the authenticator keeps its pre-Account behavior, so
// existing call sites and tests are unaffected.
func TestAuthenticator_WithoutAccountsUsesStaticFoundingAdmin(t *testing.T) {
	a := NewAuthenticator(digestOf(t, testCredential))
	code, seen := authRequest(t, a, testCredential)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if seen.Name != accounts.FoundingAdminName || seen.Role != string(accounts.RoleAdmin) {
		t.Errorf("principal = %+v, want the static founding admin", seen)
	}
	if seen.ID != "" {
		t.Errorf("AccountID = %q, want empty without a store", seen.ID)
	}
}
