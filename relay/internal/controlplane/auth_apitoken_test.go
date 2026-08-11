package controlplane

import (
	"context"
	"net/http"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
)

// fakeVerifier is the narrow TokenVerifier the authenticator needs. It records
// every credential it was asked about, so a test can assert which credentials
// reach the token path at all — the routing property, not just the outcome.
type fakeVerifier struct {
	acct  accounts.Account
	valid string
	seen  []string
}

func (f *fakeVerifier) Verify(_ context.Context, credential string) (accounts.Account, accounts.APIToken, error) {
	f.seen = append(f.seen, credential)
	if credential != f.valid {
		return accounts.Account{}, accounts.APIToken{}, accounts.ErrTokenInvalid
	}
	return f.acct, accounts.APIToken{ID: "tok-1", AccountID: f.acct.ID}, nil
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

const testAPIToken = accounts.TokenPrefix + "0123456789abcdef.a-secret" //nolint:gosec // test fixture, not a real credential

// A valid API Token authenticates as its Account, with that Account's ID and
// current role — the same Principal shape the seeded credential produces, so
// every surface downstream is unaware of which credential kind was presented.
func TestAuthenticator_APITokenResolvesToItsAccount(t *testing.T) {
	v := &fakeVerifier{acct: operatorAccount(), valid: testAPIToken}
	a := NewAuthenticator(digestOf(t, testCredential), WithAPITokens(v))

	code, seen := authRequest(t, a, testAPIToken)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if seen.ID != "acct-gleipnir" || seen.Name != "gleipnir" || seen.Role != string(accounts.RoleOperator) {
		t.Errorf("principal = %+v, want the token's Account with its stored role", seen)
	}
}

// A rejected token gets the same generic 401 as everything else, and the
// handler is never reached.
func TestAuthenticator_InvalidAPITokenIsRefused(t *testing.T) {
	v := &fakeVerifier{acct: operatorAccount(), valid: testAPIToken}
	a := NewAuthenticator(digestOf(t, testCredential), WithAPITokens(v))

	code, seen := authRequest(t, a, accounts.TokenPrefix+"deadbeef.wrong")
	if code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
	if seen != (capabilityPrincipal{}) {
		t.Errorf("handler saw principal %+v for a refused credential", seen)
	}
}

// Fail closed: without a verifier wired, a token-shaped credential is refused
// outright rather than falling through to the seeded comparison. A deployment
// that cannot check tokens must not accept things shaped like them.
func TestAuthenticator_TokenShapedCredentialWithoutVerifierIsRefused(t *testing.T) {
	a := NewAuthenticator(digestOf(t, testCredential))

	if code, _ := authRequest(t, a, testAPIToken); code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", code)
	}
	// The seeded path is untouched by the token routing.
	if code, _ := authRequest(t, a, testCredential); code != http.StatusOK {
		t.Errorf("seeded credential status = %d, want 200", code)
	}
}

// The two credential kinds are routed by prefix, never tried in turn: a
// non-token credential must never reach the verifier, and a token-shaped one
// must never be compared against the seeded digest.
//
// This is what keeps a failure's cost from depending on which check rejected
// it, and stops a near-miss on one kind being scored against the other. The
// documented consequence — a seeded credential beginning with `glp_` never
// authenticates — is asserted here so the constraint is visible rather than
// discovered in production.
func TestAuthenticator_CredentialKindsAreRoutedNotTried(t *testing.T) {
	v := &fakeVerifier{acct: operatorAccount(), valid: testAPIToken}
	a := NewAuthenticator(digestOf(t, testCredential), WithAPITokens(v))

	if code, _ := authRequest(t, a, testCredential); code != http.StatusOK {
		t.Fatalf("seeded credential status = %d, want 200", code)
	}
	if len(v.seen) != 0 {
		t.Errorf("the verifier was consulted for a non-token credential: %v", v.seen)
	}

	if code, _ := authRequest(t, a, testAPIToken); code != http.StatusOK {
		t.Fatalf("api token status = %d, want 200", code)
	}
	if len(v.seen) != 1 || v.seen[0] != testAPIToken {
		t.Errorf("verifier saw %v, want exactly the presented token", v.seen)
	}

	// A seeded credential that happens to be token-shaped is refused, because
	// it is only ever routed to the verifier.
	tokenShapedSeed := accounts.TokenPrefix + "seeded-credential" //nolint:gosec // test fixture
	b := NewAuthenticator(digestOf(t, tokenShapedSeed), WithAPITokens(v))
	if code, _ := authRequest(t, b, tokenShapedSeed); code != http.StatusUnauthorized {
		t.Errorf("token-shaped seeded credential status = %d, want 401 (documented constraint)", code)
	}
}

// An API Token for a disabled Account is refused. The authenticator does not
// re-check Enabled itself — TokenService.Verify already does, and duplicating
// the check would create two places for the rule to drift. This pins that the
// composed behaviour is correct.
func TestAuthenticator_APITokenForDisabledAccountIsRefused(t *testing.T) {
	disabled := operatorAccount()
	disabled.Enabled = false
	v := &disablingVerifier{acct: disabled}
	a := NewAuthenticator(digestOf(t, testCredential), WithAPITokens(v))

	if code, _ := authRequest(t, a, testAPIToken); code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", code)
	}
}

// disablingVerifier models a real TokenService: it refuses a disabled
// Account's token with the same generic error as any other failure.
type disablingVerifier struct{ acct accounts.Account }

func (d *disablingVerifier) Verify(context.Context, string) (accounts.Account, accounts.APIToken, error) {
	if !d.acct.Enabled {
		return accounts.Account{}, accounts.APIToken{}, accounts.ErrTokenInvalid
	}
	return d.acct, accounts.APIToken{}, nil
}
