package controlplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// requestWithHeaders drives one authenticated request carrying headers and
// returns the status plus the assertions the handler saw.
func requestWithHeaders(t *testing.T, headers map[string]string) (int, capability.Assertions) {
	t.Helper()
	a := NewAuthenticator(&fakeVerifier{acct: storedFoundingAdmin(), valid: testCredential})

	var seen capability.Assertions
	h := a.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = capability.AssertionsFromContext(r.Context())
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+testCredential)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, seen
}

func TestAssertions_HeadersReachTheHandler(t *testing.T) {
	code, seen := requestWithHeaders(t, map[string]string{
		HeaderOnBehalfOf:  "ops-team",
		HeaderTraceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		HeaderSessionRef:  "conv_01JQ8Z9K2X",
		HeaderChangeRef:   "CHG-4821",
	})
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	want := capability.Assertions{
		OnBehalfOf:  "ops-team",
		Traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
		SessionRef:  "conv_01JQ8Z9K2X",
		ChangeRef:   "CHG-4821",
	}
	if seen != want {
		t.Errorf("assertions = %+v, want %+v", seen, want)
	}
}

// Asserting nothing is the common case and must be unremarkable.
func TestAssertions_AbsentHeadersAreZero(t *testing.T) {
	code, seen := requestWithHeaders(t, nil)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if !seen.IsZero() {
		t.Errorf("assertions = %+v, want zero", seen)
	}
}

// Acceptance: "Oversized asserted fields are truncated/refused per a
// documented bound." We refuse — a truncated join key joins to nothing, so
// silently shortening one produces a record that looks complete and is not.
func TestAssertions_MalformedHeadersAreRefused(t *testing.T) {
	long := strings.Repeat("x", audit.MaxAssertedFieldBytes+1)

	for _, c := range []struct{ label, header, value string }{
		{"oversized on_behalf_of", HeaderOnBehalfOf, long},
		{"oversized traceparent", HeaderTraceparent, long},
		{"oversized session_ref", HeaderSessionRef, long},
		{"oversized change_ref", HeaderChangeRef, long},
	} {
		code, seen := requestWithHeaders(t, map[string]string{c.header: c.value})
		if code != http.StatusBadRequest {
			t.Errorf("[%s] status = %d, want 400", c.label, code)
		}
		if !seen.IsZero() {
			t.Errorf("[%s] the handler was reached with %+v", c.label, seen)
		}
	}
}

// A 400 for a malformed assertion must never come *before* authentication:
// answering 400 to an unauthenticated caller would tell them their credential
// was fine, which is exactly the oracle the generic 401 exists to prevent.
func TestAssertions_AuthenticationIsCheckedFirst(t *testing.T) {
	a := NewAuthenticator(&fakeVerifier{acct: storedFoundingAdmin(), valid: testCredential})
	h := a.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("handler reached with a bad credential")
	}))

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer wrong-credential")
	req.Header.Set(HeaderOnBehalfOf, strings.Repeat("x", audit.MaxAssertedFieldBytes+1))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 — a malformed assertion must not preempt the auth check", rec.Code)
	}
}

// The verified lane carries which credential acted, so "revoke the compromised
// one" is a targeted act rather than revoking all of an Account's tokens.
func TestAssertions_PrincipalCarriesTheTokenID(t *testing.T) {
	a := NewAuthenticator(&fakeVerifier{acct: storedFoundingAdmin(), valid: testCredential})

	var seen capability.Principal
	h := a.Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen, _ = PrincipalFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/api/v1/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+testCredential)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if seen.TokenID != "tok-1" {
		t.Errorf("Principal.TokenID = %q, want the verifying token's id", seen.TokenID)
	}
	if seen.AccountID != "acct-founding" {
		t.Errorf("Principal.AccountID = %q, want the stored Account's id", seen.AccountID)
	}
}
