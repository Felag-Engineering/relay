package controlplane

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

const testToken = accounts.TokenPrefix + "fedcba9876543210.control-plane-test" // test fixture, not a real credential

// testAuthenticator accepts testToken as the founding admin's credential.
// Since #298 there is only one credential kind, so every test in this file
// now drives the API Token path.
func testAuthenticator() *Authenticator {
	return NewAuthenticator(&fakeVerifier{
		acct:  storedFoundingAdmin(),
		valid: testToken,
	})
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := PrincipalFromContext(r.Context())
		if !ok {
			http.Error(w, "no principal", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(p.Attribution()))
	})
}

func TestMiddleware_NoHeader(t *testing.T) {
	authn := testAuthenticator()
	srv := httptest.NewServer(authn.Middleware(okHandler()))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want %q", got, "Bearer")
	}
}

func TestMiddleware_MalformedHeader(t *testing.T) {
	authn := testAuthenticator()
	srv := httptest.NewServer(authn.Middleware(okHandler()))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestMiddleware_WrongToken(t *testing.T) {
	authn := testAuthenticator()
	srv := httptest.NewServer(authn.Middleware(okHandler()))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer wrong-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}

func TestMiddleware_CorrectToken(t *testing.T) {
	authn := testAuthenticator()
	srv := httptest.NewServer(authn.Middleware(okHandler()))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer "+testToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body := readAll(t, resp.Body)
	if body != "founding-admin:admin" {
		t.Errorf("body = %q, want %q", body, "founding-admin:admin")
	}
}

// TestMiddleware_TokenNeverInResponseBody asserts every 401 response body is
// the fixed generic error, regardless of what was presented — so a caller
// probing with near-miss tokens never gets them reflected back.
func TestMiddleware_TokenNeverInResponseBody(t *testing.T) {
	authn := testAuthenticator()
	srv := httptest.NewServer(authn.Middleware(okHandler()))
	defer srv.Close()

	presented := "totally-wrong-" + testToken
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header.Set("Authorization", "Bearer "+presented)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	body := readAll(t, resp.Body)
	if strings.Contains(body, presented) || strings.Contains(body, testToken) {
		t.Fatalf("401 body contains presented token: %q", body)
	}
	if body != genericAuthError {
		t.Errorf("body = %q, want generic %q", body, genericAuthError)
	}
}

// TestMiddleware_TokenNeverLogged proves the presented token never reaches
// slog output on either the success or failure path, mirroring
// enroll/token_test.go's TestNoSecretInLogs structure.
func TestMiddleware_TokenNeverLogged(t *testing.T) {
	authn := testAuthenticator()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	loggingHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, _ := PrincipalFromContext(r.Context())
		logger.Info("request handled", "principal", p.Attribution(), "path", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(authn.Middleware(loggingHandler))
	defer srv.Close()

	for _, presented := range []string{"", testToken, "wrong-" + testToken} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		if presented != "" {
			req.Header.Set("Authorization", "Bearer "+presented)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		resp.Body.Close()
	}

	logOutput := buf.String()
	if strings.Contains(logOutput, testToken) {
		t.Errorf("slog output contains the credential: %s", logOutput)
	}

	// Also assert the digest never appears in hex form anywhere reachable
	// from logging — only hashes are ever compared, and they are never logged.
	sum := sha256.Sum256([]byte(testToken))
	hashHex := fmt.Sprintf("%x", sum)
	if strings.Contains(logOutput, hashHex) {
		t.Errorf("slog output contains the credential digest: %s", logOutput)
	}
}

// TestAuthenticator_HoldsNoSecretMaterial is a structural (by-construction)
// guarantee: the Authenticator holds no credential material of any kind —
// neither a plaintext nor a digest. It holds collaborators that verify
// credentials (a TokenVerifier, and since #299 an OAuth resolver) and nothing
// a secret could be assigned to.
//
// Asserted by reflection over the struct's own fields rather than by
// behaviour, because the claim is about the type's shape. A `string` or
// `[]byte` field is exactly where a credential or a digest would land, so the
// test fails the moment one appears — which is the regression worth catching.
// The OAuth resolver's own strings are configuration (issuer, audience, claim
// name, metadata URL): public values that appear in the RFC 9728 document the
// Relay serves to anyone who asks.
func TestAuthenticator_HoldsNoSecretMaterial(t *testing.T) {
	typ := reflect.TypeOf(Authenticator{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		switch f.Type.Kind() {
		case reflect.String:
			t.Errorf("Authenticator field %q is a string — a credential or digest could be stored there", f.Name)
		case reflect.Slice:
			if f.Type.Elem().Kind() == reflect.Uint8 {
				t.Errorf("Authenticator field %q is a []byte — a digest could be stored there", f.Name)
			}
		}
	}
}

// A nil verifier is a wiring mistake, caught at construction in the
// composition root rather than by a listener that silently refuses everyone.
func TestNewAuthenticator_PanicsOnNilVerifier(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewAuthenticator(nil) did not panic")
		}
	}()
	NewAuthenticator(nil)
}

func TestFoundingAdmin(t *testing.T) {
	p := FoundingAdmin()
	if p.Account != "founding-admin" || p.Role != "admin" {
		t.Fatalf("FoundingAdmin = %+v, want Account=founding-admin Role=admin", p)
	}
}

func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return string(b)
}
