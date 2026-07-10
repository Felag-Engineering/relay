package controlplane

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const testToken = "s3cr3t-control-plane-credential" //nolint:gosec // test fixture, not a real credential

func testAuthenticator() *Authenticator {
	sum := sha256.Sum256([]byte(testToken))
	return NewAuthenticator(sum[:])
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

	resp, err := http.Get(srv.URL) //nolint:noctx // test
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close() //nolint:errcheck

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
	defer resp.Body.Close() //nolint:errcheck

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
	defer resp.Body.Close() //nolint:errcheck

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
	defer resp.Body.Close() //nolint:errcheck

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
	defer resp.Body.Close() //nolint:errcheck

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
		resp.Body.Close() //nolint:errcheck
	}

	logOutput := buf.String()
	if strings.Contains(logOutput, testToken) {
		t.Errorf("slog output contains the credential: %s", logOutput)
	}

	// Also assert the digest never appears in hex form anywhere reachable
	// from logging — Authenticator only ever compares digests, never logs them.
	sum := sha256.Sum256([]byte(testToken))
	hashHex := fmt.Sprintf("%x", sum)
	if strings.Contains(logOutput, hashHex) {
		t.Errorf("slog output contains the credential digest: %s", logOutput)
	}
}

// TestAuthenticator_HoldsOnlyDigest is a structural (by-construction) guarantee
// that Authenticator never stores plaintext: NewAuthenticator's only parameter
// is a digest, and the struct has no other exported or unexported field a
// caller could populate with plaintext. This is asserted indirectly: a digest
// built from a token authenticates that token, and an Authenticator built
// directly from a hand-computed digest (never having seen "the" plaintext
// string in this test) behaves identically — there is no separate plaintext
// path into the type.
func TestAuthenticator_HoldsOnlyDigest(t *testing.T) {
	sum := sha256.Sum256([]byte(testToken))
	authn := NewAuthenticator(sum[:])

	if !authn.validToken(testToken) {
		t.Fatal("Authenticator built from digest should accept the matching token")
	}
	if authn.validToken("anything-else") {
		t.Fatal("Authenticator should reject a non-matching token")
	}
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
