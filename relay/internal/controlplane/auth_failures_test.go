package controlplane

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/metrics"
)

type authRefusal struct {
	surface   metrics.AuthSurface
	presented bool
}

type recordingCounter struct {
	mu    sync.Mutex
	calls []authRefusal
}

func (c *recordingCounter) IncAuthRefusal(s metrics.AuthSurface, presented bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, authRefusal{s, presented})
}

func countingAuthenticator(c AuthFailureCounter) *Authenticator {
	return NewAuthenticator(
		&fakeVerifier{acct: storedFirstAdmin(), valid: testToken},
		WithConsoleSessions(&fakeSessionResolver{acct: storedFirstAdmin(), valid: testSessionID}, testConsoleSessionOptions()),
		WithAuthFailureCounter(c),
	)
}

func serveThrough(a *Authenticator, req *http.Request) *httptest.ResponseRecorder {
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMiddleware_CountsEachRefusalBySurface(t *testing.T) {
	cookie := func(value string) *http.Cookie {
		return &http.Cookie{Name: consoleauth.SessionCookieName, Value: value}
	}
	tests := []struct {
		name   string
		method string
		path   string
		header string // Authorization value; empty sets none
		cookie *http.Cookie
		want   authRefusal
	}{
		{"control api, no header", http.MethodGet, "/api/v1/ping", "", nil, authRefusal{metrics.AuthSurfaceControlAPI, false}},
		{"mcp, unknown bearer", http.MethodPost, "/mcp", "Bearer not-a-real-token", nil, authRefusal{metrics.AuthSurfaceMCP, true}},
		{"console, no cookie", http.MethodGet, "/console/fleet", "", nil, authRefusal{metrics.AuthSurfaceConsole, false}},
		{"console, unknown session", http.MethodGet, "/console/fleet", "", cookie("not-a-session"), authRefusal{metrics.AuthSurfaceConsole, true}},
		{"console, wrong bearer", http.MethodGet, "/console/fleet", "Bearer wrong", nil, authRefusal{metrics.AuthSurfaceConsole, true}},
		{"metrics, no header", http.MethodGet, "/metrics", "", nil, authRefusal{metrics.AuthSurfaceOther, false}},
		{"control api, cookie only: off-scope cookie is not a credential", http.MethodGet, "/api/v1/ping", "", cookie(testSessionID), authRefusal{metrics.AuthSurfaceControlAPI, false}},
		{"control api, non-Bearer scheme", http.MethodGet, "/api/v1/ping", "Basic x", nil, authRefusal{metrics.AuthSurfaceControlAPI, false}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			counter := &recordingCounter{}
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			if tc.cookie != nil {
				req.AddCookie(tc.cookie)
			}
			if rec := serveThrough(countingAuthenticator(counter), req); rec.Code == http.StatusOK {
				t.Fatalf("request was admitted, want a refusal")
			}
			if len(counter.calls) != 1 || counter.calls[0] != tc.want {
				t.Fatalf("recorded %+v, want exactly [%+v]", counter.calls, tc.want)
			}
		})
	}
}

func TestMiddleware_DoesNotCountWhatItDoesNotRefuse(t *testing.T) {
	tests := []struct {
		name string
		req  func() *http.Request
	}{
		{"a valid token", func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/ping", nil)
			r.Header.Set("Authorization", "Bearer "+testToken)
			return r
		}},
		{"a valid session", func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/console/fleet", nil)
			r.AddCookie(&http.Cookie{Name: consoleauth.SessionCookieName, Value: testSessionID})
			return r
		}},
		{"the public sign-in page", func() *http.Request {
			return httptest.NewRequest(http.MethodGet, "/console/login", nil)
		}},
		{"a malformed assertion after a valid token", func() *http.Request {
			r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
			r.Header.Set("Authorization", "Bearer "+testToken)
			r.Header.Set(HeaderOnBehalfOf, strings.Repeat("x", audit.MaxAssertedFieldBytes+1))
			return r
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			counter := &recordingCounter{}
			serveThrough(countingAuthenticator(counter), tc.req())
			if len(counter.calls) != 0 {
				t.Fatalf("recorded %+v, want no refusals", counter.calls)
			}
		})
	}
}

func TestMiddleware_NilCounterIsNoOp(t *testing.T) {
	rec := serveThrough(testAuthenticator(), httptest.NewRequest(http.MethodGet, "/api/v1/ping", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
