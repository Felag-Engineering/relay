package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/consoleauth"
)

// consolesession_test.go covers the browser credential lane (#418) and, since
// #459, its REACH: a Console session cookie authenticates the Console and
// nothing else on this listener.
//
// The predicates here are stand-ins with the same shape as package console's
// real ones, because console imports controlplane and not the other way round.
// What these tests pin is that the BOUNDARY consults a scope predicate at all,
// and refuses when it says no. That the real predicate covers exactly the
// Console's route table — and no more — is asserted in package console, next
// to the table it is a claim about (console.TestSessionScope_*).

// -----------------------------------------------------------------------
// Harness
// -----------------------------------------------------------------------

const testSessionID = "console-session-fixture"

// fakeSessionResolver stands in for *consoleauth.Service on the browser lane.
// It models the real resolver's contract: one indistinguishable error for
// every failure, and the Account read at call time so a test can mutate it
// between requests.
type fakeSessionResolver struct {
	acct  accounts.Account
	valid string
	seen  []string
}

func (f *fakeSessionResolver) Resolve(_ context.Context, id consoleauth.SessionID) (consoleauth.Session, accounts.Account, error) {
	f.seen = append(f.seen, id.Reveal())
	if id.Reveal() != f.valid || !f.acct.Enabled {
		return consoleauth.Session{}, accounts.Account{}, errors.New("no such session")
	}
	return consoleauth.Session{AccountID: f.acct.ID}, f.acct, nil
}

// testConsoleAuthenticator wires both lanes: the API Token lane (testToken)
// and the browser lane (testSessionID), with predicates shaped like the ones
// the composition root takes from package console.
func testConsoleAuthenticator() (*Authenticator, *fakeSessionResolver) {
	resolver := &fakeSessionResolver{acct: storedFoundingAdmin(), valid: testSessionID}
	a := NewAuthenticator(
		&fakeVerifier{acct: storedFoundingAdmin(), valid: testToken},
		WithConsoleSessions(resolver, ConsoleSessionOptions{
			Public: func(r *http.Request) bool { return r.URL.Path == "/console/login" },
			Scope: func(r *http.Request) bool {
				return r.URL.Path == "/console" || strings.HasPrefix(r.URL.Path, "/console/")
			},
			Unauthorized: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusSeeOther)
			}),
		}),
	)
	return a, resolver
}

// consoleRequest drives one cookie-bearing request through the middleware and
// reports the status plus the Principal the handler saw. reached is false when
// the middleware refused before the handler ran.
func consoleRequest(t *testing.T, a *Authenticator, method, target string) (status int, p capability.Principal, reached bool) {
	t.Helper()
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		p, _ = PrincipalFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(method, target, nil)
	req.AddCookie(&http.Cookie{Name: consoleauth.SessionCookieName, Value: testSessionID})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, p, reached
}

// -----------------------------------------------------------------------
// Reach (#459)
// -----------------------------------------------------------------------

// The finding, pinned: an admin's valid Console session cookie does NOT
// authenticate the Control API's dispatch routes. Before #459 it did — the
// lane was chosen by request shape alone (no Authorization header + a Console
// mounted), so the cookie the `__Host-` prefix forces onto Path=/ was a
// fleet-wide Raw Exec credential on POST /api/v1/raw-exec.
func TestConsoleSession_DoesNotAuthenticateTheControlAPI(t *testing.T) {
	offConsole := []string{
		"/api/v1/operations",
		"/api/v1/raw-exec",
		"/api/v1/accounts",
		"/mcp",
		"/metrics",
		// A path that CLEANS to one of the above — "/console/../api/v1/..."
		// — is refused too, but by the predicate rather than by the boundary:
		// the stand-in here is a naive prefix match on purpose, so that this
		// test pins only "the boundary asks", and the normalisation is
		// asserted against the real predicate in package console.
	}
	for _, target := range offConsole {
		t.Run(target, func(t *testing.T) {
			a, resolver := testConsoleAuthenticator()
			status, p, reached := consoleRequest(t, a, http.MethodPost, target)
			if reached {
				t.Fatalf("a Console cookie authenticated %s as %s (%s) — the cookie is a credential for the Console, not for this surface",
					target, p.Account, p.Role)
			}
			if status == http.StatusOK {
				t.Errorf("status = %d, want a refusal", status)
			}
			if len(resolver.seen) != 0 {
				t.Errorf("the session was resolved %d time(s) off-scope; an out-of-scope cookie must not even be read", len(resolver.seen))
			}
		})
	}
}

// The other half, and the one that must not regress when v0.7.0 adds the
// execution composer: the cookie still authenticates the Console itself,
// including the routes ADR-0026 will mount under the same prefix.
func TestConsoleSession_AuthenticatesTheConsole(t *testing.T) {
	onConsole := []struct{ method, target string }{
		{http.MethodGet, "/console/"},
		{http.MethodGet, "/console"}, // net/http redirects this to /console/
		{http.MethodGet, "/console/nodes/node-1"},
		{http.MethodPost, "/console/logout"},
		// v0.7.0's execution surface (ADR-0026): mounted under the same
		// prefix, so a path-scoped cookie still reaches it.
		{http.MethodGet, "/console/run"},
		{http.MethodPost, "/console/run/apply"},
	}
	for _, c := range onConsole {
		t.Run(c.target, func(t *testing.T) {
			a, _ := testConsoleAuthenticator()
			status, p, reached := consoleRequest(t, a, c.method, c.target)
			if !reached {
				t.Fatalf("a valid Console cookie was refused on %s: status = %d", c.target, status)
			}
			if p.Role != string(accounts.RoleAdmin) || p.Account != accounts.FoundingAdminName {
				t.Errorf("principal = %s (%s), want %s (admin)", p.Account, p.Role, accounts.FoundingAdminName)
			}
			if p.AuthMethod != capability.AuthMethodConsoleSession {
				t.Errorf("AuthMethod = %q, want %q", p.AuthMethod, capability.AuthMethodConsoleSession)
			}
		})
	}
}

// A bearer header still wins outright, on the Console's own paths too: the
// lanes are routed structurally, never tried in turn (ADR-0023, #299), and
// scoping the cookie lane does not turn a cookie into a fallback.
func TestConsoleSession_BearerHeaderIsNeverResolvedAsASession(t *testing.T) {
	a, resolver := testConsoleAuthenticator()

	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/console/", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	req.AddCookie(&http.Cookie{Name: consoleauth.SessionCookieName, Value: testSessionID})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Error("a bad bearer header fell back to the session cookie")
	}
	if len(resolver.seen) != 0 {
		t.Errorf("the session resolver saw %d request(s) carrying a bearer header", len(resolver.seen))
	}
}

// The Scope predicate is required, exactly like Public: defaulting it to "the
// whole listener" is the one default it must never have, and a wiring mistake
// must fail at construction in the composition root rather than serve a
// control-plane-wide cookie.
func TestWithConsoleSessions_PanicsWithoutAScope(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("WithConsoleSessions accepted a nil Scope predicate")
		}
		if !strings.Contains(r.(string), "Scope") {
			t.Errorf("panic = %v, want it to name the missing Scope predicate", r)
		}
	}()
	NewAuthenticator(
		&fakeVerifier{acct: storedFoundingAdmin(), valid: testToken},
		WithConsoleSessions(&fakeSessionResolver{}, ConsoleSessionOptions{
			Public:       func(*http.Request) bool { return false },
			Unauthorized: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}),
		}),
	)
}
