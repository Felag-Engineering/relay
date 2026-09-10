package controlplane

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

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

// testSessionAuthenticatedAt is a fixed, non-zero moment so a test can assert
// the SESSION that crossed the boundary is the resolver's, and not a
// zero-value stand-in a handler could not tell apart from "no session".
var testSessionAuthenticatedAt = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

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
	// Method and AuthenticatedAt are set to distinctive, non-zero values so a
	// test can tell "the boundary carried the resolver's actual Session"
	// apart from "the boundary carried a zero-value stand-in".
	return consoleauth.Session{
		AccountID:       f.acct.ID,
		Method:          consoleauth.MethodPassword,
		AuthenticatedAt: testSessionAuthenticatedAt,
	}, f.acct, nil
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

// -----------------------------------------------------------------------
// The session seam (#477)
// -----------------------------------------------------------------------

// consoleSessionRequest is consoleRequest's twin for tests that need the
// ConsoleSession the boundary injected, not just the Principal.
func consoleSessionRequest(t *testing.T, a *Authenticator, method, target string, cookies ...*http.Cookie) (status int, cs ConsoleSession, csOK, reached bool) {
	t.Helper()
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		cs, csOK = ConsoleSessionFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(method, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, cs, csOK, reached
}

// TestConsoleSession_TheResolvedSessionReachesTheHandler pins #477's fix: the
// Session Resolve returns must reach the handler through the context, not be
// discarded (`_ = sess`) leaving a handler to re-read the raw cookie — the
// second authentication path this seam exists to prevent.
func TestConsoleSession_TheResolvedSessionReachesTheHandler(t *testing.T) {
	a, _ := testConsoleAuthenticator()
	status, cs, ok, reached := consoleSessionRequest(t, a, http.MethodGet, "/console/",
		&http.Cookie{Name: consoleauth.SessionCookieName, Value: testSessionID})
	if !reached {
		t.Fatalf("a valid Console cookie was refused: status = %d", status)
	}
	if !ok {
		t.Fatal("ConsoleSessionFromContext returned ok=false on the browser lane")
	}
	if cs.ID.Reveal() != testSessionID {
		t.Errorf("ConsoleSession.ID = %q, want %q", cs.ID.Reveal(), testSessionID)
	}
	// The step-up stamp crosses because StepUp refreshes it. Method, Role and
	// the rest of the sign-in snapshot deliberately do not — see the type's doc
	// and TestConsoleSession_CarriesNoIdentitySnapshot.
	if !cs.AuthenticatedAt.Equal(testSessionAuthenticatedAt) {
		t.Errorf("ConsoleSession.AuthenticatedAt = %v, want %v", cs.AuthenticatedAt, testSessionAuthenticatedAt)
	}
}

// TestConsoleSession_TheTokenLaneCarriesNoSession is the one that matters for
// #460: a zero-value Session leaking onto the machine lane would later mean a
// zero-value CSRF secret on a surface that never had one.
func TestConsoleSession_TheTokenLaneCarriesNoSession(t *testing.T) {
	a, _ := testConsoleAuthenticator()
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := ConsoleSessionFromContext(r.Context()); ok {
			t.Error("a bearer-token request carried a ConsoleSession")
		}
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/console/", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("a valid bearer token was refused: status = %d", rec.Code)
	}
}

// TestConsoleSession_TheSignInPageSeesItToo is Middleware's PUBLIC branch —
// the one an already-signed-in visitor to the sign-in page hits. It must
// inject the session through the same contextWith path as the main branch,
// or a fix applied only to the main branch leaves this one's hand-rolled
// WithValue behind.
func TestConsoleSession_TheSignInPageSeesItToo(t *testing.T) {
	a, _ := testConsoleAuthenticator()
	status, cs, ok, reached := consoleSessionRequest(t, a, http.MethodGet, "/console/login",
		&http.Cookie{Name: consoleauth.SessionCookieName, Value: testSessionID})
	if !reached {
		t.Fatalf("the public sign-in route refused a valid cookie: status = %d", status)
	}
	if !ok {
		t.Fatal("the public branch resolved a Principal but injected no ConsoleSession")
	}
	if cs.ID.Reveal() != testSessionID {
		t.Errorf("ConsoleSession.ID = %q, want %q", cs.ID.Reveal(), testSessionID)
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

// TestConsoleSession_CarriesNoIdentitySnapshot is a structural guard, not a
// behavioural one: it fails if ConsoleSession ever grows a field naming an
// identity, because consoleauth.Session's Account/Role/Kind are a sign-in-time
// snapshot that is never refreshed, while the Principal beside it on the same
// context is rebuilt from a fresh Account read on every request.
//
// Written as a guard rather than left to review because the field that would
// be added is the one a handler reaches for. #428's step-up POST gates mutate
// applies and relay:-label management and already takes the ID from here; a
// `Role` within reach would read `admin` for a demoted admin until their
// session lapsed, and no behavioural test would notice. Reflection over the
// declared fields is what makes "do not add one" enforceable.
//
// If a consumer genuinely needs a session fact, add a NARROW, refreshed field
// (as AuthenticatedAt is) and extend the allowlist here deliberately.
func TestConsoleSession_CarriesNoIdentitySnapshot(t *testing.T) {
	allowed := map[string]bool{"ID": true, "AuthenticatedAt": true}

	typ := reflect.TypeOf(ConsoleSession{})
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !allowed[name] {
			t.Errorf("ConsoleSession grew field %q. Authorization comes from the Principal "+
				"and only the Principal — see the type's doc comment before widening this.", name)
		}
	}

	// And the snapshot fields specifically, by name, so the message a future
	// reader gets names the actual hazard rather than only the allowlist.
	for _, forbidden := range []string{"Role", "Kind", "Account", "AccountID", "Session"} {
		if _, found := typ.FieldByName(forbidden); found {
			t.Errorf("ConsoleSession carries %q, a sign-in-time snapshot that goes stale; "+
				"the fresh value lives on the Principal", forbidden)
		}
	}
}
