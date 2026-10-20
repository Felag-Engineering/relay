package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
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

// testSessionCSRFSecret stands in for a derived CSRF token: a distinctive,
// non-zero value so a test can tell "the boundary carried the resolver's
// derivation" apart from "the boundary carried a zero-value stand-in". A
// plain string is enough here — CSRFToken (#460) is a value recomputed per
// request, not a type with its own construction rules the way SessionID is.
const testSessionCSRFSecret = "csrf-token-fixture"

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

// CSRFToken stands in for the real derivation (consoleauth.Store.CSRFToken):
// a fixed, distinctive value for the one identifier this fixture ever
// resolves, and empty for anything else — mirroring the production
// derivation's "no identifier, no token" shape without needing a real Store.
func (f *fakeSessionResolver) CSRFToken(id consoleauth.SessionID) consoleauth.CSRFToken {
	if id.Reveal() != f.valid {
		return consoleauth.CSRFToken{}
	}
	return consoleauth.ParseCSRFToken(testSessionCSRFSecret)
}

// testConsoleAuthenticator wires both lanes: the API Token lane (testToken)
// and the browser lane (testSessionID), with predicates shaped like the ones
// the composition root takes from package console.
func testConsoleAuthenticator() (*Authenticator, *fakeSessionResolver) {
	resolver := &fakeSessionResolver{acct: storedFirstAdmin(), valid: testSessionID}
	a := NewAuthenticator(
		&fakeVerifier{acct: storedFirstAdmin(), valid: testToken},
		WithConsoleSessions(resolver, testConsoleSessionOptions()),
	)
	return a, resolver
}

// testConsoleSessionOptions is the browser lane's configuration, shared by
// every harness here so the stand-in predicates cannot drift between them.
// The Unauthorized stand-in redirects to a sign-in path the way package
// console's real handler does, so a test can tell the redirect apart from the
// 401 challenge by more than its status code.
func testConsoleSessionOptions() ConsoleSessionOptions {
	return ConsoleSessionOptions{
		Public: func(r *http.Request) bool { return r.URL.Path == "/console/login" },
		Scope: func(r *http.Request) bool {
			return r.URL.Path == "/console" || strings.HasPrefix(r.URL.Path, "/console/")
		},
		Unauthorized: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Location", "/console/login")
			w.WriteHeader(http.StatusSeeOther)
		}),
	}
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
			if p.Role != string(accounts.RoleAdmin) || p.Account != testAdminName {
				t.Errorf("principal = %s (%s), want %s (admin)", p.Account, p.Role, testAdminName)
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
// Refusal shape
// -----------------------------------------------------------------------

// testConsoleOAuthAuthenticator is testConsoleAuthenticator with OAuth also
// configured — the deployment in which the refusal's shape matters most,
// because the 401 challenge is the only way an off-the-shelf harness learns
// where to sign in.
func testConsoleOAuthAuthenticator(t *testing.T) (*Authenticator, string) {
	t.Helper()
	f := newIDP(t)
	metadataURL := "https://relay.example.internal:9443" + ProtectedResourceMetadataPath
	a := NewAuthenticator(
		&fakeVerifier{acct: storedFirstAdmin(), valid: testToken},
		WithOAuth(
			OAuthConfig{Issuer: testIssuer, Audience: testAudience},
			f.verifier, &fakeLookup{accts: map[string]accounts.Account{}}, metadataURL,
		),
		WithConsoleSessions(
			&fakeSessionResolver{acct: storedFirstAdmin(), valid: testSessionID},
			testConsoleSessionOptions(),
		),
	)
	return a, metadataURL
}

// refusedRequest drives one request through the middleware and returns the
// recorded response, failing the test if the handler was reached.
func refusedRequest(t *testing.T, a *Authenticator, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	a.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Errorf("%s %s reached the handler without a valid credential", req.Method, req.URL.Path)
	})).ServeHTTP(rec, req)
	return rec
}

// assertChallenge checks that rec is the generic 401 carrying the discovery
// pointer, and not the Console's redirect to its sign-in page.
func assertChallenge(t *testing.T, rec *httptest.ResponseRecorder, metadataURL string) {
	t.Helper()
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d (Location %q), want 401", rec.Code, rec.Header().Get("Location"))
	}
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, want none: a machine caller must not be sent to the Console's sign-in page", loc)
	}
	want := `Bearer resource_metadata="` + metadataURL + `"`
	if got := rec.Header().Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}
	if body := rec.Body.String(); body != genericAuthError {
		t.Errorf("body = %q, want the generic %q", body, genericAuthError)
	}
}

// The finding, pinned: with the Console mounted, an unauthenticated request
// for the MCP endpoint or the Control API is answered with the 401 discovery
// challenge (ADR-0024), not a redirect to the Console's sign-in page. Before
// this, the refusal branched on "no bearer header" alone, so an MCP harness's
// first, tokenless request was sent to an HTML page instead of into the OAuth
// flow the challenge advertises.
//
// A Console cookie on the request changes nothing: off the Console it is not a
// credential (#459), so it must not change the refusal's shape either.
func TestConsoleSession_UnauthenticatedOffConsoleGetsTheChallenge(t *testing.T) {
	offConsole := []struct{ method, target string }{
		{http.MethodPost, "/mcp"},
		{http.MethodGet, "/mcp"},
		{http.MethodGet, "/api/v1/operations"},
		{http.MethodPost, "/api/v1/raw-exec"},
		{http.MethodGet, "/metrics"},
		{http.MethodGet, "/"},
		{http.MethodGet, "/consoleX"}, // a sibling of the prefix, not inside it
	}
	a, metadataURL := testConsoleOAuthAuthenticator(t)
	for _, c := range offConsole {
		for _, withCookie := range []bool{false, true} {
			name := c.method + " " + c.target
			if withCookie {
				name += " with a Console cookie"
			}
			t.Run(name, func(t *testing.T) {
				req := httptest.NewRequest(c.method, c.target, nil)
				if withCookie {
					req.AddCookie(&http.Cookie{Name: consoleauth.SessionCookieName, Value: testSessionID})
				}
				assertChallenge(t, refusedRequest(t, a, req), metadataURL)
			})
		}
	}
}

// The other half: an unauthenticated browser on a Console page is still sent
// to the sign-in page, because a browser cannot answer a Bearer challenge.
func TestConsoleSession_UnauthenticatedOnConsoleIsRedirectedToSignIn(t *testing.T) {
	onConsole := []string{"/console", "/console/", "/console/nodes/node-1", "/console/events"}
	a, _ := testConsoleOAuthAuthenticator(t)
	for _, target := range onConsole {
		t.Run(target, func(t *testing.T) {
			rec := refusedRequest(t, a, httptest.NewRequest(http.MethodGet, target, nil))
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/console/login" {
				t.Errorf("status = %d, Location = %q; want 303 to the sign-in page", rec.Code, rec.Header().Get("Location"))
			}
			if got := rec.Header().Get("WWW-Authenticate"); got != "" {
				t.Errorf("WWW-Authenticate = %q on a browser redirect, want none", got)
			}
		})
	}
}

// A request that presents a bearer credential is a machine caller wherever it
// was going, so a bad one gets the 401 challenge — on the Console's own paths
// too. Redirecting it would send a script to an HTML sign-in page it cannot
// use. (This is the property the original `!hasBearer` condition held, and
// scoping the redirect keeps it.)
func TestConsoleSession_InvalidBearerGetsTheChallengeEverywhere(t *testing.T) {
	a, metadataURL := testConsoleOAuthAuthenticator(t)
	for _, target := range []string{"/mcp", "/api/v1/operations", "/console/", "/console/nodes/node-1"} {
		t.Run(target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, target, nil)
			req.Header.Set("Authorization", "Bearer not-a-real-token")
			assertChallenge(t, refusedRequest(t, a, req), metadataURL)
		})
	}
}

// The discovery document stays reachable with no credential when the Console
// is mounted: the handshake is the challenge AND the document it points at,
// and mounting the Console must not put either behind its sign-in page.
func TestConsoleSession_MetadataIsReachableWithoutACredential(t *testing.T) {
	a, _ := testConsoleOAuthAuthenticator(t)
	srv := New(Config{Addr: "127.0.0.1:0", GetCertificate: staticCert(relaytest.SelfSignedServerCert(t, "controlplane-test"))}, a)

	ts := httptest.NewServer(srv.http.Handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + ProtectedResourceMetadataPath)
	if err != nil {
		t.Fatalf("Get metadata: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metadata status = %d, want 200 without a credential", resp.StatusCode)
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

// TestConsoleSession_CarriesTheSessionCSRFSecret pins that authenticateConsole
// populates CSRFToken from the resolver's derivation (#460), not from
// consoleauth.Session — there is no field on Session to read it from, by
// design. *Fails if*: authenticateConsole drops the field, or stops calling
// ConsoleSessionResolver.CSRFToken.
func TestConsoleSession_CarriesTheSessionCSRFSecret(t *testing.T) {
	a, _ := testConsoleAuthenticator()
	status, cs, ok, reached := consoleSessionRequest(t, a, http.MethodGet, "/console/",
		&http.Cookie{Name: consoleauth.SessionCookieName, Value: testSessionID})
	if !reached {
		t.Fatalf("a valid Console cookie was refused: status = %d", status)
	}
	if !ok {
		t.Fatal("ConsoleSessionFromContext returned ok=false on the browser lane")
	}
	if cs.CSRFToken.Reveal() != testSessionCSRFSecret {
		t.Errorf("ConsoleSession.CSRFToken = %q, want %q", cs.CSRFToken.Reveal(), testSessionCSRFSecret)
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
		&fakeVerifier{acct: storedFirstAdmin(), valid: testToken},
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
	allowed := map[string]bool{
		"ID":              true,
		"AuthenticatedAt": true,
		// CSRFToken (#460) is the narrow, non-identity field this issue
		// added: it is derived PER REQUEST from the ID already on this same
		// struct, names no identity of its own, and redacts nothing because
		// it redacts under every stringifying interface, exactly as
		// SessionID does and for the same reason — a value checked by
		// equality is a working credential in a log line, not a cracking
		// target (consoleauth.Store.CSRFToken
		// keeps no table of these — see that method's doc).
		"CSRFToken": true,
	}

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

// TestConsoleSession_NeverPrintsItsCSRFToken pins finding 2 of #460's security
// review: the derived token must not be recoverable by formatting or logging a
// ConsoleSession.
//
// #460 rejected a STORED per-session secret partly because "a heap dump, a core
// file, or a log leak" would each be sufficient — the attacker never needs the
// session cookie, since the victim's browser attaches it. Deriving rather than
// storing answers the heap and core-file halves. Only a type that refuses to
// print itself answers the log half, and that is the cheap half, because logs
// ship off-box.
//
// *Fails if*: CSRFToken becomes a bare string again, or loses any of its four
// redacting methods. One slog call or one %+v anywhere in a handler or
// middleware is all it would take.
func TestConsoleSession_NeverPrintsItsCSRFToken(t *testing.T) {
	cs := ConsoleSession{
		ID:        consoleauth.ParseSessionID(testSessionID),
		CSRFToken: consoleauth.ParseCSRFToken(testSessionCSRFSecret),
	}

	for _, rendered := range []string{
		fmt.Sprintf("%v", cs),
		fmt.Sprintf("%+v", cs),
		fmt.Sprintf("%#v", cs),
		cs.CSRFToken.String(),
		fmt.Sprint(slog.AnyValue(cs.CSRFToken)),
	} {
		if strings.Contains(rendered, testSessionCSRFSecret) {
			t.Errorf("a rendered ConsoleSession leaked the CSRF token: %s", rendered)
		}
	}

	marshalled, err := json.Marshal(cs)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(marshalled), testSessionCSRFSecret) {
		t.Errorf("JSON-marshalling a ConsoleSession leaked the CSRF token: %s", marshalled)
	}

	// And the one legitimate way out still works, or the type is unusable.
	if cs.CSRFToken.Reveal() != testSessionCSRFSecret {
		t.Errorf("Reveal() = %q, want %q", cs.CSRFToken.Reveal(), testSessionCSRFSecret)
	}
}
