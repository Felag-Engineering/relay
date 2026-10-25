package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
)

// sessionscope_test.go asserts the extent of [SessionScope] (#459) the way
// login_test.go asserts the extent of [Unauthenticated]: against the route
// table, in the package that owns it, rather than by description.
//
// The property under test is that a Console session cookie is a credential for
// the Console and for nothing else on the control-plane listener. It has two
// halves, and both are load-bearing: too narrow and the Console breaks (or,
// worse, loops through its own sign-in page); too wide and an operator's
// browser cookie is a Control API credential — which, on POST
// /api/v1/raw-exec, is a fleet-wide arbitrary-command credential.

// Every route this process can mount is inside the scope.
func TestSessionScope_CoversEveryMountedRoute(t *testing.T) {
	for _, r := range Routes(Deps{}) {
		// Link() strips ServeMux's exact-match marker; the remaining wildcard
		// segments are literal enough for a prefix predicate.
		target := r.Link()
		if !SessionScope(httptest.NewRequest(r.Method, target, nil)) {
			t.Errorf("route %q is outside SessionScope — a signed-in operator could not reach it", r.Pattern())
		}
	}
}

// And nothing else is. The Control API and the MCP surface authenticate with
// an Account credential presented in a header; a cookie the browser attaches
// to every path is not one.
func TestSessionScope_ExcludesEveryOtherSurface(t *testing.T) {
	outside := []string{
		"/",
		"/api/v1/operations",
		"/api/v1/raw-exec",
		"/api/v1/jobs/job-1/cancel",
		"/api/v1/accounts",
		"/mcp",
		"/metrics",
		"/.well-known/oauth-protected-resource",
		// Not a Console path: the prefix is a path segment, not a string
		// prefix.
		"/console-of-someone-else",
		// Traversals resolve before the decision, so a path that the router
		// will serve as an API route is judged as one.
		"/console/../api/v1/operations",
		"/console/nodes/../../api/v1/raw-exec",
		"/console/./../mcp",
	}
	for _, target := range outside {
		if SessionScope(httptest.NewRequest(http.MethodPost, target, nil)) {
			t.Errorf("%q is inside SessionScope — a Console session cookie would authenticate it", target)
		}
	}
}

// The bare "/console" is in scope even though nothing is registered there.
// net/http answers it with a redirect to "/console/" (a 307 since Go 1.26; a
// 301 before it — the status changed, the redirect and its target did not),
// and refusing it would
// send a signed-in operator to the sign-in page, back to "/console", and round
// again — a sign-in loop, not a security control.
func TestSessionScope_AdmitsTheBarePrefixSoSignInCannotLoop(t *testing.T) {
	if !SessionScope(httptest.NewRequest(http.MethodGet, "/console", nil)) {
		t.Error(`"/console" is outside SessionScope; net/http redirects it to "/console/", so refusing it loops the sign-in`)
	}

	// The redirect is the stdlib's, not ours — assert it rather than assume
	// it, since the reason above depends on it.
	mux := http.NewServeMux()
	mux.HandleFunc("/console/", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/console", nil))
	if rec.Code != http.StatusTemporaryRedirect {
		t.Errorf(`GET /console = %d, want %d — the sign-in-loop reasoning above assumes the subtree redirect`,
			rec.Code, http.StatusTemporaryRedirect)
	}
	// The loop is avoided only because the redirect lands INSIDE the scope.
	loc := rec.Header().Get("Location")
	if loc != "/console/" {
		t.Fatalf(`GET /console redirects to %q, want "/console/"`, loc)
	}
	if !SessionScope(httptest.NewRequest(http.MethodGet, loc, nil)) {
		t.Errorf("the redirect target %q is outside SessionScope", loc)
	}
}

// End to end, over the REAL boundary and a REAL session: an admin signs in,
// then presents the cookie the browser would present on the Control API's
// dispatch route. Before #459 the boundary resolved it and handed the handler
// an admin Principal; now the request is refused and the session is never
// resolved.
//
// A second Authenticator over the fixture's own sign-in service, because what
// is under test is a route the Console does not mount — the property is about
// the boundary's reach, not about the Console's route table.
func TestSessionScope_ARealSessionIsRefusedOnTheControlAPI(t *testing.T) {
	f := newLoginFixture(t)

	rec, cookies := f.signIn(t, f.mike.Name, consolePassword)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("sign-in status = %d, want %d", rec.Code, http.StatusSeeOther)
	}
	session := cookieNamed(cookies, consoleauth.SessionCookieName)
	if session == nil || session.Value == "" {
		t.Fatal("sign-in set no session cookie")
	}
	if session.Path != "/" {
		t.Fatalf("session cookie Path = %q, want %q — the __Host- prefix forces it, which is why the scope predicate has to exist", session.Path, "/")
	}

	var reached bool
	var seen accounts.Role
	boundary := controlplane.NewAuthenticator(
		roleVerifier{role: accounts.RoleAdmin},
		controlplane.WithConsoleSessions(f.svc, controlplane.ConsoleSessionOptions{
			Public:       Unauthenticated,
			Scope:        SessionScope,
			Unauthorized: UnauthorizedHandler(),
		}),
	).Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		if p, ok := controlplane.PrincipalFromContext(r.Context()); ok {
			seen = accounts.Role(p.Role)
		}
		w.WriteHeader(http.StatusOK)
	}))

	for _, target := range []string{"/api/v1/operations", "/api/v1/raw-exec"} {
		reached, seen = false, ""
		req := httptest.NewRequest(http.MethodPost, target,
			strings.NewReader(`{"selector":"tag:env=prod","argv":["rm","-rf","/"]}`))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(session)
		boundary.ServeHTTP(httptest.NewRecorder(), req)

		if reached {
			t.Errorf("a real Console session authenticated POST %s as %s", target, seen)
		}
	}

	// The same cookie still works where it belongs.
	reached, seen = false, ""
	req := httptest.NewRequest(http.MethodGet, HomePath, nil)
	req.AddCookie(session)
	boundary.ServeHTTP(httptest.NewRecorder(), req)
	if !reached || seen != accounts.RoleAdmin {
		t.Errorf("the session was refused on %s (reached=%v, role=%q)", HomePath, reached, seen)
	}
}
