package controlplane

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// serve answers one request through the Server's whole handler chain, the
// pre-authentication mux included.
func serve(t *testing.T, srv *Server, method, target, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	srv.http.Handler.ServeHTTP(rec, req)
	return rec
}

// The redirect answers exactly GET (and HEAD) / with the fixed target, whatever
// credential the request carries: it reads none.
func TestRootRedirect_AnswersExactlyGetRoot(t *testing.T) {
	srv := New(Config{Addr: "127.0.0.1:0", RootRedirect: "/console/"}, testAuthenticator())

	for _, c := range []struct{ name, method, token string }{
		{"GET, no credential", http.MethodGet, ""},
		{"HEAD, no credential", http.MethodHead, ""},
		{"GET, invalid bearer", http.MethodGet, "not-a-real-token"},
		{"GET, valid bearer", http.MethodGet, testToken},
	} {
		t.Run(c.name, func(t *testing.T) {
			rec := serve(t, srv, c.method, "/", c.token)
			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
			}
			if loc := rec.Header().Get("Location"); loc != "/console/" {
				t.Errorf("Location = %q, want %q", loc, "/console/")
			}
		})
	}
}

// Nothing else moves ahead of authentication: another method on / and any
// other path keep their existing answers.
func TestRootRedirect_LeavesEverythingElseAuthenticated(t *testing.T) {
	srv := New(Config{Addr: "127.0.0.1:0", RootRedirect: "/console/"}, testAuthenticator())

	for _, c := range []struct{ method, target string }{
		{http.MethodPost, "/"},
		{http.MethodGet, "/index.html"},
		{http.MethodGet, "/api/v1/ping"},
		{http.MethodGet, "/mcp"},
	} {
		rec := serve(t, srv, c.method, c.target, "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want %d", c.method, c.target, rec.Code, http.StatusUnauthorized)
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Errorf("%s %s Location = %q, want none", c.method, c.target, loc)
		}
	}
}

// Unset, / is the authenticated mux's like every other path: the redirect
// exists only where the composition root asks for it.
func TestRootRedirect_UnsetLeavesRootAuthenticated(t *testing.T) {
	srv := New(Config{Addr: "127.0.0.1:0"}, testAuthenticator())

	rec := serve(t, srv, http.MethodGet, "/", "")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET / = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// A target that is not a local path would be an open redirect; it is refused
// when the Server is built.
func TestRootRedirect_RefusesANonLocalTarget(t *testing.T) {
	for _, target := range []string{"https://evil.example/", "//evil.example/", "console/"} {
		t.Run(target, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("New accepted RootRedirect %q", target)
				}
			}()
			New(Config{Addr: "127.0.0.1:0", RootRedirect: target}, testAuthenticator())
		})
	}
}
