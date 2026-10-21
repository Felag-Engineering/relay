// Package main: unauthenticated_refusal_e2e_test.go pins the SHAPE of an
// authentication refusal against the real composition root, with the Console
// mounted and OAuth configured — the deployment in which the two refusals
// meet on one listener.
//
// An MCP harness's first request carries no token; the 401's
// `WWW-Authenticate: Bearer resource_metadata=…` is how it discovers the
// OAuth flow (ADR-0024). The Console's sign-in redirect is for a browser on a
// Console page. The unit tests in controlplane pin the branch against stand-in
// predicates; this pins that the composition root wires the real ones so that
// a request for /mcp or /api/v1 is never sent to the Console's sign-in page.
package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/console"
)

func TestE2E_UnauthenticatedRefusalShapeWithConsoleAndOAuth(t *testing.T) {
	idp := startE2EIDP(t)
	f := startRelay(t,
		WithControlPlane(),
		withE2EOAuth(idp),
		WithConfig(func(c *Config) { c.ConsoleEnabled = true }),
	)
	wantChallenge := `Bearer resource_metadata="https://relay.e2e.invalid` + controlplane.ProtectedResourceMetadataPath + `"`

	// Redirects are asserted, never followed: following one is exactly the
	// failure this pins (a harness landing on HTML instead of a challenge).
	noFollow := func(credential string) *http.Client {
		c := f.ClientFor(credential)
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return c
	}

	send := func(t *testing.T, client *http.Client, method, path string) *http.Response {
		t.Helper()
		var body *strings.Reader
		if method == http.MethodPost {
			body = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
		} else {
			body = strings.NewReader("")
		}
		req, err := http.NewRequest(method, f.ControlBase+path, body)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		if method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	challenged := []struct {
		name, credential, method, path string
	}{
		{"no credential, MCP", "", http.MethodPost, "/mcp"},
		{"no credential, Control API", "", http.MethodGet, "/api/v1/ping"},
		{"invalid bearer, MCP", "not-a-real-token", http.MethodPost, "/mcp"},
		{"invalid bearer, Console page", "not-a-real-token", http.MethodGet, console.PathPrefix},
	}
	for _, c := range challenged {
		t.Run(c.name, func(t *testing.T) {
			resp := send(t, noFollow(c.credential), c.method, c.path)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d (Location %q), want 401", resp.StatusCode, resp.Header.Get("Location"))
			}
			if loc := resp.Header.Get("Location"); loc != "" {
				t.Errorf("Location = %q, want none", loc)
			}
			if got := resp.Header.Get("WWW-Authenticate"); got != wantChallenge {
				t.Errorf("WWW-Authenticate = %q, want %q", got, wantChallenge)
			}
		})
	}

	t.Run("no credential, Console page", func(t *testing.T) {
		resp := send(t, noFollow(""), http.MethodGet, console.PathPrefix)
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("status = %d, want 303 to the sign-in page", resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, console.LoginPath) {
			t.Errorf("Location = %q, want the sign-in page %q", loc, console.LoginPath)
		}
	})

	// Escaped dot-segments over a real socket. net/http's ServeMux cleans the
	// ESCAPED path, so `%2e%2e` reaches the auth middleware as a literal
	// segment, while console.SessionScope decodes and then cleans. These are
	// the forms where the router and the scope check see different paths
	// (plain `..` is answered with a 301 by the mux before auth runs), so the
	// refusal's shape is pinned for each: what matters here is that a path
	// the scope check places OFF the Console is never redirected, and one it
	// places ON the Console is redirected with no crafted destination.
	escaped := func(t *testing.T, rawPath string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, f.ControlBase+rawPath, nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		// Guard the premise: the client must put the path on the wire exactly
		// as written, not a normalised form of it.
		if got := req.URL.RequestURI(); got != rawPath {
			t.Fatalf("the client would send %q, not %q: the escaped path was normalised before sending", got, rawPath)
		}
		resp, err := noFollow("").Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", rawPath, err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	t.Run("no credential, escaped traversal out of the Console", func(t *testing.T) {
		resp := escaped(t, "/console/%2e%2e/api/v1/ping")
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d (Location %q), want 401", resp.StatusCode, resp.Header.Get("Location"))
		}
		if loc := resp.Header.Get("Location"); loc != "" {
			t.Errorf("Location = %q, want none", loc)
		}
		if got := resp.Header.Get("WWW-Authenticate"); got != wantChallenge {
			t.Errorf("WWW-Authenticate = %q, want %q", got, wantChallenge)
		}
	})

	t.Run("no credential, escaped traversal into the Console", func(t *testing.T) {
		resp := escaped(t, "/api/v1/%2e%2e/%2e%2e/console/")
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("status = %d (WWW-Authenticate %q), want 303", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
		}
		if loc := resp.Header.Get("Location"); loc != console.LoginPath {
			t.Errorf("Location = %q, want exactly %q with no next", loc, console.LoginPath)
		}
	})

	t.Run("no credential, protected-resource metadata", func(t *testing.T) {
		resp := send(t, noFollow(""), http.MethodGet, controlplane.ProtectedResourceMetadataPath)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("status = %d, want 200: the document the challenge points at must be reachable without a credential", resp.StatusCode)
		}
	})
}

// With the Console mounted, a browser opened on the bare host is sent to it:
// the real composition root sets the control plane's root redirect, and only
// then. Without the Console, / stays a 401 like every other unauthenticated
// path.
func TestE2E_RootRedirectsToTheConsoleOnlyWhenItIsMounted(t *testing.T) {
	get := func(t *testing.T, f *relayFixture) *http.Response {
		t.Helper()
		client := f.ClientFor("")
		client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, err := client.Get(f.ControlBase + "/")
		if err != nil {
			t.Fatalf("GET /: %v", err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}

	t.Run("console mounted", func(t *testing.T) {
		f := startRelay(t, WithControlPlane(), WithConfig(func(c *Config) { c.ConsoleEnabled = true }))
		resp := get(t, f)
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("GET / = %d, want %d", resp.StatusCode, http.StatusFound)
		}
		if loc := resp.Header.Get("Location"); loc != console.HomePath {
			t.Errorf("Location = %q, want %q", loc, console.HomePath)
		}
	})

	t.Run("console off", func(t *testing.T) {
		f := startRelay(t, WithControlPlane())
		resp := get(t, f)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET / = %d (Location %q), want %d", resp.StatusCode, resp.Header.Get("Location"), http.StatusUnauthorized)
		}
	})
}
