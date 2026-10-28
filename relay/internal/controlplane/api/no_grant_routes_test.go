package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
)

// Proves AP-84.
//
// TestControlAPI_ServesNoApprovalGrantRoute: no route requests, lists, reads or
// revokes an approval grant, and the paths that once did answer 404 even to an
// authenticated admin. The OpenAPI document is held to the same route table by
// TestOpenAPISpec and TestServedRoutes.
func TestControlAPI_ServesNoApprovalGrantRoute(t *testing.T) {
	for _, r := range Routes() {
		if strings.HasPrefix(r.Path, "/api/v1/approval-grants") {
			t.Errorf("route %s is registered; approval grants are removed", r.Pattern())
		}
	}

	authn := controlplane.NewAuthenticator(roleVerifier{credential: testCredential, role: accounts.RoleAdmin})
	mux := http.NewServeMux()
	Register(mux, Deps{Now: fixedNow})
	h := authn.Middleware(mux)

	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/approval-grants"},
		{http.MethodGet, "/api/v1/approval-grants"},
		{http.MethodGet, "/api/v1/approval-grants/g-1"},
		{http.MethodPost, "/api/v1/approval-grants/g-1/revoke"},
	} {
		rec := do(t, h, c.method, c.path, nil)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", c.method, c.path, rec.Code)
		}
	}
}
