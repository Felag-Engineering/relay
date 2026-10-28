// Package main: approval_grant_e2e_test.go proves, through the REAL composition
// root, that the Relay serves no approval-grant route. It is the counterpart to
// approval_e2e_test.go: every gated dispatch parks and is answered on its own.
package main

import (
	"net/http"
	"testing"
)

// Proves AP-84.
//
// TestApprovalGrant_TheComposedRelayServesNoGrantRoute: with approval gating on,
// each route that once requested, listed, read or revoked an approval grant
// answers 404 to an authenticated admin through the real control-plane listener.
func TestApprovalGrant_TheComposedRelayServesNoGrantRoute(t *testing.T) {
	f := startGatedRelay(t, gateAllMutates)

	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/approval-grants"},
		{http.MethodGet, "/api/v1/approval-grants"},
		{http.MethodGet, "/api/v1/approval-grants/g-1"},
		{http.MethodPost, "/api/v1/approval-grants/g-1/revoke"},
	} {
		resp := controlAPIRequest(t, f.ClientFor(f.Credential), c.method, f.ControlBase+c.path, f.Credential, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", c.method, c.path, resp.StatusCode)
		}
	}
}
