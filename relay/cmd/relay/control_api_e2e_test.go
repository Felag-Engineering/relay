// Package main: control_api_e2e_test.go exercises the /api/v1 Control API
// (#116) against the real Relay composition root (newServer) — both HTTP
// planes at once: the control-plane HTTPS listener driving the API calls,
// and the node-plane gRPC listener (via bufconn) driving a synthetic
// relay-daemon so each API action's real-world effect (enrollment
// succeeding/failing, a Tunnel tearing down, dispatch refusing) is observed,
// not just the HTTP response code.
//
// controlAPITestCredential must match the plaintext writeCredentialHashFile
// (newserver_test.go) hashes into the credential file used here.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// controlAPITestCredential is the plaintext credential writeCredentialHashFile
// hashes into the control-plane credential file (see newserver_test.go).
const controlAPITestCredential = "test-control-plane-credential" //nolint:gosec // test fixture

// startControlAPIServer boots the real Relay composition root with the
// control plane enabled: the node-plane gRPC server on an in-memory bufconn
// listener, and the control-plane HTTPS server on a real 127.0.0.1 TCP
// listener (the Control API needs a real net.Listener; bufconn only wraps
// gRPC's dialer). Returns the bufconn listener, deps, the control-plane base
// URL, and an *http.Client trusting the Relay's own CA.
func startControlAPIServer(t *testing.T) (*bufconn.Listener, *appDeps, string, *http.Client) {
	t.Helper()

	cfg := baseTestConfig(t)
	cfg.ControlEnabled = true
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.ControlCredentialHashFile = writeCredentialHashFile(t)

	srv, deps, err := newServer(cfg)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	t.Cleanup(func() { deps.store.Close() }) //nolint:errcheck
	t.Cleanup(srv.Stop)

	nodeLis := bufconn.Listen(1 << 20)
	go srv.Serve(nodeLis) //nolint:errcheck

	controlLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen (control-plane): %v", err)
	}
	go func() { _ = deps.control.Serve(controlLis) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = deps.control.Shutdown(ctx)
	})

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(deps.ca.Bundle()) {
		t.Fatal("AppendCertsFromPEM(deps.ca.Bundle()) returned false")
	}
	client := &http.Client{
		// ServerName forced to "localhost" to match the control-plane server
		// certificate's SAN (relayCA.IssueServerCertificate([]string{cfg.Hostname}, nil)
		// in newServer) even though the test dials 127.0.0.1.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"}},
	}

	return nodeLis, deps, "https://" + controlLis.Addr().String(), client
}

// controlAPIRequest issues a request against the control-plane API with the
// given bearer token (empty means no Authorization header) and an optional
// JSON body, and returns the response.
func controlAPIRequest(t *testing.T, client *http.Client, method, url, token string, body any) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("json.Marshal request body: %v", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("NewRequest %s %s: %v", method, url, err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do %s %s: %v", method, url, err)
	}
	return resp
}

// mintTokenAPIResponse mirrors internal/controlplane/api.mintTokenResponse's
// wire shape (deliberately not imported: this test exercises the Control API
// as an outside HTTP caller would, over the wire, not via package api's
// internal types).
type mintTokenAPIResponse struct {
	ID        string   `json:"id"`
	Token     string   `json:"token"`
	Scope     []string `json:"scope"`
	ExpiresAt string   `json:"expires_at"`
	MaxUses   int      `json:"max_uses"`
}

// TestControlAPI_EnrollmentTokenLifecycle drives ROADMAP acceptance
// criterion 1/4: the seeded credential mints a scoped Enrollment Token over
// /api/v1; a daemon enrolls with it; a revoked token can no longer enroll.
func TestControlAPI_EnrollmentTokenLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nodeLis, deps, base, client := startControlAPIServer(t)

	mintResp := controlAPIRequest(t, client, http.MethodPost, base+"/api/v1/enrollment-tokens",
		controlAPITestCredential, map[string]any{
			"scope":       []string{"relay:env=prod"},
			"ttl_seconds": 3600,
		})
	defer mintResp.Body.Close() //nolint:errcheck
	if mintResp.StatusCode != http.StatusCreated {
		t.Fatalf("mint status = %d, want %d", mintResp.StatusCode, http.StatusCreated)
	}
	var minted mintTokenAPIResponse
	if err := json.NewDecoder(mintResp.Body).Decode(&minted); err != nil {
		t.Fatalf("decode mint response: %v", err)
	}
	if minted.ID == "" || minted.Token == "" {
		t.Fatalf("mint response missing id/token: %+v", minted)
	}

	// A daemon enrolls with the minted plaintext over the node-plane gRPC
	// listener: enrollment must succeed while the token is live.
	enrollConn := dialTLS(t, nodeLis, &tls.Config{RootCAs: certPool(t, deps.ca.Bundle())})
	csrPEM, _ := newCSR(t, "ignored-cn")
	enrollResp, err := gleipnirv1.NewEnrollmentClient(enrollConn).Enroll(ctx, &gleipnirv1.EnrollRequest{
		EnrollmentToken: minted.Token,
		Csr:             csrPEM,
		Facts:           &gleipnirv1.Facts{Hostname: "host-control-api", Os: "linux"},
	})
	if err != nil {
		t.Fatalf("Enroll with freshly minted token: %v", err)
	}
	if enrollResp.GetNodeId() == "" {
		t.Fatal("Enroll: node_id is empty")
	}

	revokeResp := controlAPIRequest(t, client, http.MethodDelete,
		base+"/api/v1/enrollment-tokens/"+minted.ID, controlAPITestCredential, nil)
	defer revokeResp.Body.Close() //nolint:errcheck
	if revokeResp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want %d", revokeResp.StatusCode, http.StatusNoContent)
	}

	// The same plaintext must no longer enroll a second Node.
	enrollConn2 := dialTLS(t, nodeLis, &tls.Config{RootCAs: certPool(t, deps.ca.Bundle())})
	csr2PEM, _ := newCSR(t, "ignored-cn-2")
	_, err = gleipnirv1.NewEnrollmentClient(enrollConn2).Enroll(ctx, &gleipnirv1.EnrollRequest{
		EnrollmentToken: minted.Token,
		Csr:             csr2PEM,
		Facts:           &gleipnirv1.Facts{Hostname: "host-control-api-2", Os: "linux"},
	})
	if err == nil {
		t.Fatal("expected Enroll to fail with a revoked token, got nil error")
	}
	if code := status.Code(err); code != codes.PermissionDenied {
		t.Errorf("Enroll with revoked token: code = %v, want %v", code, codes.PermissionDenied)
	}
}

// TestControlAPI_NodeRevoke drives ROADMAP acceptance criterion 2/4:
// revoking a Node over the API drops its Tunnel and blocks reconnection.
func TestControlAPI_NodeRevoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nodeLis, deps, base, client := startControlAPIServer(t)

	// Seed an Enrollment Token via the test-only deps.tokens path (mirrors
	// lifecycle_e2e_test.go) — this test's focus is node revoke, not mint.
	_, plaintext, err := deps.tokens.Create(ctx, []string{"relay:env=prod"}, time.Hour)
	if err != nil {
		t.Fatalf("seed Enrollment Token: %v", err)
	}

	enrollConn := dialTLS(t, nodeLis, &tls.Config{RootCAs: certPool(t, deps.ca.Bundle())})
	csrPEM, leafKey := newCSR(t, "ignored-cn")
	enrollResp, err := gleipnirv1.NewEnrollmentClient(enrollConn).Enroll(ctx, &gleipnirv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             csrPEM,
		Facts:           &gleipnirv1.Facts{Hostname: "host-node-revoke", Os: "linux"},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	nodeID := enrollResp.GetNodeId()

	clientCert := assembleClientCert(t, enrollResp.GetCertificate(), leafKey)
	pool := certPool(t, deps.ca.Bundle())
	mtlsConn := dialTLS(t, nodeLis, &tls.Config{Certificates: []tls.Certificate{clientCert}, RootCAs: pool})
	stream, err := gleipnirv1.NewTunnelClient(mtlsConn).Open(ctx)
	if err != nil {
		t.Fatalf("Tunnel Open: %v", err)
	}
	if err := stream.Send(&gleipnirv1.DaemonMessage{
		Body: &gleipnirv1.DaemonMessage_Hello{Hello: &gleipnirv1.Hello{Facts: &gleipnirv1.Facts{Hostname: "host-node-revoke", Os: "linux"}}},
	}); err != nil {
		t.Fatalf("send Hello: %v", err)
	}
	if msg, err := stream.Recv(); err != nil || msg.GetPing() == nil {
		t.Fatalf("recv Ping: msg=%v err=%v", msg, err)
	}

	revokeResp := controlAPIRequest(t, client, http.MethodPost,
		base+"/api/v1/nodes/"+nodeID+"/revoke", controlAPITestCredential, nil)
	defer revokeResp.Body.Close() //nolint:errcheck
	if revokeResp.StatusCode != http.StatusNoContent {
		t.Fatalf("node revoke status = %d, want %d", revokeResp.StatusCode, http.StatusNoContent)
	}

	teardown := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		teardown <- err
	}()
	select {
	case revokeErr := <-teardown:
		if revokeErr == nil {
			t.Fatal("expected the live Tunnel stream to tear down after API node revoke, got nil")
		}
		if code := status.Code(revokeErr); code != codes.Unauthenticated {
			t.Errorf("expected codes.Unauthenticated after API node revoke, got %v", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: live Tunnel stream was not torn down after API node revoke")
	}

	// Reconnection with the now-revoked Node cert must be rejected.
	revokedConn := dialTLS(t, nodeLis, &tls.Config{Certificates: []tls.Certificate{clientCert}, RootCAs: pool})
	revokedStream, reconnectErr := gleipnirv1.NewTunnelClient(revokedConn).Open(ctx)
	if reconnectErr == nil {
		_ = revokedStream.Send(&gleipnirv1.DaemonMessage{Body: &gleipnirv1.DaemonMessage_Hello{Hello: &gleipnirv1.Hello{}}})
		_, reconnectErr = revokedStream.Recv()
	}
	if reconnectErr == nil {
		t.Fatal("expected reconnection with a revoked Node cert to fail, got nil")
	}
}

// TestControlAPI_FreezeEngageRelease drives ROADMAP acceptance criterion
// 3/4: Freeze engaged over the API stops dispatch; release (with reason)
// restores it; both audited (via the intrinsic capability.AuditSink, not
// package api's recordLifecycle — see freeze.go).
func TestControlAPI_FreezeEngageRelease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	_, deps, base, client := startControlAPIServer(t)

	engageResp := controlAPIRequest(t, client, http.MethodPost, base+"/api/v1/freeze/engage", controlAPITestCredential, nil)
	defer engageResp.Body.Close() //nolint:errcheck
	if engageResp.StatusCode != http.StatusOK {
		t.Fatalf("freeze engage status = %d, want %d", engageResp.StatusCode, http.StatusOK)
	}

	sel := capability.Selector{}
	act := jobs.Action{RiskClass: jobs.RiskClassRead}
	// controlplane.FoundingAdmin() — not an unattributed/non-admin probe
	// Principal — so these three calls keep verifying the Freeze gate itself
	// (frozen -> FrozenError; released -> a genuine success), not an authz
	// denial that would satisfy "err != nil" for the wrong reason (RB1, plan
	// review): since #154, ControlEnabled wires the real deny-by-default
	// authz.NewStaged Authorizer, and a non-admin Principal here would be
	// denied with authz.ErrUnauthorized before ever reaching the Freeze
	// check's dispatch outcome.
	admin := controlplane.FoundingAdmin()
	_, runErr := deps.capability.Run(ctx, admin, sel, act)
	var frozenErr *capability.FrozenError
	if !errors.As(runErr, &frozenErr) {
		t.Fatalf("capability.Run after engage: err = %v, want a *capability.FrozenError", runErr)
	}

	// Release without a reason must be refused (ADR-0013 asymmetric
	// activation) and the Freeze must remain engaged.
	noReasonResp := controlAPIRequest(t, client, http.MethodPost, base+"/api/v1/freeze/release",
		controlAPITestCredential, map[string]string{"reason": ""})
	defer noReasonResp.Body.Close() //nolint:errcheck
	if noReasonResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("freeze release without reason status = %d, want %d", noReasonResp.StatusCode, http.StatusBadRequest)
	}
	if _, runErr := deps.capability.Run(ctx, admin, sel, act); !errors.As(runErr, &frozenErr) {
		t.Fatalf("capability.Run after refused release: err = %v, want still a *capability.FrozenError", runErr)
	}

	releaseResp := controlAPIRequest(t, client, http.MethodPost, base+"/api/v1/freeze/release",
		controlAPITestCredential, map[string]string{"reason": "incident resolved"})
	defer releaseResp.Body.Close() //nolint:errcheck
	if releaseResp.StatusCode != http.StatusOK {
		t.Fatalf("freeze release status = %d, want %d", releaseResp.StatusCode, http.StatusOK)
	}

	// After a genuine release, dispatch must genuinely succeed for an
	// authorized (admin) Principal — not merely "not a FrozenError", which an
	// authz denial would also satisfy (RB1, plan review).
	if _, runErr := deps.capability.Run(ctx, admin, sel, act); runErr != nil {
		t.Fatalf("capability.Run after release: err = %v, want nil (dispatch unblocked for an admin Principal)", runErr)
	}

	records, err := deps.audit.List(ctx)
	if err != nil {
		t.Fatalf("deps.audit.List: %v", err)
	}
	var sawEngage, sawRelease bool
	for _, r := range records {
		switch r.Kind {
		case "freeze_engage":
			sawEngage = true
			if r.Principal == "" {
				t.Error("freeze_engage audit Record has empty Principal")
			}
		case "freeze_release":
			sawRelease = true
			if r.Reason != "incident resolved" {
				t.Errorf("freeze_release audit Record Reason = %q, want %q", r.Reason, "incident resolved")
			}
		}
	}
	if !sawEngage || !sawRelease {
		t.Errorf("audit records missing freeze_engage/freeze_release: sawEngage=%v sawRelease=%v (records=%+v)", sawEngage, sawRelease, records)
	}
}

// TestControlAPI_RequiresCredential drives ROADMAP acceptance criterion 4/4:
// requests without the credential are refused on every /api/v1 route added
// by this issue.
func TestControlAPI_RequiresCredential(t *testing.T) {
	_, _, base, client := startControlAPIServer(t)

	cases := []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodPost, "/api/v1/enrollment-tokens", map[string]any{"scope": []string{"relay:env=prod"}, "ttl_seconds": 3600}},
		{http.MethodDelete, "/api/v1/enrollment-tokens/does-not-matter", nil},
		{http.MethodPost, "/api/v1/nodes/does-not-matter/revoke", nil},
		{http.MethodPost, "/api/v1/freeze/engage", nil},
		{http.MethodPost, "/api/v1/freeze/release", map[string]string{"reason": "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			resp := controlAPIRequest(t, client, tc.method, base+tc.path, "", tc.body)
			defer resp.Body.Close() //nolint:errcheck
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
			}
		})
	}
}
