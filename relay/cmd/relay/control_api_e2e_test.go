// Package main: control_api_e2e_test.go exercises the /api/v1 Control API
// (#116) against the real Relay composition root (newServer) — both HTTP
// planes at once: the control-plane HTTPS listener driving the API calls,
// and the node-plane gRPC listener (via bufconn) driving a synthetic
// relay-daemon so each API action's real-world effect (enrollment
// succeeding/failing, a Tunnel tearing down, dispatch refusing) is observed,
// not just the HTTP response code.
//
// Authentication is the founding admin's bootstrap credential, minted from the
// running Relay's own store by bootstrapCredential (harness_test.go) — the
// in-process equivalent of `relay bootstrap-token` (#298, ADR-0023).
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/audit"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane/mcp"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/jobs"
	relayv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// startControlAPIServer boots the real Relay composition root with the
// control plane enabled: the node-plane gRPC server on an in-memory bufconn
// listener, and the control-plane HTTPS server on a real 127.0.0.1 TCP
// listener (the Control API needs a real net.Listener; bufconn only wraps
// gRPC's dialer). Returns the bufconn listener, deps, the control-plane base
// URL, and an *http.Client trusting the Relay's own CA.
//
// The returned credential is the founding admin's bootstrap token — the same
// thing `relay bootstrap-token` prints — since #298 left no shared credential
// to configure.
func startControlAPIServer(t *testing.T) (*bufconn.Listener, *appDeps, string, *http.Client, string) {
	t.Helper()
	f := startRelay(t, WithControlPlane())
	return f.Bufconn, f.Deps, f.ControlBase, f.ClientFor(""), f.Credential
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
// criterion 1/4: the bootstrap credential mints a scoped Enrollment Token over
// /api/v1; a daemon enrolls with it; a revoked token can no longer enroll.
func TestControlAPI_EnrollmentTokenLifecycle(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	nodeLis, deps, base, client, credential := startControlAPIServer(t)

	mintResp := controlAPIRequest(t, client, http.MethodPost, base+"/api/v1/enrollment-tokens",
		credential, map[string]any{
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
	enrollConn := dialTLS(t, nodeLis, &tls.Config{RootCAs: relaytest.CertPool(t, deps.ca.Bundle())})
	csrPEM, _ := relaytest.NewCSR(t, "ignored-cn")
	enrollResp, err := relayv1.NewEnrollmentClient(enrollConn).Enroll(ctx, &relayv1.EnrollRequest{
		EnrollmentToken: minted.Token,
		Csr:             csrPEM,
		Facts:           &relayv1.Facts{Hostname: "host-control-api", Os: "linux"},
	})
	if err != nil {
		t.Fatalf("Enroll with freshly minted token: %v", err)
	}
	if enrollResp.GetNodeId() == "" {
		t.Fatal("Enroll: node_id is empty")
	}

	revokeResp := controlAPIRequest(t, client, http.MethodDelete,
		base+"/api/v1/enrollment-tokens/"+minted.ID, credential, nil)
	defer revokeResp.Body.Close() //nolint:errcheck
	if revokeResp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status = %d, want %d", revokeResp.StatusCode, http.StatusNoContent)
	}

	// The same plaintext must no longer enroll a second Node.
	enrollConn2 := dialTLS(t, nodeLis, &tls.Config{RootCAs: relaytest.CertPool(t, deps.ca.Bundle())})
	csr2PEM, _ := relaytest.NewCSR(t, "ignored-cn-2")
	_, err = relayv1.NewEnrollmentClient(enrollConn2).Enroll(ctx, &relayv1.EnrollRequest{
		EnrollmentToken: minted.Token,
		Csr:             csr2PEM,
		Facts:           &relayv1.Facts{Hostname: "host-control-api-2", Os: "linux"},
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

	nodeLis, deps, base, client, credential := startControlAPIServer(t)

	// Seed an Enrollment Token via the test-only deps.tokens path (mirrors
	// lifecycle_e2e_test.go) — this test's focus is node revoke, not mint.
	_, plaintext, err := deps.tokens.Create(ctx, []string{"relay:env=prod"}, time.Hour)
	if err != nil {
		t.Fatalf("seed Enrollment Token: %v", err)
	}

	enrollConn := dialTLS(t, nodeLis, &tls.Config{RootCAs: relaytest.CertPool(t, deps.ca.Bundle())})
	csrPEM, leafKey := relaytest.NewCSR(t, "ignored-cn")
	enrollResp, err := relayv1.NewEnrollmentClient(enrollConn).Enroll(ctx, &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             csrPEM,
		Facts:           &relayv1.Facts{Hostname: "host-node-revoke", Os: "linux"},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	nodeID := enrollResp.GetNodeId()

	clientCert := relaytest.AssembleClientCert(t, enrollResp.GetCertificate(), leafKey)
	pool := relaytest.CertPool(t, deps.ca.Bundle())
	mtlsConn := dialTLS(t, nodeLis, &tls.Config{Certificates: []tls.Certificate{clientCert}, RootCAs: pool})
	stream, err := relayv1.NewTunnelClient(mtlsConn).Open(ctx)
	if err != nil {
		t.Fatalf("Tunnel Open: %v", err)
	}
	if err := stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Hello{Hello: &relayv1.Hello{Facts: &relayv1.Facts{Hostname: "host-node-revoke", Os: "linux"}}},
	}); err != nil {
		t.Fatalf("send Hello: %v", err)
	}
	if msg, err := stream.Recv(); err != nil || msg.GetPing() == nil {
		t.Fatalf("recv Ping: msg=%v err=%v", msg, err)
	}

	revokeResp := controlAPIRequest(t, client, http.MethodPost,
		base+"/api/v1/nodes/"+nodeID+"/revoke", credential, nil)
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
	revokedStream, reconnectErr := relayv1.NewTunnelClient(revokedConn).Open(ctx)
	if reconnectErr == nil {
		_ = revokedStream.Send(&relayv1.DaemonMessage{Body: &relayv1.DaemonMessage_Hello{Hello: &relayv1.Hello{}}})
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

	_, deps, base, client, credential := startControlAPIServer(t)

	engageResp := controlAPIRequest(t, client, http.MethodPost, base+"/api/v1/freeze/engage", credential, nil)
	defer engageResp.Body.Close() //nolint:errcheck
	if engageResp.StatusCode != http.StatusOK {
		t.Fatalf("freeze engage status = %d, want %d", engageResp.StatusCode, http.StatusOK)
	}

	sel := capability.Selector{}
	// A real Action kind, not a bare RiskClass: since #298 the Authorizer
	// denies an unrecognized ActionKind for every role including admin, so a
	// kind-less probe would be refused by authz and stop testing the Freeze.
	act := jobs.Action{Kind: jobs.ActionOperation, OperationName: "system.facts", RiskClass: jobs.RiskClassRead}
	// controlplane.FoundingAdmin() — not an unattributed/non-admin probe
	// Principal — so these three calls keep verifying the Freeze gate itself
	// (frozen -> FrozenError; released -> a genuine success), not an authz
	// denial that would satisfy "err != nil" for the wrong reason (RB1, plan
	// review): since #154, ControlEnabled wires the real deny-by-default
	// authz.NewRoleGate Authorizer, and a non-admin Principal here would be
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
		credential, map[string]string{"reason": ""})
	defer noReasonResp.Body.Close() //nolint:errcheck
	if noReasonResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("freeze release without reason status = %d, want %d", noReasonResp.StatusCode, http.StatusBadRequest)
	}
	if _, runErr := deps.capability.Run(ctx, admin, sel, act); !errors.As(runErr, &frozenErr) {
		t.Fatalf("capability.Run after refused release: err = %v, want still a *capability.FrozenError", runErr)
	}

	releaseResp := controlAPIRequest(t, client, http.MethodPost, base+"/api/v1/freeze/release",
		credential, map[string]string{"reason": "incident resolved"})
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
	_, _, base, client, _ := startControlAPIServer(t)

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

// -----------------------------------------------------------------------
// Execution routes (#356) — composition-root wiring
// -----------------------------------------------------------------------

// TestControlAPI_ExecutionRoutesAreWired proves the execution slice is
// reachable through the REAL composition root, not just through a hand-built
// mux in package api's own tests. That distinction matters: every assertion in
// api/execution_test.go would still pass if apiSurface.Mount forgot to pass
// Exec/Jobs, because those tests construct Deps themselves. This one fails if
// the wiring is missing.
//
// It drives plan mode, which is the safe probe by construction (ADR-0011):
// it resolves, authorizes, and checks exactly as a real run would but executes
// nothing, so the test needs no daemon and can never dispatch. With no Node
// enrolled the Selector matches zero, and the meaningful assertions are that
// the route exists (not 404), is authenticated, and returns a well-formed plan
// carrying ADR-0011's advisory.
func TestControlAPI_ExecutionRoutesAreWired(t *testing.T) {
	_, _, base, client, credential := startControlAPIServer(t)

	t.Run("run_operation plan is served", func(t *testing.T) {
		resp := controlAPIRequest(t, client, http.MethodPost, base+"/api/v1/operations",
			credential, map[string]any{"operation": "system.facts", "plan": true})
		defer resp.Body.Close() //nolint:errcheck

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (route must be wired through apiSurface.Mount)", resp.StatusCode)
		}
		var plan struct {
			Matched  int    `json:"matched"`
			Advisory string `json:"advisory"`
			JobID    string `json:"job_id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&plan); err != nil {
			t.Fatalf("decode plan: %v", err)
		}
		if plan.Advisory == "" {
			t.Error("plan response carries no advisory; ADR-0011 requires the point-in-time disclaimer")
		}
		if plan.JobID != "" {
			t.Errorf("plan response carries job_id %q; a Plan creates no Job", plan.JobID)
		}
	})

	t.Run("raw_exec plan is served", func(t *testing.T) {
		resp := controlAPIRequest(t, client, http.MethodPost, base+"/api/v1/raw-exec",
			credential, map[string]any{"argv": []string{"/bin/echo", "hi"}, "plan": true})
		defer resp.Body.Close() //nolint:errcheck

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200; the founding admin may plan a Raw Exec", resp.StatusCode)
		}
	})

	t.Run("a malformed operation is a 400, never a Policy verdict", func(t *testing.T) {
		// #345's trap, asserted end-to-end on this surface: a misspelled
		// argument name must be refused as malformed input before it can reach
		// a Node and come back as denied_by_policy.
		resp := controlAPIRequest(t, client, http.MethodPost, base+"/api/v1/operations",
			credential, map[string]any{
				"operation": "service.restart",
				"args":      map[string]string{"unitt": "nginx"},
			})
		defer resp.Body.Close() //nolint:errcheck

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400 for a misspelled argument name", resp.StatusCode)
		}
	})

	t.Run("unauthenticated is refused", func(t *testing.T) {
		resp := controlAPIRequest(t, client, http.MethodPost, base+"/api/v1/operations",
			"", map[string]any{"operation": "system.facts", "plan": true})
		defer resp.Body.Close() //nolint:errcheck

		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401 — the execution routes sit behind the same Authenticator as every other /api/v1 route", resp.StatusCode)
		}
	})
}

// -----------------------------------------------------------------------
// Job read + cancel routes (#357)
// -----------------------------------------------------------------------

// seedJob writes a Job with two resolved Tasks straight through the repos, so
// the Job-read routes can be exercised without a real daemon (the real-daemon
// path is covered by TestMCPExecution_RealDaemon_E2E, which needs
// RELAY_DAEMON_BIN and is skipped in a normal run). Returns the Job id.
func seedJob(t *testing.T, deps *appDeps) string {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	jobID := "job-e2e-1"
	if err := deps.jobs.CreateJob(ctx, jobs.Job{ID: jobID, CreatedAt: now}); err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	stageID := "stage-e2e-1"
	if err := deps.jobs.AddStage(ctx, jobs.Stage{ID: stageID, JobID: jobID, Index: 0}); err != nil {
		t.Fatalf("AddStage: %v", err)
	}

	// One Task that ran and exited 0, one that never ran (unreachable) — the
	// pair that makes the exit_code presence rule observable.
	act := jobs.Action{
		Kind:          jobs.ActionOperation,
		OperationName: "system.facts",
		RiskClass:     jobs.RiskClassRead,
	}
	ran := jobs.Task{ID: "task-e2e-ran", JobID: jobID, StageID: stageID, NodeID: "node-ran", Action: act, CreatedAt: now}
	if err := deps.tasks.CreateTask(ctx, ran); err != nil {
		t.Fatalf("CreateTask(ran): %v", err)
	}
	if err := deps.tasks.MarkDispatched(ctx, ran.ID, now); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}
	if err := deps.tasks.Resolve(ctx, ran.ID, jobs.Result{
		Outcome: jobs.OutcomeSuccess, ExitCode: 0, Stdout: []byte("hello"),
	}); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	offline := jobs.Task{ID: "task-e2e-offline", JobID: jobID, StageID: stageID, NodeID: "node-offline", Action: act, CreatedAt: now}
	if err := deps.tasks.CreateTask(ctx, offline); err != nil {
		t.Fatalf("CreateTask(offline): %v", err)
	}
	if err := deps.tasks.MarkUnreachable(ctx, offline.ID, now); err != nil {
		t.Fatalf("MarkUnreachable: %v", err)
	}
	return jobID
}

// TestControlAPI_JobRoutes drives #357's acceptance through the real
// composition root: a dispatched Job is re-readable by id with truthful
// per-Node outcomes, an unknown id is a legible 404, and cancel reaches the
// capability layer.
func TestControlAPI_JobRoutes(t *testing.T) {
	_, deps, base, client, credential := startControlAPIServer(t)
	jobID := seedJob(t, deps)

	t.Run("a dispatched Job is re-readable by id", func(t *testing.T) {
		resp := controlAPIRequest(t, client, http.MethodGet, base+"/api/v1/jobs/"+jobID, credential, nil)
		defer resp.Body.Close() //nolint:errcheck
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var body struct {
			JobID   string            `json:"job_id"`
			Results []json.RawMessage `json:"results"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body.JobID != jobID || len(body.Results) != 2 {
			t.Fatalf("job_id=%q with %d results, want %q with 2", body.JobID, len(body.Results), jobID)
		}
		// The did-it-run distinction survives the round trip: the Task that
		// ran carries exit_code, the one that never ran does not.
		wantExit := map[string]bool{"node-ran": true, "node-offline": false}
		for _, raw := range body.Results {
			var m map[string]json.RawMessage
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatalf("decode result: %v", err)
			}
			var nodeID string
			_ = json.Unmarshal(m["node_id"], &nodeID)
			if _, present := m["exit_code"]; present != wantExit[nodeID] {
				t.Errorf("%s: exit_code present = %v, want %v", nodeID, present, wantExit[nodeID])
			}
		}
	})

	t.Run("an unknown Job id is a 404", func(t *testing.T) {
		resp := controlAPIRequest(t, client, http.MethodGet, base+"/api/v1/jobs/job-does-not-exist", credential, nil)
		defer resp.Body.Close() //nolint:errcheck
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
	})

	t.Run("the read is audited", func(t *testing.T) {
		// ADR-0025: reading a Job returns captured Task output, so the access
		// must leave a trail. This also proves apiSurface.Mount wired Reads.
		records, err := deps.audit.ByJob(context.Background(), jobID)
		if err != nil {
			t.Fatalf("audit.ByJob: %v", err)
		}
		var reads int
		for _, rec := range records {
			if rec.Kind == audit.KindRead {
				reads++
			}
		}
		if reads == 0 {
			t.Error("no KindRead audit record for the Job read; the API read route must be audited like MCP's get_job")
		}
	})

	t.Run("cancelling a finished Job is a clean no-op", func(t *testing.T) {
		resp := controlAPIRequest(t, client, http.MethodPost, base+"/api/v1/jobs/"+jobID+"/cancel", credential, nil)
		defer resp.Body.Close() //nolint:errcheck
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (every Task is terminal; none is touched)", resp.StatusCode)
		}
	})

	t.Run("cancelling an unknown Job is a 404", func(t *testing.T) {
		resp := controlAPIRequest(t, client, http.MethodPost, base+"/api/v1/jobs/nope/cancel", credential, nil)
		defer resp.Body.Close() //nolint:errcheck
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
	})
}

// TestControlAPI_JobResultsMatchMCP is #357's third acceptance criterion:
// "results are consistent with what MCP returns for the same Job". Both
// surfaces are driven over their real transports against the SAME seeded Job,
// and their per-Node result sets are compared field by field.
//
// This is the assertion that would catch the two surfaces drifting — a
// renderer changed on one side, an exit_code rule applied differently, a
// different sort order — which is exactly the failure invariant 10 exists to
// prevent and which no single-surface test can see.
func TestControlAPI_JobResultsMatchMCP(t *testing.T) {
	f := startRelay(t, WithControlPlane())
	jobID := seedJob(t, f.Deps)

	// API side.
	resp := controlAPIRequest(t, f.ClientFor(""), http.MethodGet,
		f.ControlBase+"/api/v1/jobs/"+jobID, f.Credential, nil)
	defer resp.Body.Close() //nolint:errcheck
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("API status = %d, want 200", resp.StatusCode)
	}
	var apiBody struct {
		Results []mcp.PerNodeResult `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&apiBody); err != nil {
		t.Fatalf("decode API body: %v", err)
	}

	// MCP side, same Job, same server.
	session := relaytest.Connect(t, f.ControlBase, f.Client())
	res := relaytest.CallTool(t, session, "get_job", map[string]any{"job_id": jobID})
	if res.IsError {
		t.Fatalf("get_job returned IsError; content = %+v", res.Content)
	}
	var mcpOut mcp.ExecutionOutput
	if err := json.Unmarshal([]byte(mcpToolText(t, res)), &mcpOut); err != nil {
		t.Fatalf("decode MCP output: %v", err)
	}

	if len(apiBody.Results) != len(mcpOut.Results) {
		t.Fatalf("API returned %d per-Node results, MCP returned %d — the same Job must read the same through either door",
			len(apiBody.Results), len(mcpOut.Results))
	}
	for i := range apiBody.Results {
		a, m := apiBody.Results[i], mcpOut.Results[i]
		if a.NodeID != m.NodeID || a.Outcome != m.Outcome {
			t.Errorf("result[%d]: API {%s %s} != MCP {%s %s}", i, a.NodeID, a.Outcome, m.NodeID, m.Outcome)
		}
		// exit_code is a pointer on both sides: presence must agree, not just
		// the value — that IS the #207/#253 did-it-run distinction.
		switch {
		case (a.ExitCode == nil) != (m.ExitCode == nil):
			t.Errorf("result[%d] (%s): exit_code presence differs — API nil=%v, MCP nil=%v",
				i, a.NodeID, a.ExitCode == nil, m.ExitCode == nil)
		case a.ExitCode != nil && *a.ExitCode != *m.ExitCode:
			t.Errorf("result[%d] (%s): exit_code %d != %d", i, a.NodeID, *a.ExitCode, *m.ExitCode)
		}
		if a.Stdout != m.Stdout || a.Stderr != m.Stderr {
			t.Errorf("result[%d] (%s): captured output differs between surfaces", i, a.NodeID)
		}
	}
}

// mcpToolText extracts a tool result's single text payload. (The
// integration-tagged e2e files have their own copy; this package's default
// build cannot see it.)
func mcpToolText(t *testing.T, res *sdkmcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatal("CallToolResult.Content is empty")
	}
	tc, ok := res.Content[0].(*sdkmcp.TextContent)
	if !ok {
		t.Fatalf("Content[0] = %T, want *sdkmcp.TextContent", res.Content[0])
	}
	return tc.Text
}
