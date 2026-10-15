// Package main: lifecycle_e2e_test.go exercises the full Node lifecycle via the
// real Relay composition root (newServer). No fakes on the security path.
//
// The test acts as a synthetic relay-daemon and covers the three v0.0.2
// acceptance criteria end-to-end:
//
//  1. Enrollment Token → Enroll → correct relay:/node: Labels in registry.
//  2. Renew over mTLS → fresh cert, same node_id, new serial.
//  3. RevokeNode → immediate Tunnel teardown + handshake rejection on reconnect.
//
// Helpers are duplicated inline (not cross-imported from transport_test.go or
// ca_test.go which live in different test binaries — see transport_test.go:27-29).
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"strings"
	"testing"
	"time"

	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// dialTLS opens a *grpc.ClientConn through lis with the given TLS config.
// ServerName is forced to "localhost" to match the server certificate SAN.
// conn.Close is registered as a t.Cleanup so callers never leak the connection.
//
// bufconn.Listener.DialContext is 1-arg (func(context.Context) (net.Conn, error));
// grpc.WithContextDialer needs the 2-arg form, so we wrap it here (R1 revision).
func dialTLS(t *testing.T, lis *bufconn.Listener, clientTLS *tls.Config) *grpc.ClientConn {
	t.Helper()
	clientTLS.ServerName = "localhost"
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// startRealServer boots the real Relay composition root via newServer, attaches
// it to an in-memory bufconn listener, and returns both for the test to drive.
// srv.Stop is registered as a t.Cleanup.
func startRealServer(t *testing.T) (*bufconn.Listener, *appDeps) {
	t.Helper()
	f := startRelay(t)
	return f.Bufconn, f.Deps
}

// TestLifecycle_SeedEnrollMTLSRenewRevoke drives the complete Node lifecycle via
// the real Relay composition root. Steps:
//
//	(a) Seed a scoped Enrollment Token via the test-only deps.tokens.Create path.
//	(b) Enroll over server-auth TLS (certless, no client cert): assert CN == node_id,
//	    CaBundle matches the CA bundle, AssignedLabels contain the relay: scope Labels.
//	(c) Reconnect over mTLS with the issued cert; open Tunnel, send Hello (with
//	    node:role=web and a relay: Label that must be dropped), recv Ping, then assert
//	    registry shows correct NodeLabels / RelayLabels / non-zero LastSeen.
//	(d) Send Heartbeat; poll until LastSeen advances (≤5 s).
//	(e) Renew over the same mTLS conn: assert fresh cert, same node_id, new serial.
//	(f) RevokeNode: assert still-open Tunnel stream tears down with
//	    codes.Unauthenticated within 5 s (ADR-0006 immediate live-stream disconnect).
//	(g) Reconnect with now-revoked cert: assert handshake-level rejection (err != nil).
func TestLifecycle_SeedEnrollMTLSRenewRevoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	lis, deps := startRealServer(t)

	// -------------------------------------------------------------------------
	// (a) Seed Enrollment Token — test-only path (no production seam or admin RPC).
	//     Two relay: Labels to verify both are stamped at Enroll.
	// -------------------------------------------------------------------------
	tokenScope := []string{"relay:env=prod", "relay:role=web"}
	_, plaintext, err := deps.tokens.Create(ctx, tokenScope, time.Hour)
	if err != nil {
		t.Fatalf("seed Enrollment Token: %v", err)
	}

	// -------------------------------------------------------------------------
	// (b) Enroll: certless server-auth TLS (no client cert).
	//     The Relay CA signs the CSR and stamps the Relay-assigned node_id as CN —
	//     the CSR subject ("ignored-cn") is never trusted (ADR-0006).
	// -------------------------------------------------------------------------
	enrollConn := dialTLS(t, lis, &tls.Config{
		RootCAs: relaytest.CertPool(t, deps.ca.Bundle()),
	})
	csrPEM, leafKey := relaytest.NewCSR(t, "ignored-cn")
	enrollResp, err := relayv1.NewEnrollmentClient(enrollConn).Enroll(ctx, &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             csrPEM,
		SelfLabels:      []*relayv1.Label{{Key: "node:role", Value: "web"}},
		Facts:           &relayv1.Facts{Hostname: "host-e2e", Os: "linux"},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	nodeID := enrollResp.GetNodeId()
	if nodeID == "" {
		t.Fatal("Enroll: node_id is empty")
	}
	if !strings.HasPrefix(nodeID, "node-") {
		t.Errorf("node_id %q does not have expected node- prefix", nodeID)
	}

	// Issued cert CN must equal the Relay-assigned node_id (ADR-0006).
	enrollBlock, _ := pem.Decode(enrollResp.GetCertificate())
	if enrollBlock == nil {
		t.Fatal("Enroll: cannot decode Certificate PEM")
	}
	enrolledCert, err := x509.ParseCertificate(enrollBlock.Bytes)
	if err != nil {
		t.Fatalf("Enroll: parse issued cert: %v", err)
	}
	if enrolledCert.Subject.CommonName != nodeID {
		t.Errorf("cert CN: got %q, want %q (node_id)", enrolledCert.Subject.CommonName, nodeID)
	}

	// CaBundle must match the Relay CA's own bundle (R3: use bytes.Equal).
	if !bytes.Equal(enrollResp.GetCaBundle(), deps.ca.Bundle()) {
		t.Error("CaBundle in EnrollResponse does not match deps.ca.Bundle()")
	}

	// AssignedLabels must carry both relay: Labels from the token scope, and only
	// those — the Relay stamps identity Labels solely from the Enrollment Token's
	// scope, never from the relay-daemon's request (ADR-0006).
	// Key format includes the "relay:" prefix per the proto convention (handler.go:284).
	wantAssigned := map[string]string{"relay:env": "prod", "relay:role": "web"}
	gotAssigned := make(map[string]string, len(enrollResp.GetAssignedLabels()))
	for _, l := range enrollResp.GetAssignedLabels() {
		gotAssigned[l.GetKey()] = l.GetValue()
	}
	if len(gotAssigned) != len(wantAssigned) {
		t.Errorf("AssignedLabels: got %d entries %v, want exactly %d %v",
			len(gotAssigned), gotAssigned, len(wantAssigned), wantAssigned)
	}
	for k, v := range wantAssigned {
		if got, ok := gotAssigned[k]; !ok || got != v {
			t.Errorf("AssignedLabels[%q]: got %q (present=%v), want %q", k, got, ok, v)
		}
	}

	// Assemble the Node identity cert for subsequent mTLS connections.
	clientCert := relaytest.AssembleClientCert(t, enrollResp.GetCertificate(), leafKey)
	pool := relaytest.CertPool(t, deps.ca.Bundle())

	// -------------------------------------------------------------------------
	// (c) mTLS Tunnel: reconnect with the issued Node cert, open Tunnel, send Hello.
	//     The relay: Label in Hello is silently dropped — only node: Labels are
	//     accepted from the relay-daemon (ADR-0006 two-namespace Label authority).
	//     Ping is the sync point: Upsert is guaranteed complete before Ping is sent.
	// -------------------------------------------------------------------------
	mtlsConn := dialTLS(t, lis, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pool,
	})
	stream, err := relayv1.NewTunnelClient(mtlsConn).Open(ctx)
	if err != nil {
		t.Fatalf("Tunnel Open: %v", err)
	}
	if err = stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Hello{
			Hello: &relayv1.Hello{
				Facts: &relayv1.Facts{Hostname: "host-e2e", Os: "linux"},
				Labels: []*relayv1.Label{
					{Key: "node:role", Value: "web"},
					{Key: "relay:env", Value: "ignored"}, // relay: Labels are dropped (ADR-0006)
				},
			},
		},
	}); err != nil {
		t.Fatalf("send Hello: %v", err)
	}
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv Ping: %v", err)
	}
	if msg.GetPing() == nil {
		t.Fatalf("expected Ping after Hello, got %T", msg.Body)
	}

	// Registry assertions — Ping sync point guarantees the Upsert is complete.
	n, ok := deps.registry.Get(nodeID)
	if !ok {
		t.Fatal("Node not found in registry after Hello")
	}
	// NodeLabels: node:role=web from Hello; bare key stored without "node:" prefix.
	if n.NodeLabels["role"] != "web" {
		t.Errorf("NodeLabels[role]: got %q, want %q", n.NodeLabels["role"], "web")
	}
	if len(n.NodeLabels) != 1 {
		t.Errorf("NodeLabels should have exactly 1 entry, got %v", n.NodeLabels)
	}
	// RelayLabels: stamped from the Enrollment Token scope; preserved across Hello
	// Upsert because the update path in memory.go leaves relay-space untouched.
	if n.RelayLabels["env"] != "prod" {
		t.Errorf("RelayLabels[env]: got %q, want prod", n.RelayLabels["env"])
	}
	if n.RelayLabels["role"] != "web" {
		t.Errorf("RelayLabels[role]: got %q, want web", n.RelayLabels["role"])
	}
	if len(n.RelayLabels) != 2 {
		t.Errorf("RelayLabels should have exactly 2 entries, got %v", n.RelayLabels)
	}
	if n.LastSeen.IsZero() {
		t.Error("LastSeen is zero after Hello")
	}
	seenAfterHello := n.LastSeen

	// -------------------------------------------------------------------------
	// (d) Heartbeat: assert LastSeen advances in the registry.
	//     The handler processes Heartbeat asynchronously; poll with a 5 s bound.
	// -------------------------------------------------------------------------
	if err = stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Heartbeat{
			Heartbeat: &relayv1.Heartbeat{UnixMillis: time.Now().UnixMilli()},
		},
	}); err != nil {
		t.Fatalf("send Heartbeat: %v", err)
	}
	heartbeatDone := make(chan struct{}, 1)
	go func() {
		for {
			n, ok := deps.registry.Get(nodeID)
			if ok && n.LastSeen.After(seenAfterHello) {
				heartbeatDone <- struct{}{}
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	select {
	case <-heartbeatDone:
		// LastSeen advanced — UpdateLastSeen was called on the Heartbeat.
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: LastSeen did not advance after Heartbeat")
	}

	// -------------------------------------------------------------------------
	// (e) Renew: fresh cert over the same mTLS conn.
	//     Identity comes from the verified client cert (not a token) — Renew is
	//     mTLS-required and not in the certless allowlist.
	// -------------------------------------------------------------------------
	csr2PEM, _ := relaytest.NewCSR(t, "ignored-again") // key unused: this step only asserts cert properties
	renewResp, err := relayv1.NewEnrollmentClient(mtlsConn).Renew(ctx, &relayv1.RenewRequest{
		Csr: csr2PEM,
	})
	if err != nil {
		t.Fatalf("Renew: %v", err)
	}
	if renewResp.GetNodeId() != nodeID {
		t.Errorf("Renew node_id: got %q, want %q", renewResp.GetNodeId(), nodeID)
	}
	renewBlock, _ := pem.Decode(renewResp.GetCertificate())
	if renewBlock == nil {
		t.Fatal("Renew: cannot decode Certificate PEM")
	}
	renewedCert, err := x509.ParseCertificate(renewBlock.Bytes)
	if err != nil {
		t.Fatalf("Renew: parse renewed cert: %v", err)
	}
	if renewedCert.Subject.CommonName != nodeID {
		t.Errorf("renewed cert CN: got %q, want %q", renewedCert.Subject.CommonName, nodeID)
	}
	// Fresh issuance must produce a new serial number (same CA, new cert).
	if enrolledCert.SerialNumber.Cmp(renewedCert.SerialNumber) == 0 {
		t.Error("renewed cert has same serial as enrolled cert; expected fresh issuance")
	}
	if !renewedCert.NotAfter.After(time.Now()) {
		t.Error("renewed cert NotAfter is not in the future")
	}

	// -------------------------------------------------------------------------
	// (f) Revoke — immediate live-stream teardown (ADR-0006).
	//     RevokeNode adds nodeID to the denylist and cancels the handler's derived
	//     context (via conns.Disconnect), which causes the still-open Tunnel stream
	//     to return codes.Unauthenticated to the synthetic relay-daemon.
	// -------------------------------------------------------------------------
	teardown := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		teardown <- err
	}()
	deps.revocation.RevokeNode(nodeID)
	select {
	case revokeErr := <-teardown:
		if revokeErr == nil {
			t.Fatal("expected Unauthenticated after RevokeNode, got nil")
		}
		if code := status.Code(revokeErr); code != codes.Unauthenticated {
			t.Errorf("expected codes.Unauthenticated after revocation, got %v", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: live Tunnel stream was not torn down after RevokeNode")
	}

	// -------------------------------------------------------------------------
	// (g) Reconnect rejection: fresh connection with the now-revoked Node cert.
	//     VerifyConnection checks the denylist at TLS handshake time (ADR-0006);
	//     error may surface as Unavailable (TLS) or Unauthenticated (interceptor).
	// -------------------------------------------------------------------------
	revokedConn := dialTLS(t, lis, &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pool,
	})
	revokedStream, reconnectErr := relayv1.NewTunnelClient(revokedConn).Open(ctx)
	if reconnectErr == nil {
		_ = revokedStream.Send(&relayv1.DaemonMessage{
			Body: &relayv1.DaemonMessage_Hello{Hello: &relayv1.Hello{}},
		})
		_, reconnectErr = revokedStream.Recv()
	}
	if reconnectErr == nil {
		t.Fatal("expected rejection on reconnect with revoked Node cert, got nil")
	}
}
