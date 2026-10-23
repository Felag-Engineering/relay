// Package main: revocation_persist_e2e_test.go proves issue #133 end-to-end via
// the real Relay composition root (newServer), booted TWICE against one shared
// CADir + StorePath. Revocation of a Node and of an Enrollment Token must
// survive a Relay restart (ADR-0006 "revocation is instant" must also hold
// across a process restart).
//
// Both tests boot, revoke, stop+close, then reboot the SAME Config so the CA
// reopens (the revoked cert still chains) and the store reopens (proving the
// denylist/token rehydration). dialTLS and the relaytest helpers are shared
// with lifecycle_e2e_test.go (same test binary).
package main

import (
	"context"
	"crypto/tls"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

// persistTestConfig returns a Config whose CADir and StorePath live under a
// single persistent temp dir, so two newServer boots share both: the CA reopens
// (revoked certs still chain) and the store reopens (revocation state survives).
func persistTestConfig(t *testing.T) Config {
	t.Helper()
	dir := t.TempDir()
	return Config{
		Addr:                 ":0",
		CADir:                filepath.Join(dir, "ca"),
		StorePath:            filepath.Join(dir, "relay.db"),
		Hostname:             "localhost",
		EnrollIPRate:         5,
		EnrollIPBurst:        3,
		EnrollGlobalRate:     50,
		EnrollGlobalBurst:    10,
		EnrollMaxTrackedIPs:  100000,
		MaxNodes:             110000,
		DispatchConcurrency:  capability.DefaultDispatchConcurrency,
		CertExpiringFraction: nodestate.DefaultCertExpiringFraction,
	}
}

// bootServer constructs the real server from cfg and attaches it to a fresh
// bufconn listener. It returns the listener, deps, and the *grpc.Server so the
// caller can Stop it and Close the store explicitly between reboots (SQLite is a
// single writer; the second Open must not race the first handle).
func bootServer(t *testing.T, cfg Config) (*bufconn.Listener, *appDeps, *grpc.Server) {
	t.Helper()
	srv, deps, err := newServer(cfg, testStartupFiles(t, cfg))
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	lis := bufconn.Listen(1 << 20)
	go srv.Serve(lis)
	return lis, deps, srv
}

// TestRevokedNode_RefusedAfterRestart enrolls a Node, opens a Tunnel (Ping syncs
// the registry Upsert), revokes the Node, restarts the Relay, and asserts the
// revoked cert is refused on reconnect — the denylist was rehydrated from the
// persisted registry (issue #133).
// Proves DI-21.
func TestRevokedNode_RefusedAfterRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := persistTestConfig(t)
	lis, deps, srv := bootServer(t, cfg)

	// Enroll: seed a token, then Enroll certless to obtain the Node identity cert.
	_, plaintext, err := deps.tokens.Create(ctx, []string{"relay:env=prod"}, time.Hour)
	if err != nil {
		t.Fatalf("seed Enrollment Token: %v", err)
	}
	enrollConn := dialTLS(t, lis, &tls.Config{RootCAs: relaytest.CertPool(t, deps.ca.Bundle())})
	csrPEM, leafKey := relaytest.NewCSR(t, "ignored-cn")
	enrollResp, err := relayv1.NewEnrollmentClient(enrollConn).Enroll(ctx, &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             csrPEM,
		Facts:           &relayv1.Facts{Hostname: "host-133", Os: "linux"},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	nodeID := enrollResp.GetNodeId()
	clientCert := relaytest.AssembleClientCert(t, enrollResp.GetCertificate(), leafKey)
	pool := relaytest.CertPool(t, deps.ca.Bundle())

	// Open a Tunnel and send Hello; Ping is the sync point that the registry
	// Upsert (which creates the row SetRevoked will persist against) is complete.
	mtlsConn := dialTLS(t, lis, &tls.Config{Certificates: []tls.Certificate{clientCert}, RootCAs: pool})
	stream, err := relayv1.NewTunnelClient(mtlsConn).Open(ctx)
	if err != nil {
		t.Fatalf("Tunnel Open: %v", err)
	}
	if err = stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Hello{Hello: &relayv1.Hello{
			Facts: &relayv1.Facts{Hostname: "host-133", Os: "linux"},
		}},
	}); err != nil {
		t.Fatalf("send Hello: %v", err)
	}
	if msg, err := stream.Recv(); err != nil {
		t.Fatalf("recv Ping: %v", err)
	} else if msg.GetPing() == nil {
		t.Fatalf("expected Ping after Hello, got %T", msg.Body)
	}

	// Revoke, then restart the Relay against the SAME CADir + StorePath.
	deps.revocation.RevokeNode(nodeID)
	srv.Stop()
	if err := deps.store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	lis2, deps2, srv2 := bootServer(t, cfg)
	t.Cleanup(srv2.Stop)
	t.Cleanup(func() { deps2.store.Close() })

	// Reconnect with the now-revoked cert: the rehydrated denylist must refuse it
	// at (or immediately after) the TLS handshake.
	revokedConn := dialTLS(t, lis2, &tls.Config{Certificates: []tls.Certificate{clientCert}, RootCAs: pool})
	revokedStream, reconnectErr := relayv1.NewTunnelClient(revokedConn).Open(ctx)
	if reconnectErr == nil {
		_ = revokedStream.Send(&relayv1.DaemonMessage{
			Body: &relayv1.DaemonMessage_Hello{Hello: &relayv1.Hello{}},
		})
		_, reconnectErr = revokedStream.Recv()
	}
	if reconnectErr == nil {
		t.Fatal("expected rejection on reconnect with revoked Node cert after restart, got nil")
	}
}

// TestRevokedToken_EnrollRefusedAfterRestart creates an Enrollment Token,
// revokes it, restarts the Relay, and asserts an Enroll with that token is
// refused — the token store is the authority and the revocation survives the
// restart (issue #133).
func TestRevokedToken_EnrollRefusedAfterRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := persistTestConfig(t)
	lis, deps, srv := bootServer(t, cfg)

	tok, plaintext, err := deps.tokens.Create(ctx, []string{"relay:env=prod"}, time.Hour)
	if err != nil {
		t.Fatalf("seed Enrollment Token: %v", err)
	}

	// Revoke the token (cascade over an empty registry just kills the token).
	// This test's registry is empty, so the cascade records nothing through
	// this recorder; the attribution assertions for a non-empty cascade live at
	// the API seam (internal/controlplane/api).
	recordsNothingBecauseTheRegistryIsEmpty := func([]string) error { return nil }
	if err := deps.revocation.RevokeToken(ctx, tok.ID, recordsNothingBecauseTheRegistryIsEmpty); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	// Sanity: before restart the token already fails to enroll.
	caBundle := deps.ca.Bundle()
	enrollConn := dialTLS(t, lis, &tls.Config{RootCAs: relaytest.CertPool(t, caBundle)})
	csrPEM, _ := relaytest.NewCSR(t, "ignored-cn")
	if _, err := relayv1.NewEnrollmentClient(enrollConn).Enroll(ctx, &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             csrPEM,
		Facts:           &relayv1.Facts{Hostname: "host-133", Os: "linux"},
	}); err == nil {
		t.Fatal("expected Enroll with revoked token to fail before restart, got nil")
	}

	// Restart the Relay against the SAME CADir + StorePath.
	srv.Stop()
	if err := deps.store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	lis2, deps2, srv2 := bootServer(t, cfg)
	t.Cleanup(srv2.Stop)
	t.Cleanup(func() { deps2.store.Close() })

	// After restart the revoked token must STILL be refused — the store is the
	// authority, not volatile memory.
	enrollConn2 := dialTLS(t, lis2, &tls.Config{RootCAs: relaytest.CertPool(t, deps2.ca.Bundle())})
	csr2PEM, _ := relaytest.NewCSR(t, "ignored-cn")
	if _, err := relayv1.NewEnrollmentClient(enrollConn2).Enroll(ctx, &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             csr2PEM,
		Facts:           &relayv1.Facts{Hostname: "host-133", Os: "linux"},
	}); err == nil {
		t.Fatal("expected Enroll with revoked token to fail after restart, got nil")
	}
}

// TestRevokedTokenCascade_NodeRevocationsPersistAcrossRestart is #607's
// closing gap: without it, no test anywhere exercised the cascade's batch
// SetRevokedAll write against real SQLite through the production
// composition root — the existing cascade test above runs over an EMPTY
// registry and never reaches it, and TestRevokedNode_RefusedAfterRestart
// revokes through the single-Node RevokeNode path instead. This test seeds
// three registry rows under one token, cascade-revokes the token, and
// asserts both that the batch write reached deps.registry (the eventsink
// observer over the real sqliteRegistry, the production wiring) and that a
// restart rehydrates the denylist from what that transaction committed
// (#133, ADR-0006).
func TestRevokedTokenCascade_NodeRevocationsPersistAcrossRestart(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cfg := persistTestConfig(t)
	_, deps, srv := bootServer(t, cfg)

	tok, _, err := deps.tokens.Create(ctx, []string{"relay:env=prod"}, time.Hour)
	if err != nil {
		t.Fatalf("seed Enrollment Token: %v", err)
	}

	nodeIDs := []string{"casc-node-1", "casc-node-2", "casc-node-3"}
	for _, id := range nodeIDs {
		if _, err := deps.registry.Upsert(registry.Report{NodeID: id, EnrollingTokenID: tok.ID}); err != nil {
			t.Fatalf("Upsert(%s): %v", id, err)
		}
	}

	recorder := func([]string) error { return nil }
	if err := deps.revocation.RevokeToken(ctx, tok.ID, recorder); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}

	revoked, err := deps.registry.RevokedNodeIDs()
	if err != nil {
		t.Fatalf("RevokedNodeIDs: %v", err)
	}
	for _, id := range nodeIDs {
		if !slices.Contains(revoked, id) {
			t.Errorf("RevokedNodeIDs after cascade = %v, want it to contain %s — the batch write must have reached real SQLite", revoked, id)
		}
	}

	// Restart the Relay against the SAME CADir + StorePath.
	srv.Stop()
	if err := deps.store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	_, deps2, srv2 := bootServer(t, cfg)
	t.Cleanup(srv2.Stop)
	t.Cleanup(func() { deps2.store.Close() })

	for _, id := range nodeIDs {
		if !deps2.denylist.IsRevoked(id) {
			t.Errorf("%s should be denylisted after restart — the rows the chunk transaction committed are what rehydration reads", id)
		}
	}
}
