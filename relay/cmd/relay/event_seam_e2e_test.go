// Package main: event_seam_e2e_test.go is #416's composition-root proof —
// the event seam (internal/events, internal/eventsink) actually wired into
// the real Relay: a real daemon connect over the real mTLS Tunnel produces a
// TransitionConnected registry event, and the stream closing produces
// TransitionDisconnected. Everything else about the seam (four publishers,
// gap/resume semantics, the structural no-read-output guards) is unit-tested
// in internal/events and internal/eventsink; this file only proves the
// composition root actually subscribes callers to the real thing.
package main

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/events"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// recvRegistryEvent reads the next KindRegistry event off sub or fails the test.
func recvRegistryEvent(t *testing.T, sub *events.Subscription) *events.RegistryEvent {
	t.Helper()
	select {
	case ev := <-sub.C():
		if ev.Kind != events.KindRegistry || ev.Registry == nil {
			t.Fatalf("got a non-registry event: %+v", ev)
		}
		return ev.Registry
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a registry event")
		return nil
	}
}

// TestEventSeam_RealDaemonConnectDisconnect drives a real Enroll + real mTLS
// Tunnel connect against the real composition root (newServer) and asserts
// the event bus it wires (deps.events) sees TransitionConnected when the
// stream opens and TransitionDisconnected when it closes — the acceptance
// line "registry (connect, disconnect, ... never heartbeats)" proven against
// the actual wiring, not a mock registry.
func TestEventSeam_RealDaemonConnectDisconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	lis, deps := startRealServer(t)

	_, plaintext, err := deps.tokens.Create(ctx, []string{"relay:env=prod"}, time.Hour)
	if err != nil {
		t.Fatalf("seed Enrollment Token: %v", err)
	}

	enrollConn := dialTLS(t, lis, &tls.Config{RootCAs: relaytest.CertPool(t, deps.ca.Bundle())})
	csrPEM, leafKey := relaytest.NewCSR(t, "ignored-cn")
	enrollResp, err := relayv1.NewEnrollmentClient(enrollConn).Enroll(ctx, &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             csrPEM,
		Facts:           &relayv1.Facts{Hostname: "host-event-seam", Os: "linux"},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	nodeID := enrollResp.GetNodeId()
	if nodeID == "" {
		t.Fatal("Enroll: node_id is empty")
	}

	// Subscribed AFTER Enroll completes: Enroll's own SetRelayLabels call
	// (handler.go step k) publishes a TransitionLabelsChanged this test is
	// not about — subscribing here isolates the Tunnel connect/disconnect
	// this test asserts on.
	sub := deps.events.Subscribe([]events.Kind{events.KindRegistry}, "")
	defer sub.Close()

	clientCert := relaytest.AssembleClientCert(t, enrollResp.GetCertificate(), leafKey)
	pool := relaytest.CertPool(t, deps.ca.Bundle())

	mtlsConn := dialTLS(t, lis, &tls.Config{Certificates: []tls.Certificate{clientCert}, RootCAs: pool})
	stream, err := relayv1.NewTunnelClient(mtlsConn).Open(ctx)
	if err != nil {
		t.Fatalf("Tunnel Open: %v", err)
	}
	if err := stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Hello{
			Hello: &relayv1.Hello{Facts: &relayv1.Facts{Hostname: "host-event-seam", Os: "linux"}},
		},
	}); err != nil {
		t.Fatalf("send Hello: %v", err)
	}
	// Ping is the sync point: SetConnected(true) runs before the Upsert that
	// precedes it (tunnel.go), so by the time Ping arrives the connect event
	// has already been published.
	if msg, err := stream.Recv(); err != nil || msg.GetPing() == nil {
		t.Fatalf("recv Ping: msg=%+v err=%v", msg, err)
	}

	connected := recvRegistryEvent(t, sub)
	if connected.Transition != events.TransitionConnected || connected.NodeID != nodeID {
		t.Fatalf("first registry event = %+v, want TransitionConnected for %s", connected, nodeID)
	}

	if err := mtlsConn.Close(); err != nil {
		t.Fatalf("close mTLS conn: %v", err)
	}

	disconnected := recvRegistryEvent(t, sub)
	if disconnected.Transition != events.TransitionDisconnected || disconnected.NodeID != nodeID {
		t.Fatalf("second registry event = %+v, want TransitionDisconnected for %s", disconnected, nodeID)
	}
}
