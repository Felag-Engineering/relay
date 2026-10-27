package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
	"google.golang.org/grpc/test/bufconn"
)

type revokedDialClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *revokedDialClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *revokedDialClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// dialRefused makes exactly one raw TLS dial with cfg and requires the Relay
// to refuse it. Raw TLS rather than a gRPC channel, so each call is one
// handshake and the count is deterministic. A timeout is not a refusal: the
// error must be the server's alert, not a deadline.
func dialRefused(t *testing.T, lis *bufconn.Listener, cfg *tls.Config) {
	t.Helper()
	raw, err := lis.Dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	client := tls.Client(raw, cfg)
	err = client.Handshake()
	if err == nil {
		// TLS 1.3: the client finishes its handshake before the server's
		// verdict; the refusal arrives as an alert on the first read.
		_, err = client.Read(make([]byte, 1))
	}
	if err == nil {
		t.Fatal("a revoked Node's certificate was admitted")
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("revoked dial timed out instead of being refused: %v", err)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("revoked dial timed out instead of being refused: %v", err)
	}
}

// TestRevokedNode_DialAuditedThenThrottled proves DI-23: a revoked Node's
// refused dial is recorded at once, then at most once per hour carrying the
// count it suppressed, and the Relay never reaches back to the Node (DI-21).
func TestRevokedNode_DialAuditedThenThrottled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	clk := &revokedDialClock{t: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	f := startRelay(t, WithRevokedDialClock(clk.Now))
	deps, lis := f.Deps, f.Bufconn

	_, plaintext, err := deps.tokens.Create(ctx, nil, time.Hour)
	if err != nil {
		t.Fatalf("seed Enrollment Token: %v", err)
	}
	pool := relaytest.CertPool(t, deps.ca.Bundle())
	enrollConn := dialTLS(t, lis, &tls.Config{RootCAs: pool})
	csrPEM, leafKey := relaytest.NewCSR(t, "ignored-cn")
	enrollResp, err := relayv1.NewEnrollmentClient(enrollConn).Enroll(ctx, &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             csrPEM,
		Facts:           &relayv1.Facts{Hostname: "host-1005", Os: "linux"},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	nodeID := enrollResp.GetNodeId()
	clientCert := relaytest.AssembleClientCert(t, enrollResp.GetCertificate(), leafKey)

	// Ping is the sync point that the registry row exists before the revoke.
	mtlsConn := dialTLS(t, lis, &tls.Config{Certificates: []tls.Certificate{clientCert}, RootCAs: pool})
	stream, err := relayv1.NewTunnelClient(mtlsConn).Open(ctx)
	if err != nil {
		t.Fatalf("Tunnel Open: %v", err)
	}
	if err = stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Hello{Hello: &relayv1.Hello{
			Facts: &relayv1.Facts{Hostname: "host-1005", Os: "linux"},
		}},
	}); err != nil {
		t.Fatalf("send Hello: %v", err)
	}
	if msg, err := stream.Recv(); err != nil {
		t.Fatalf("recv Ping: %v", err)
	} else if msg.GetPing() == nil {
		t.Fatalf("expected Ping after Hello, got %T", msg.Body)
	}

	deps.revocation.RevokeNode(nodeID)

	redial := func(n int) {
		for i := 0; i < n; i++ {
			dialRefused(t, lis, &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				RootCAs:      pool,
				ServerName:   "localhost",
				MinVersion:   tls.VersionTLS13,
				NextProtos:   []string{"h2"},
			})
		}
	}
	records := func() []audit.Record {
		t.Helper()
		all, err := deps.audit.ByNode(ctx, nodeID)
		if err != nil {
			t.Fatalf("ByNode: %v", err)
		}
		var out []audit.Record
		for _, r := range all {
			if r.Kind == audit.KindRevokedNodeDial {
				out = append(out, r)
			}
		}
		return out
	}

	redial(5)
	recs := records()
	if len(recs) != 1 {
		t.Fatalf("records after 5 refused dials = %d, want 1", len(recs))
	}
	if recs[0].NodeID != nodeID || recs[0].Reason != "suppressed=0" || recs[0].Principal != "" {
		t.Errorf("first record = NodeID %q Reason %q Principal %q, want %q / suppressed=0 / empty",
			recs[0].NodeID, recs[0].Reason, recs[0].Principal, nodeID)
	}

	clk.Advance(59 * time.Minute)
	redial(1)
	if n := len(records()); n != 1 {
		t.Fatalf("records inside the window = %d, want 1", n)
	}

	clk.Advance(time.Minute)
	redial(1)
	recs = records()
	if len(recs) != 2 {
		t.Fatalf("records after the window = %d, want 2", len(recs))
	}
	// 4 further dials at the first instant and 1 at +59m were suppressed.
	if recs[1].Reason != "suppressed=5" {
		t.Errorf("second record Reason = %q, want suppressed=5", recs[1].Reason)
	}

	// Nothing was admitted and nothing reached back to the Node (DI-21): the
	// revoke dropped the live Tunnel and no redial created another.
	deadline := time.Now().Add(5 * time.Second)
	for deps.conns.Count() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := deps.conns.Count(); n != 0 {
		t.Errorf("tracked connections = %d, want 0", n)
	}
}
