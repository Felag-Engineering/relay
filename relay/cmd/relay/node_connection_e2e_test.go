package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// nodeConnectionEnroll enrolls a Node through a token that names initialTags
// and returns its ID, client certificate and the CA pool.
func nodeConnectionEnroll(ctx context.Context, t *testing.T, f *relayFixture, initialTags []string) (string, tls.Certificate, *x509.CertPool) {
	t.Helper()
	_, plaintext, err := f.Deps.tokens.Create(ctx, initialTags, time.Hour, testHumanMinter)
	if err != nil {
		t.Fatalf("seed Enrollment Token: %v", err)
	}
	pool := relaytest.CertPool(t, f.Deps.ca.Bundle())
	csrPEM, key := relaytest.NewCSR(t, "ignored-cn")
	resp, err := relayv1.NewEnrollmentClient(dialTLS(t, f.Bufconn, &tls.Config{RootCAs: pool})).Enroll(ctx, &relayv1.EnrollRequest{
		EnrollmentToken: plaintext,
		Csr:             csrPEM,
		Facts:           &relayv1.Facts{Hostname: "enrolled-host", Os: "linux"},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	return resp.GetNodeId(), relaytest.AssembleClientCert(t, resp.GetCertificate(), key), pool
}

// The Node is the one the verified certificate names. A Hello that names a
// different Node in its deprecated node_id field changes that other Node's
// record in no way, and creates no third.
// Proves NC-3.
func TestTunnelOpen_TheNodeIsTheVerifiedCertificateNeverTheHello(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := startRelay(t)
	idA, certA, pool := nodeConnectionEnroll(ctx, t, f, nil)
	idB, _, _ := nodeConnectionEnroll(ctx, t, f, nil)
	beforeB, ok := f.Deps.registry.Get(idB)
	if !ok {
		t.Fatalf("node %s not in the registry", idB)
	}

	hello := forgeHelloNodeID(t, &relayv1.Hello{
		DaemonVersion: "9.9.9",
		Facts:         &relayv1.Facts{Hostname: "from-a"},
	}, idB)
	end := connAuditConnect(ctx, t, f, certA, pool, hello)
	defer end()

	a, _ := f.Deps.registry.Get(idA)
	if a.Facts.Hostname != "from-a" || !a.Connected {
		t.Errorf("the certificate's Node: hostname %q, connected %v, want from-a and connected", a.Facts.Hostname, a.Connected)
	}
	b, _ := f.Deps.registry.Get(idB)
	if !reflect.DeepEqual(b.Facts, beforeB.Facts) || b.DaemonVersion != beforeB.DaemonVersion || !b.LastSeen.Equal(beforeB.LastSeen) {
		t.Errorf("the Node named by the forged Hello changed: before %+v, after %+v", beforeB, b)
	}
	if b.Connected {
		t.Error("the Node named by the forged Hello reads connected")
	}
	if got := len(f.Deps.registry.List()); got != 2 {
		t.Errorf("registry holds %d Nodes, want 2", got)
	}
}

// A Node's report writes only what a Node may write. A relay:, tag: or state:
// label in its Hello is dropped, so the Relay's and the human's labels are
// exactly what they were, and only its node: label is recorded.
// Proves NC-24.
func TestTunnelOpen_ANodeReportWritesNoRelayOrTagLabel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := startRelay(t)
	nodeID, cert, pool := nodeConnectionEnroll(ctx, t, f, []string{"tag:env=prod"})

	end := connAuditConnect(ctx, t, f, cert, pool, &relayv1.Hello{
		Labels: []*relayv1.Label{
			{Key: "relay:node-id", Value: "forged"},
			{Key: "relay:quarantine", Value: "on"},
			{Key: "tag:env", Value: "attacker"},
			{Key: "state:offline", Value: "yes"},
			{Key: "node:role", Value: "web"},
		},
	})
	defer end()

	n, ok := f.Deps.registry.Get(nodeID)
	if !ok {
		t.Fatalf("node %s not in the registry", nodeID)
	}
	if want := map[string]string{"node-id": nodeID}; !reflect.DeepEqual(n.RelayLabels, want) {
		t.Errorf("RelayLabels = %v, want %v", n.RelayLabels, want)
	}
	if want := map[string]string{"env": "prod"}; !reflect.DeepEqual(n.TagLabels, want) {
		t.Errorf("TagLabels = %v, want %v", n.TagLabels, want)
	}
	if want := map[string]string{"role": "web"}; !reflect.DeepEqual(n.NodeLabels, want) {
		t.Errorf("NodeLabels = %v, want %v", n.NodeLabels, want)
	}
	if n.Quarantined() {
		t.Error("a Node's Hello quarantined the Node")
	}
}

// Each connect replaces the Node's self-reported Facts and node: labels, and
// a change in them is recorded in the registry and never audited.
// Proves NC-25.
func TestTunnelOpen_ChangedFactsAndNodeLabelsAreRecordedAndNeverAudited(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	f := startRelay(t)
	nodeID, cert, pool := nodeConnectionEnroll(ctx, t, f, nil)
	hello := func(hostname, role string) *relayv1.Hello {
		return &relayv1.Hello{
			DaemonVersion: "0.2.0",
			Facts:         &relayv1.Facts{Hostname: hostname},
			Labels:        []*relayv1.Label{{Key: "node:role", Value: role}},
		}
	}

	// connAuditSession returns only once the first stream has fully ended, so
	// the reconnect below is a new connect and not a second live stream.
	connAuditSession(ctx, t, f, cert, pool, hello("host-a", "web"))
	before, err := f.Deps.audit.ByNode(ctx, nodeID)
	if err != nil {
		t.Fatalf("ByNode: %v", err)
	}

	connAuditSession(ctx, t, f, cert, pool, hello("host-b", "db"))
	n, _ := f.Deps.registry.Get(nodeID)
	if n.Facts.Hostname != "host-b" || !reflect.DeepEqual(n.NodeLabels, map[string]string{"role": "db"}) {
		t.Errorf("registry shows hostname %q, labels %v, want host-b and role=db", n.Facts.Hostname, n.NodeLabels)
	}
	after, err := f.Deps.audit.ByNode(ctx, nodeID)
	if err != nil {
		t.Fatalf("ByNode: %v", err)
	}
	if len(after) != len(before) {
		t.Errorf("the Node has %d audit records after changing Facts and a node: label, want the %d it had before", len(after), len(before))
	}
}

// openTunnel opens a Tunnel presenting cert, sends hello and waits for the
// Ping. Unlike connAuditConnect it reports failure by returning an error, so it
// is safe off the test goroutine. The returned func ends the stream.
func openTunnel(ctx context.Context, f *relayFixture, cert tls.Certificate, pool *x509.CertPool, hello *relayv1.Hello) (func(), error) {
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return f.Bufconn.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: "localhost",
		})),
	)
	if err != nil {
		return nil, err
	}
	sctx, cancel := context.WithCancel(ctx)
	end := func() {
		cancel()
		conn.Close()
	}
	stream, err := relayv1.NewTunnelClient(conn).Open(sctx)
	if err != nil {
		end()
		return nil, err
	}
	if err := stream.Send(&relayv1.DaemonMessage{Body: &relayv1.DaemonMessage_Hello{Hello: hello}}); err != nil {
		end()
		return nil, err
	}
	msg, err := stream.Recv()
	if err != nil {
		end()
		return nil, err
	}
	if msg.GetPing() == nil {
		end()
		return nil, fmt.Errorf("expected Ping after Hello, got %T", msg.Body)
	}
	return end, nil
}

// The Relay applies no admission limit to Nodes connecting: a fleet that
// connects at once is admitted whole. A first connect and a reconnect take the
// same Open admission path, so this drives both. 32 Nodes is a sample, not a bound.
// Proves NC-18.
func TestTunnelOpen_AFleetConnectingAtOnceIsAdmittedWhole(t *testing.T) {
	const fleet = 32
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// Generous enrollment limits: they bound Enroll, not the reconnect under
	// test, and the 32 enrollments come from one loopback peer.
	f := startRelay(t, WithConfig(func(c *Config) {
		c.EnrollIPRate = 1000
		c.EnrollIPBurst = 500
		c.EnrollGlobalRate = 1000
		c.EnrollGlobalBurst = 500
	}))
	type node struct {
		id   string
		cert tls.Certificate
	}
	var pool *x509.CertPool
	nodes := make([]node, fleet)
	for i := range nodes {
		id, cert, p := nodeConnectionEnroll(ctx, t, f, nil)
		nodes[i], pool = node{id, cert}, p
	}

	var wg sync.WaitGroup
	ends := make([]func(), fleet)
	errs := make([]error, fleet)
	for i := range nodes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ends[i], errs[i] = openTunnel(ctx, f, nodes[i].cert, pool, &relayv1.Hello{})
		}()
	}
	wg.Wait()
	for i, end := range ends {
		if end != nil {
			defer end()
		}
		if errs[i] != nil {
			t.Errorf("Node %d was not admitted: %v", i, errs[i])
		}
	}
	for i, n := range nodes {
		if got, _ := f.Deps.registry.Get(n.id); !got.Connected {
			t.Errorf("Node %d reads not connected after its Tunnel was admitted", i)
		}
	}
}

// A fleet that a restarted Relay already holds in its persisted registry
// reconnects at once and is admitted whole: nothing about the restart limits
// admission. 32 Nodes is a sample, not a bound.
// Proves NC-18.
func TestTunnelOpen_AFleetReconnectingAtOnceAfterARelayRestartIsAdmittedWhole(t *testing.T) {
	const fleet = 32
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg := persistTestConfig(t)
	// Generous enrollment limits: they bound Enroll, not the reconnect under
	// test, and the 32 enrollments come from one loopback peer.
	cfg.EnrollIPRate = 1000
	cfg.EnrollIPBurst = 500
	cfg.EnrollGlobalRate = 1000
	cfg.EnrollGlobalBurst = 500

	// connectFleet opens every Node's Tunnel at once and returns the funcs that
	// end them.
	connectFleet := func(f *relayFixture, certs []tls.Certificate, pool *x509.CertPool) []func() {
		t.Helper()
		var wg sync.WaitGroup
		ends := make([]func(), fleet)
		errs := make([]error, fleet)
		for i := range certs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ends[i], errs[i] = openTunnel(ctx, f, certs[i], pool, &relayv1.Hello{})
			}()
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Errorf("Node %d was not admitted: %v", i, err)
			}
		}
		return ends
	}
	endAll := func(ends []func()) {
		for _, end := range ends {
			if end != nil {
				end()
			}
		}
	}

	lis, deps, srv := bootServer(t, cfg)
	f1 := &relayFixture{Deps: deps, Bufconn: lis}
	ids := make([]string, fleet)
	certs := make([]tls.Certificate, fleet)
	var pool *x509.CertPool
	for i := range ids {
		ids[i], certs[i], pool = nodeConnectionEnroll(ctx, t, f1, nil)
	}
	endAll(connectFleet(f1, certs, pool))

	// Every client is ended before the Relay stops, and the Relay stops before
	// the store closes: a handler's teardown writes the registry. GracefulStop
	// waits for the handlers; Stop would not.
	srv.GracefulStop()
	if err := deps.store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	lis2, deps2, srv2 := bootServer(t, cfg)
	// Cleanups run last to first: the clients end, then the Relay stops
	// gracefully and waits for its handlers, then the store closes.
	t.Cleanup(func() { deps2.store.Close() })
	t.Cleanup(srv2.GracefulStop)
	for i, id := range ids {
		n, ok := deps2.registry.Get(id)
		if !ok || n.FirstConnectedAt.IsZero() {
			t.Fatalf("Node %d is not in the restarted Relay's registry with its first connect recorded (found %v)", i, ok)
		}
	}

	f2 := &relayFixture{Deps: deps2, Bufconn: lis2}
	ends := connectFleet(f2, certs, pool)
	t.Cleanup(func() { endAll(ends) })
	for i, id := range ids {
		if got, _ := deps2.registry.Get(id); !got.Connected {
			t.Errorf("Node %d reads not connected after its Tunnel was admitted", i)
		}
	}
}
