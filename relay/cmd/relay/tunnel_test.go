package main

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/dispatch"
	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/nodestate"
	"github.com/Felag-Engineering/relay/relay/internal/policyview"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/revocation"
	transport "github.com/Felag-Engineering/relay/relay/internal/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// testStreamWithContext wraps a ServerStream, replacing its Context. Used by
// the test interceptor to inject node_id without real TLS.
type testStreamWithContext struct {
	grpc.ServerStream
	ctx context.Context
}

func (w testStreamWithContext) Context() context.Context { return w.ctx }

// injectNodeIDInterceptor returns a stream interceptor that injects nodeID via
// transport.NewContextWithNodeID, mimicking what the production mTLS interceptor
// does after cert verification.
func injectNodeIDInterceptor(nodeID string) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		enriched := transport.NewContextWithNodeID(ss.Context(), nodeID)
		return handler(srv, testStreamWithContext{ServerStream: ss, ctx: enriched})
	}
}

// newBufconnConn starts srv on an in-memory bufconn listener and returns a
// connected client conn. Both are cleaned up when t ends.
func newBufconnConn(t *testing.T, srv *grpc.Server) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// TestTunnelOpen_HelloPing verifies the Hello → Ping exchange when identity is
// driven through an interceptor (mirroring production). The injected cert
// node_id ("cert-node-1") intentionally differs from hello.NodeId
// ("hello-node-1"): receiving a Ping (not Unauthenticated) proves the handler
// accepted the interceptor-provided identity, never the wire value.
func TestTunnelOpen_HelloPing(t *testing.T) {
	const certNodeID = "cert-node-1"   // injected by interceptor (authoritative)
	const helloNodeID = "hello-node-1" // wire-supplied (must not become node_id)

	srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(certNodeID)))
	relayv1.RegisterTunnelServer(srv, &tunnelServer{})
	conn := newBufconnConn(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	err = stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Hello{
			Hello: &relayv1.Hello{
				NodeId:        helloNodeID,
				DaemonVersion: "0.0.1-test",
				Facts: &relayv1.Facts{
					Hostname: "test-host",
					Os:       "linux",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("send hello: %v", err)
	}

	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv ping: %v", err)
	}
	ping := msg.GetPing()
	if ping == nil {
		t.Fatalf("expected Ping reply, got %T", msg.Body)
	}
	if ping.UnixMillis <= 0 {
		t.Errorf("expected positive unix_millis, got %d", ping.UnixMillis)
	}
}

// TestTunnelOpen_FailClosed verifies that with no interceptor injecting
// node_id, the handler returns codes.Unauthenticated — it never falls back to
// the wire-supplied hello.NodeId.
func TestTunnelOpen_FailClosed(t *testing.T) {
	// No interceptor: NodeIDFromContext will return ok==false.
	srv := grpc.NewServer()
	relayv1.RegisterTunnelServer(srv, &tunnelServer{})
	conn := newBufconnConn(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	if err = stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Hello{
			Hello: &relayv1.Hello{
				NodeId: "attacker-supplied-id",
			},
		},
	}); err != nil {
		t.Fatalf("send hello: %v", err)
	}

	_, err = stream.Recv()
	if err == nil {
		t.Fatal("expected Unauthenticated error, got Ping")
	}
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Errorf("expected codes.Unauthenticated, got %v", code)
	}
}

// TestTunnelOpen_RevokeTearsDownLiveStream verifies that calling
// conns.Disconnect on a currently-open stream causes the client's next Recv
// to return codes.Unauthenticated. This exercises "immediate disconnect" —
// the live Tunnel stream is actively torn down, not merely blocked on reconnect.
func TestTunnelOpen_RevokeTearsDownLiveStream(t *testing.T) {
	const nodeID = "node-live"

	conns := revocation.NewConnections()
	srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(nodeID)))
	relayv1.RegisterTunnelServer(srv, &tunnelServer{conns: conns})
	conn := newBufconnConn(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	// Send Hello to advance the handler past the initial recv.
	if err := stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Hello{
			Hello: &relayv1.Hello{NodeId: nodeID},
		},
	}); err != nil {
		t.Fatalf("send hello: %v", err)
	}

	// Recv the Ping — confirms the handler is live and the stream is tracked.
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv ping: %v", err)
	}
	if msg.GetPing() == nil {
		t.Fatalf("expected Ping, got %T", msg.Body)
	}

	// Disconnect the node — this cancels the handler's derived context, which
	// causes the goroutine-fed select in Open to return Unauthenticated.
	conns.Disconnect(nodeID)

	// The next Recv from the client must fail with Unauthenticated within a
	// reasonable timeout, confirming the live stream was torn down.
	done := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected Unauthenticated after Disconnect, got nil")
		}
		if code := status.Code(err); code != codes.Unauthenticated {
			t.Errorf("expected codes.Unauthenticated, got %v", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: live stream was not torn down after Disconnect")
	}
}

// TestTunnelOpen_HelloRegistersNode verifies that sending a Hello with Facts and
// labels causes the handler to upsert the Node into the registry with correct
// facts and node: labels, and that relay: labels supplied on the stream are
// structurally dropped (acceptance criterion for issue #29).
func TestTunnelOpen_HelloRegistersNode(t *testing.T) {
	const certNodeID = "cert-node-1"
	oldTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	reg := registry.NewInMemory(registry.WithClock(func() time.Time { return oldTime }))
	srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(certNodeID)))
	relayv1.RegisterTunnelServer(srv, &tunnelServer{reg: reg})
	conn := newBufconnConn(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	if err := stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Hello{
			Hello: &relayv1.Hello{
				NodeId:        certNodeID,
				DaemonVersion: "0.0.1-test",
				Facts:         &relayv1.Facts{Hostname: "h", Os: "linux"},
				Labels: []*relayv1.Label{
					{Key: "node:role", Value: "web"},
					{Key: "relay:env", Value: "prod"}, // must be dropped: stream cannot set relay: labels
				},
			},
		},
	}); err != nil {
		t.Fatalf("send hello: %v", err)
	}

	// Recv the Ping — registration is guaranteed complete at this point because
	// the handler Upserts before sending the Ping (ordering invariant).
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv ping: %v", err)
	}
	if msg.GetPing() == nil {
		t.Fatalf("expected Ping, got %T", msg.Body)
	}

	n, ok := reg.Get(certNodeID)
	if !ok {
		t.Fatal("node not found in registry after Hello")
	}
	if n.Facts.Hostname != "h" {
		t.Errorf("Facts.Hostname: got %q, want %q", n.Facts.Hostname, "h")
	}
	if n.DaemonVersion != "0.0.1-test" {
		t.Errorf("DaemonVersion: got %q, want %q", n.DaemonVersion, "0.0.1-test")
	}
	// node:role=web is accepted; bare key stored without prefix.
	if n.NodeLabels["role"] != "web" {
		t.Errorf("NodeLabels[role]: got %q, want web", n.NodeLabels["role"])
	}
	// relay:env must have been dropped — only "role" should be in NodeLabels.
	if len(n.NodeLabels) != 1 {
		t.Errorf("NodeLabels should have exactly 1 entry, got %v", n.NodeLabels)
	}
	// Stream can never set relay-space labels.
	if len(n.RelayLabels) != 0 {
		t.Errorf("RelayLabels should be empty after Hello, got %v", n.RelayLabels)
	}
}

// TestOpen_MalformedNodeLabelDoesNotDropTheStream drives a Hello carrying one
// malformed node: label through the real Open handler and asserts the stream
// stays up (a Ping is still received) and the Node is present in the
// registry WITHOUT the malformed label — pinning D1 (#504): a refused label
// is omitted, never sanitised, and never tears down the connection. An
// unreachable Node can never be inspected, quarantined or remediated, so
// fail-closed here means failing closed on the DATA, not on the connection.
func TestOpen_MalformedNodeLabelDoesNotDropTheStream(t *testing.T) {
	const certNodeID = "cert-node-malformed"

	reg := registry.NewInMemory()
	srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(certNodeID)))
	relayv1.RegisterTunnelServer(srv, &tunnelServer{reg: reg})
	conn := newBufconnConn(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	if err := stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Hello{
			Hello: &relayv1.Hello{
				NodeId: certNodeID,
				Facts:  &relayv1.Facts{Hostname: "h", Os: "linux"},
				Labels: []*relayv1.Label{
					// The measured payload (#504's evidence).
					{Key: "node:role", Value: "web, relay:quarantine=on"},
				},
			},
		},
	}); err != nil {
		t.Fatalf("send hello: %v", err)
	}

	// The stream must stay up: a Ping still arrives.
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv ping: %v (the stream must survive a malformed node: label)", err)
	}
	if msg.GetPing() == nil {
		t.Fatalf("expected Ping, got %T", msg.Body)
	}

	n, ok := reg.Get(certNodeID)
	if !ok {
		t.Fatal("node not found in registry after Hello — a malformed label must not cost the Node its connection")
	}
	if len(n.NodeLabels) != 0 {
		t.Errorf("NodeLabels: got %v, want empty — the malformed label must be omitted, not sanitised", n.NodeLabels)
	}
}

// TestOpen_HostileNodeLabelCannotRenderTwoPredicates is modelled on
// nodestate_test.go's TestFacts_HostileDaemonVersionCannotInjectASelectorTerm:
// it drives the issue's measured payload through the REAL ingress path
// (Hello -> nodeLabelsFromHello -> registry.Upsert -> Get), re-renders every
// stored node: pair exactly as console/fleet.go's buildFacets does
// ("node:" + k + "=" + v), joins them with capability.ParseSelector's
// separator, and asserts the result is the issue's own success condition:
// no predicate ever lands in NamespaceRelay, and the predicate count matches
// the number of labels actually stored — never more.
func TestOpen_HostileNodeLabelCannotRenderTwoPredicates(t *testing.T) {
	const certNodeID = "cert-node-hostile"

	reg := registry.NewInMemory()
	srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(certNodeID)))
	relayv1.RegisterTunnelServer(srv, &tunnelServer{reg: reg})
	conn := newBufconnConn(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	if err := stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Hello{
			Hello: &relayv1.Hello{
				NodeId: certNodeID,
				Facts:  &relayv1.Facts{Hostname: "h", Os: "linux"},
				Labels: []*relayv1.Label{
					// The measured payload (#504's evidence).
					{Key: "node:role", Value: "web, relay:quarantine=on"},
					{Key: "node:site", Value: "us-east-1"},
				},
			},
		},
	}); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("recv ping: %v", err)
	}

	n, ok := reg.Get(certNodeID)
	if !ok {
		t.Fatal("node not found in registry after Hello")
	}

	rendered := make([]string, 0, len(n.NodeLabels))
	for k, v := range n.NodeLabels {
		rendered = append(rendered, "node:"+k+"="+v)
	}
	joined := strings.Join(rendered, ", ")
	sel, err := capability.ParseSelector(joined)
	if err != nil {
		t.Fatalf("ParseSelector(%q): %v", joined, err)
	}
	if len(sel.Predicates) != len(n.NodeLabels) {
		t.Fatalf("rendered %q to %d predicates, want exactly %d (one per stored label) — the issue's own two-predicate symptom",
			joined, len(sel.Predicates), len(n.NodeLabels))
	}
	for _, p := range sel.Predicates {
		if p.Namespace == capability.NamespaceRelay {
			t.Fatalf("a hostile node: label injected a relay:-spelled predicate: %+v (rendered: %q)", p, joined)
		}
	}
}

// TestTunnelOpen_HeartbeatUpdatesLastSeen verifies that receiving a Heartbeat
// causes the handler to advance the Node's LastSeen timestamp in the registry.
// The registry is seeded with a fixed old clock so Hello records LastSeen=oldTime;
// UpdateLastSeen is called with the handler's real time.Now(), which is strictly
// after oldTime, so the advance is observable.
func TestTunnelOpen_HeartbeatUpdatesLastSeen(t *testing.T) {
	const certNodeID = "cert-node-hb"
	oldTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	reg := registry.NewInMemory(registry.WithClock(func() time.Time { return oldTime }))
	srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(certNodeID)))
	relayv1.RegisterTunnelServer(srv, &tunnelServer{reg: reg})
	conn := newBufconnConn(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	if err := stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Hello{
			Hello: &relayv1.Hello{NodeId: certNodeID},
		},
	}); err != nil {
		t.Fatalf("send hello: %v", err)
	}

	// Recv the Ping — confirms the Node is registered with LastSeen=oldTime.
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv ping: %v", err)
	}
	if msg.GetPing() == nil {
		t.Fatalf("expected Ping, got %T", msg.Body)
	}

	// Verify Hello recorded LastSeen as oldTime (the fixed clock).
	n, ok := reg.Get(certNodeID)
	if !ok {
		t.Fatal("node not found in registry after Hello")
	}
	if !n.LastSeen.Equal(oldTime) {
		t.Fatalf("LastSeen after Hello: got %v, want %v", n.LastSeen, oldTime)
	}

	// Send a Heartbeat — the handler will call UpdateLastSeen(nodeID, time.Now()).
	if err := stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Heartbeat{
			Heartbeat: &relayv1.Heartbeat{UnixMillis: time.Now().UnixMilli()},
		},
	}); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}

	// Poll for LastSeen to advance past oldTime. The handler processes the
	// Heartbeat asynchronously; a select-with-timeout loop with a small sleep
	// avoids a busy-spin while bounding the test's wall-clock cost.
	found := make(chan struct{}, 1)
	go func() {
		for {
			n, ok := reg.Get(certNodeID)
			if ok && n.LastSeen.After(oldTime) {
				found <- struct{}{}
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	select {
	case <-found:
		// LastSeen advanced past oldTime — UpdateLastSeen was called.
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: LastSeen was not updated after Heartbeat")
	}
}

// TestNodeLabelsFromHello is a pure unit test for the nodeLabelsFromHello
// helper, covering both the two-namespace label-authority rule (ADR-0006)
// and the well-formedness gate (#504).
func TestNodeLabelsFromHello(t *testing.T) {
	tests := []struct {
		name        string
		input       []*relayv1.Label
		want        map[string]string
		wantRefused []string
	}{
		{
			name:  "node: prefix is accepted; bare key is stored",
			input: []*relayv1.Label{{Key: "node:role", Value: "web"}},
			want:  map[string]string{"role": "web"},
		},
		{
			name:  "relay: prefix is dropped (stream cannot set relay: labels)",
			input: []*relayv1.Label{{Key: "relay:env", Value: "prod"}},
			want:  map[string]string{},
		},
		{
			// Unlike a relay:/tag:/unprefixed key (never even an attempted
			// node: label, so silently dropped per the WHY comment above),
			// "node:" with nothing after the prefix IS an attempted node:
			// label that failed well-formedness, so it is surfaced as refused.
			name:        "node: with empty bare key is refused",
			input:       []*relayv1.Label{{Key: "node:", Value: "val"}},
			want:        map[string]string{},
			wantRefused: []string{"node:"},
		},
		{
			name:  "no namespace prefix is dropped",
			input: []*relayv1.Label{{Key: "role", Value: "web"}},
			want:  map[string]string{},
		},
		{
			// The measured payload (#504's evidence): a value that would
			// render as a second, relay:-spelled Selector term.
			name:        "malformed value is refused, not sanitised",
			input:       []*relayv1.Label{{Key: "node:role", Value: "web, relay:quarantine=on"}},
			want:        map[string]string{},
			wantRefused: []string{"node:role"},
		},
		{
			// ONE BAD LABEL DOES NOT COST THE NODE ITS GOOD ONES (D1: omission
			// is per-label).
			name: "one malformed label among good ones costs only itself",
			input: []*relayv1.Label{
				{Key: "node:role", Value: "web"},
				{Key: "node:site", Value: "a b"},
			},
			want:        map[string]string{"role": "web"},
			wantRefused: []string{"node:site"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, refused := nodeLabelsFromHello(tc.input)
			if len(got) != len(tc.want) {
				t.Errorf("len: got %d, want %d; got=%v, want=%v",
					len(got), len(tc.want), got, tc.want)
				return
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("key %q: got %q, want %q", k, got[k], v)
				}
			}
			if len(refused) != len(tc.wantRefused) {
				t.Fatalf("refused: got %v, want %v", refused, tc.wantRefused)
			}
			for i, k := range tc.wantRefused {
				if refused[i] != k {
					t.Errorf("refused[%d]: got %q, want %q", i, refused[i], k)
				}
			}
		})
	}
}

// TestSnapshotFromProto is a pure unit test for the conversion the tunnel
// handler uses to record a daemon-reported PolicySnapshot into the
// display-only policyview.Cache (#117).
func TestSnapshotFromProto(t *testing.T) {
	ps := &relayv1.PolicySnapshot{
		RawExecEnabled:    true,
		RawAllowPatterns:  []string{`^/usr/bin/systemctl restart .+$`},
		RawDenyPatterns:   []string{`.*rm -rf.*`},
		AllowedOperations: []string{"system.facts", "file.read"},
		PolicyFingerprint: "sha256:abc123",
		OperationRules: []*relayv1.OperationRule{
			{
				Name: "service.restart",
				AllowedArgs: []*relayv1.ArgMatcher{
					{Values: []string{"nginx", "php-fpm"}},
				},
			},
			{
				Name: "file.read",
				AllowedArgs: []*relayv1.ArgMatcher{
					{Values: []string{"*"}},
				},
			},
		},
		DenyRules: []*relayv1.DenyRule{
			{
				Name: "file.read",
				Args: []*relayv1.ArgMatcher{
					{Values: []string{"/etc/shadow"}},
				},
			},
		},
	}

	got := snapshotFromProto(ps)

	want := policyview.Snapshot{
		RawExecEnabled:    true,
		RawAllowPatterns:  []string{`^/usr/bin/systemctl restart .+$`},
		RawDenyPatterns:   []string{`.*rm -rf.*`},
		AllowedOperations: []string{"system.facts", "file.read"},
		PolicyFingerprint: "sha256:abc123",
	}
	if got.RawExecEnabled != want.RawExecEnabled {
		t.Errorf("RawExecEnabled = %v, want %v", got.RawExecEnabled, want.RawExecEnabled)
	}
	if got.PolicyFingerprint != want.PolicyFingerprint {
		t.Errorf("PolicyFingerprint = %q, want %q", got.PolicyFingerprint, want.PolicyFingerprint)
	}
	if len(got.RawAllowPatterns) != 1 || got.RawAllowPatterns[0] != want.RawAllowPatterns[0] {
		t.Errorf("RawAllowPatterns = %v, want %v", got.RawAllowPatterns, want.RawAllowPatterns)
	}
	if len(got.RawDenyPatterns) != 1 || got.RawDenyPatterns[0] != want.RawDenyPatterns[0] {
		t.Errorf("RawDenyPatterns = %v, want %v", got.RawDenyPatterns, want.RawDenyPatterns)
	}
	if len(got.AllowedOperations) != 2 {
		t.Errorf("AllowedOperations = %v, want 2 entries", got.AllowedOperations)
	}

	wantOperationRules := []policyview.OperationRule{
		{Name: "service.restart", AllowedArgs: [][]string{{"nginx", "php-fpm"}}},
		{Name: "file.read", AllowedArgs: [][]string{{"*"}}},
	}
	if !reflect.DeepEqual(got.OperationRules, wantOperationRules) {
		t.Errorf("OperationRules = %+v, want %+v", got.OperationRules, wantOperationRules)
	}

	wantDenyRules := []policyview.DenyRule{
		{Name: "file.read", Args: [][]string{{"/etc/shadow"}}},
	}
	if !reflect.DeepEqual(got.DenyRules, wantDenyRules) {
		t.Errorf("DenyRules = %+v, want %+v", got.DenyRules, wantDenyRules)
	}

	// Deep-copy check: mutating the source proto's nested values must not
	// reach into the converted policyview.Snapshot (display-only cache
	// discipline; ADR-0002).
	ps.OperationRules[0].AllowedArgs[0].Values[0] = "MUTATED"
	ps.DenyRules[0].Args[0].Values[0] = "MUTATED"
	if got.OperationRules[0].AllowedArgs[0][0] != "nginx" {
		t.Errorf("OperationRules were not deep-copied: got %q, want %q",
			got.OperationRules[0].AllowedArgs[0][0], "nginx")
	}
	if got.DenyRules[0].Args[0][0] != "/etc/shadow" {
		t.Errorf("DenyRules were not deep-copied: got %q, want %q",
			got.DenyRules[0].Args[0][0], "/etc/shadow")
	}
}

// TestTunnelOpen_PolicySnapshotCapturesIntoCache verifies that sending a
// DaemonMessage.policy causes the handler to record it into the
// tunnelServer's policyview.Cache, keyed by the cert-derived nodeID (the
// injected interceptor identity, never a wire value — PolicySnapshot itself
// carries no node_id field, so this also proves the handler never confuses
// "which stream sent this" with anything on the wire). This is the capture
// wiring for #117's describe_node.
func TestTunnelOpen_PolicySnapshotCapturesIntoCache(t *testing.T) {
	const certNodeID = "cert-node-policy"

	cache := policyview.New()
	srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(certNodeID)))
	relayv1.RegisterTunnelServer(srv, &tunnelServer{policy: cache})
	conn := newBufconnConn(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	if err := stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Hello{
			Hello: &relayv1.Hello{NodeId: certNodeID},
		},
	}); err != nil {
		t.Fatalf("send hello: %v", err)
	}

	// Recv the Ping — confirms the handler is past Hello and into the recvMsg
	// select loop that handles PolicySnapshot.
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv ping: %v", err)
	}
	if msg.GetPing() == nil {
		t.Fatalf("expected Ping, got %T", msg.Body)
	}

	if err := stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Policy{
			Policy: &relayv1.PolicySnapshot{
				RawExecEnabled:    true,
				AllowedOperations: []string{"system.facts"},
				PolicyFingerprint: "sha256:live",
			},
		},
	}); err != nil {
		t.Fatalf("send policy snapshot: %v", err)
	}

	// The handler processes the PolicySnapshot asynchronously; poll for the
	// cache entry to appear rather than assuming synchronous delivery.
	found := make(chan struct{}, 1)
	go func() {
		for {
			if _, ok := cache.Get(certNodeID); ok {
				found <- struct{}{}
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	select {
	case <-found:
		got, ok := cache.Get(certNodeID)
		if !ok {
			t.Fatal("cache.Get after found signal: ok = false")
		}
		if got.PolicyFingerprint != "sha256:live" {
			t.Errorf("PolicyFingerprint = %q, want %q", got.PolicyFingerprint, "sha256:live")
		}
		if !got.RawExecEnabled {
			t.Error("RawExecEnabled = false, want true")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: PolicySnapshot was not captured into the policyview.Cache")
	}
}

// openNodeStream opens a Tunnel stream, sends Hello and waits for the Ping, so
// the Node is registered (and marked connected) when it returns.
func openNodeStream(ctx context.Context, t *testing.T, conn *grpc.ClientConn, nodeID string) grpc.BidiStreamingClient[relayv1.DaemonMessage, relayv1.RelayMessage] {
	t.Helper()
	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if err := stream.Send(&relayv1.DaemonMessage{
		Body: &relayv1.DaemonMessage_Hello{Hello: &relayv1.Hello{NodeId: nodeID}},
	}); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv ping: %v", err)
	}
	if msg.GetPing() == nil {
		t.Fatalf("expected Ping, got %T", msg.Body)
	}
	return stream
}

// nodeMarkedOffline reports whether the registry's record of nodeID carries the
// state:offline marker, the way every surface derives it.
func nodeMarkedOffline(t *testing.T, reg registry.Repository, nodeID string) bool {
	t.Helper()
	n, ok := reg.Get(nodeID)
	if !ok {
		t.Fatalf("node %q not in the registry", nodeID)
	}
	for _, m := range nodestate.Markers(nodestate.Input{Node: n}) {
		if m.Key == string(nodestate.MarkerOffline) {
			return true
		}
	}
	return false
}

func waitUntil(t *testing.T, what string, within time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestTunnelServer_DefaultDeadlineIsThreeHeartbeatIntervals(t *testing.T) {
	if got, want := (&tunnelServer{}).livenessDeadline(), 3*60*time.Second; got != want {
		t.Fatalf("default liveness deadline = %v, want %v", got, want)
	}
}

// A Node that sends no Heartbeat within the deadline is closed with
// Unavailable, marked offline, and its last_seen stays the last heartbeat.
func TestTunnelOpen_MissedHeartbeatsMarkOfflineAndCloseStream(t *testing.T) {
	const nodeID = "node-missed-hb"
	oldTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	reg := registry.NewInMemory(registry.WithClock(func() time.Time { return oldTime }))
	srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(nodeID)))
	relayv1.RegisterTunnelServer(srv, &tunnelServer{reg: reg, heartbeatDeadline: 200 * time.Millisecond})
	conn := newBufconnConn(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream := openNodeStream(ctx, t, conn, nodeID)

	if n, _ := reg.Get(nodeID); !n.Connected {
		t.Fatal("node not connected after Hello")
	}
	if nodeMarkedOffline(t, reg, nodeID) {
		t.Fatal("a connected node carries the offline marker")
	}

	_, err := stream.Recv()
	if got := status.Code(err); got != codes.Unavailable {
		t.Fatalf("Recv after the deadline = %v, want code Unavailable", err)
	}
	waitUntil(t, "node marked not connected", 5*time.Second, func() bool {
		n, _ := reg.Get(nodeID)
		return !n.Connected
	})
	if !nodeMarkedOffline(t, reg, nodeID) {
		t.Fatal("a node that missed its heartbeats does not carry the offline marker")
	}
	if n, _ := reg.Get(nodeID); !n.LastSeen.Equal(oldTime) {
		t.Fatalf("LastSeen = %v, want it left at the last heartbeat (%v)", n.LastSeen, oldTime)
	}
}

func TestTunnelOpen_HeartbeatsWithinDeadlineKeepNodeConnected(t *testing.T) {
	const nodeID = "node-steady-hb"
	reg := registry.NewInMemory()
	srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(nodeID)))
	relayv1.RegisterTunnelServer(srv, &tunnelServer{reg: reg, heartbeatDeadline: time.Second})
	conn := newBufconnConn(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream := openNodeStream(ctx, t, conn, nodeID)

	recvDone := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		recvDone <- err
	}()

	// Three times the deadline, so only the heartbeats can be keeping it open;
	// the deadline is wide enough that a slow -race run does not trip it.
	end := time.Now().Add(3 * time.Second)
	for time.Now().Before(end) {
		if err := stream.Send(&relayv1.DaemonMessage{
			Body: &relayv1.DaemonMessage_Heartbeat{Heartbeat: &relayv1.Heartbeat{UnixMillis: time.Now().UnixMilli()}},
		}); err != nil {
			t.Fatalf("send heartbeat: %v", err)
		}
		select {
		case err := <-recvDone:
			t.Fatalf("stream closed while heartbeats were arriving: %v", err)
		case <-time.After(100 * time.Millisecond):
		}
	}
	if n, _ := reg.Get(nodeID); !n.Connected {
		t.Fatal("node not connected while its heartbeats arrive within the deadline")
	}
}

// Only a Heartbeat is liveness evidence: other traffic never extends the
// deadline.
func TestTunnelOpen_OnlyHeartbeatsResetTheDeadline(t *testing.T) {
	const nodeID = "node-chatty"
	reg := registry.NewInMemory()
	srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(nodeID)))
	relayv1.RegisterTunnelServer(srv, &tunnelServer{reg: reg, heartbeatDeadline: 300 * time.Millisecond})
	conn := newBufconnConn(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream := openNodeStream(ctx, t, conn, nodeID)

	recvDone := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		recvDone <- err
	}()
	for {
		select {
		case err := <-recvDone:
			if got := status.Code(err); got != codes.Unavailable {
				t.Fatalf("stream ended with %v, want code Unavailable", err)
			}
			return
		case <-time.After(50 * time.Millisecond):
			_ = stream.Send(&relayv1.DaemonMessage{
				Body: &relayv1.DaemonMessage_TaskResult{TaskResult: &relayv1.TaskResult{TaskId: "no-such-task"}},
			})
		case <-ctx.Done():
			t.Fatal("stream never closed although only TaskResults arrived")
		}
	}
}

// registerSignalSink wraps a taskSink to say when a register call has
// returned and when its unregister has fully run.
type registerSignalSink struct {
	taskSink
	registered   chan struct{}
	unregistered chan struct{}
}

func newRegisterSignalSink(inner taskSink) *registerSignalSink {
	return &registerSignalSink{
		taskSink:     inner,
		registered:   make(chan struct{}, 8),
		unregistered: make(chan struct{}, 8),
	}
}

func (s *registerSignalSink) register(nodeID string, send func(*relayv1.RelayMessage) error, opts ...dispatch.RegisterOption) func() {
	unregister := s.taskSink.register(nodeID, send, opts...)
	s.registered <- struct{}{}
	return func() {
		unregister()
		s.unregistered <- struct{}{}
	}
}

func awaitSignal(t *testing.T, what string, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timeout waiting for %s", what)
	}
}

// The end of a replaced stream never marks the live Node offline: the registry
// keeps the Node connected for as long as its newer stream lives.
func TestTunnelOpen_ReplacedStreamEndDoesNotMarkLiveNodeOffline(t *testing.T) {
	const nodeID = "node-replaced"

	run := func(t *testing.T, sink *registerSignalSink) registry.Repository {
		reg := registry.NewInMemory()
		// handlerDone fires as each Open handler returns, deferred teardown
		// included, so the test waits on A's teardown having run rather than
		// on a delay.
		handlerDone := make(chan struct{}, 2)
		inject := injectNodeIDInterceptor(nodeID)
		srv := grpc.NewServer(grpc.StreamInterceptor(func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			defer func() { handlerDone <- struct{}{} }()
			return inject(srv, ss, info, handler)
		}))
		ts := &tunnelServer{reg: reg}
		if sink != nil {
			ts.sink = sink
		}
		relayv1.RegisterTunnelServer(srv, ts)
		conn := newBufconnConn(t, srv)

		ctxA, cancelA := context.WithCancel(context.Background())
		defer cancelA()
		ctxB, cancelB := context.WithCancel(context.Background())
		defer cancelB()

		openNodeStream(ctxA, t, conn, nodeID)
		if sink != nil {
			awaitSignal(t, "stream A to register", sink.registered)
		}
		openNodeStream(ctxB, t, conn, nodeID)
		if sink != nil {
			awaitSignal(t, "stream B to register", sink.registered)
		}

		cancelA()
		awaitSignal(t, "stream A's handler to return", handlerDone)
		if sink != nil {
			awaitSignal(t, "stream A's teardown", sink.unregistered)
		}

		if n, _ := reg.Get(nodeID); !n.Connected {
			t.Fatal("the end of a replaced stream marked the live node not connected")
		}
		if nodeMarkedOffline(t, reg, nodeID) {
			t.Fatal("the end of a replaced stream marked the live node offline")
		}
		return reg
	}

	t.Run("claim alone", func(t *testing.T) {
		run(t, nil)
	})

	t.Run("with a router", func(t *testing.T) {
		var offlineCalls atomic.Int32
		router := dispatch.NewRouter(nil, nil, dispatch.WithOnOffline(func(string, map[string]struct{}) {
			offlineCalls.Add(1)
		}))
		run(t, newRegisterSignalSink(routerSink{r: router}))
		if got := offlineCalls.Load(); got != 0 {
			t.Fatalf("offline hook ran %d times for a replaced registration, want 0", got)
		}
	})
}

// A Node that reconnects while the offline resolution of its previous stream
// is still running reads connected throughout, and stays connected after.
func TestTunnelOpen_ReconnectDuringOfflineResolutionStaysConnected(t *testing.T) {
	const nodeID = "node-flap"
	reg := registry.NewInMemory()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	router := dispatch.NewRouter(nil, nil, dispatch.WithOnOffline(func(string, map[string]struct{}) {
		entered <- struct{}{}
		<-release
	}))
	sink := newRegisterSignalSink(routerSink{r: router})

	srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(nodeID)))
	relayv1.RegisterTunnelServer(srv, &tunnelServer{reg: reg, sink: sink})
	conn := newBufconnConn(t, srv)

	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()

	openNodeStream(ctxA, t, conn, nodeID)
	awaitSignal(t, "stream A to register", sink.registered)

	cancelA()
	awaitSignal(t, "the offline resolution to start", entered)
	if n, _ := reg.Get(nodeID); n.Connected {
		t.Fatal("node reads connected while its stream's offline resolution runs")
	}

	// B's Ping is sent before it registers, so it arrives while Register waits
	// behind the offline resolution.
	openNodeStream(ctxB, t, conn, nodeID)
	if n, _ := reg.Get(nodeID); !n.Connected {
		t.Fatal("reconnected node does not read connected")
	}
	if router.Connected(nodeID) {
		t.Fatal("the new registration was not held behind the offline resolution")
	}

	close(release)
	waitUntil(t, "the new registration", 5*time.Second, func() bool { return router.Connected(nodeID) })
	awaitSignal(t, "stream A's teardown", sink.unregistered)
	if n, _ := reg.Get(nodeID); !n.Connected {
		t.Fatal("the old stream's teardown marked the reconnected node not connected")
	}
	if nodeMarkedOffline(t, reg, nodeID) {
		t.Fatal("the reconnected node carries the offline marker")
	}
}

// holdSecondRegister wraps a registerSignalSink so the second register call
// pauses, signalling held, until release is closed. It stops a replacement
// stream between its claim on the Node and its Router registration.
type holdSecondRegister struct {
	*registerSignalSink
	calls   atomic.Int32
	held    chan struct{}
	release chan struct{}
}

func (s *holdSecondRegister) register(nodeID string, send func(*relayv1.RelayMessage) error, opts ...dispatch.RegisterOption) func() {
	if s.calls.Add(1) == 2 {
		s.held <- struct{}{}
		<-s.release
	}
	return s.registerSignalSink.register(nodeID, send, opts...)
}

// A stream that ends after a newer one has claimed the Node but before that one
// has registered with the Router must not resolve its Tasks as node-offline:
// the Node is reconnecting. The Task stays Dispatched, the replacement's
// registration re-sends it for its result, and the real result the replacement
// delivers is the one recorded.
func TestTunnelOpen_OldStreamEndingBeforeTheReplacementRegistersRunsNoOfflineResolution(t *testing.T) {
	const nodeID = "node-handover"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tasks, st := testTaskRepositoryWithStore(t)
	// The production stack, except that the first connect does not reconcile:
	// the test sends the Task on stream A itself.
	var reconciler *dispatch.Reconciler
	var connects atomic.Int32
	router := dispatch.NewRouter(func(id string) {
		if connects.Add(1) > 1 {
			_ = reconciler.ReconcileNode(ctx, id)
		}
	}, nil, dispatch.WithOnOffline(func(id string, delivered map[string]struct{}) {
		_ = reconciler.ResolveOffline(ctx, id, delivered)
	}))
	reconciler = dispatch.NewReconciler(tasks, router)
	reg := registry.NewInMemory()
	sink := &holdSecondRegister{
		registerSignalSink: newRegisterSignalSink(routerSink{r: router}),
		held:               make(chan struct{}, 1),
		release:            make(chan struct{}),
	}

	task := seedDispatchedTask(t, st, tasks, nodeID, "task-1")

	srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(nodeID)))
	relayv1.RegisterTunnelServer(srv, &tunnelServer{reg: reg, sink: sink})
	conn := newBufconnConn(t, srv)

	ctxA, cancelA := context.WithCancel(ctx)
	defer cancelA()
	ctxB, cancelB := context.WithCancel(ctx)
	defer cancelB()

	streamA := openNodeStream(ctxA, t, conn, nodeID)
	awaitSignal(t, "stream A to register", sink.registered)

	dispatched := make(chan error, 1)
	go func() {
		_, err := router.Dispatch(ctx, nodeID, task)
		dispatched <- err
	}()
	if msg, err := streamA.Recv(); err != nil || msg.GetTask().GetTaskId() != task.ID {
		t.Fatalf("stream A received (%v, %v), want the Task", msg, err)
	}

	// B claims the Node and is held before its Router registration.
	streamB := openNodeStream(ctxB, t, conn, nodeID)
	awaitSignal(t, "stream B to reach its registration", sink.held)

	cancelA()
	awaitSignal(t, "stream A's teardown", sink.unregistered)

	select {
	case err := <-dispatched:
		if !errors.Is(err, jobs.ErrStreamReplaced) {
			t.Errorf("Dispatch error = %v, want jobs.ErrStreamReplaced", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Dispatch did not return after stream A ended")
	}
	if got, err := tasks.Get(ctx, task.ID); err != nil || got.State != jobs.DispatchStateDispatched {
		t.Fatalf("task = %+v (%v), want it still Dispatched: the Node is reconnecting, not offline", got, err)
	}
	if n, _ := reg.Get(nodeID); !n.Connected {
		t.Fatal("the old stream's end marked the reconnecting node not connected")
	}

	// B registers, its reconnect re-sends the Task for its result, and the real
	// result it delivers is recorded.
	close(sink.release)
	awaitSignal(t, "stream B to register", sink.registered)
	if msg, err := streamB.Recv(); err != nil || msg.GetTask().GetTaskId() != task.ID {
		t.Fatalf("stream B received (%v, %v), want the Task re-sent for its result", msg, err)
	}
	if err := streamB.Send(&relayv1.DaemonMessage{Body: &relayv1.DaemonMessage_TaskResult{
		TaskResult: &relayv1.TaskResult{TaskId: task.ID, Outcome: relayv1.Outcome_OUTCOME_SUCCESS},
	}}); err != nil {
		t.Fatalf("send TaskResult: %v", err)
	}
	waitUntil(t, "the real result to be recorded", 5*time.Second, func() bool {
		got, err := tasks.Get(ctx, task.ID)
		return err == nil && got.State == jobs.DispatchStateResolved && got.Outcome == jobs.OutcomeSuccess
	})

	cancelB()
	awaitSignal(t, "stream B's teardown", sink.unregistered)
}
