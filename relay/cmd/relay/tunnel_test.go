package main

import (
	"context"
	"net"
	"testing"
	"time"

	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/revocation"
	transport "github.com/Felag-Engineering/gleipnir-relay/relay/internal/transport"
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
	go srv.Serve(lis) //nolint:errcheck
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
	gleipnirv1.RegisterTunnelServer(srv, &tunnelServer{})
	conn := newBufconnConn(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := gleipnirv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	err = stream.Send(&gleipnirv1.DaemonMessage{
		Body: &gleipnirv1.DaemonMessage_Hello{
			Hello: &gleipnirv1.Hello{
				NodeId:        helloNodeID,
				DaemonVersion: "0.0.1-test",
				Facts: &gleipnirv1.Facts{
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
	gleipnirv1.RegisterTunnelServer(srv, &tunnelServer{})
	conn := newBufconnConn(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := gleipnirv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	if err = stream.Send(&gleipnirv1.DaemonMessage{
		Body: &gleipnirv1.DaemonMessage_Hello{
			Hello: &gleipnirv1.Hello{
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
	gleipnirv1.RegisterTunnelServer(srv, &tunnelServer{conns: conns})
	conn := newBufconnConn(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := gleipnirv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	// Send Hello to advance the handler past the initial recv.
	if err := stream.Send(&gleipnirv1.DaemonMessage{
		Body: &gleipnirv1.DaemonMessage_Hello{
			Hello: &gleipnirv1.Hello{NodeId: nodeID},
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
	gleipnirv1.RegisterTunnelServer(srv, &tunnelServer{reg: reg})
	conn := newBufconnConn(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := gleipnirv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	if err := stream.Send(&gleipnirv1.DaemonMessage{
		Body: &gleipnirv1.DaemonMessage_Hello{
			Hello: &gleipnirv1.Hello{
				NodeId:        certNodeID,
				DaemonVersion: "0.0.1-test",
				Facts:         &gleipnirv1.Facts{Hostname: "h", Os: "linux"},
				Labels: []*gleipnirv1.Label{
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
	gleipnirv1.RegisterTunnelServer(srv, &tunnelServer{reg: reg})
	conn := newBufconnConn(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := gleipnirv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	if err := stream.Send(&gleipnirv1.DaemonMessage{
		Body: &gleipnirv1.DaemonMessage_Hello{
			Hello: &gleipnirv1.Hello{NodeId: certNodeID},
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
	if err := stream.Send(&gleipnirv1.DaemonMessage{
		Body: &gleipnirv1.DaemonMessage_Heartbeat{
			Heartbeat: &gleipnirv1.Heartbeat{UnixMillis: time.Now().UnixMilli()},
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

// TestNodeLabelsFromHello is a pure unit test for the nodeLabelsFromHello helper.
func TestNodeLabelsFromHello(t *testing.T) {
	tests := []struct {
		name  string
		input []*gleipnirv1.Label
		want  map[string]string
	}{
		{
			name:  "node: prefix is accepted; bare key is stored",
			input: []*gleipnirv1.Label{{Key: "node:role", Value: "web"}},
			want:  map[string]string{"role": "web"},
		},
		{
			name:  "relay: prefix is dropped (stream cannot set relay: labels)",
			input: []*gleipnirv1.Label{{Key: "relay:env", Value: "prod"}},
			want:  map[string]string{},
		},
		{
			name:  "node: with empty bare key is dropped",
			input: []*gleipnirv1.Label{{Key: "node:", Value: "val"}},
			want:  map[string]string{},
		},
		{
			name:  "no namespace prefix is dropped",
			input: []*gleipnirv1.Label{{Key: "role", Value: "web"}},
			want:  map[string]string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := nodeLabelsFromHello(tc.input)
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
		})
	}
}

// TestSnapshotFromProto is a pure unit test for the conversion the tunnel
// handler uses to record a daemon-reported PolicySnapshot into the
// display-only policyview.Cache (#117).
func TestSnapshotFromProto(t *testing.T) {
	ps := &gleipnirv1.PolicySnapshot{
		RawExecEnabled:    true,
		RawAllowPatterns:  []string{`^/usr/bin/systemctl restart .+$`},
		RawDenyPatterns:   []string{`.*rm -rf.*`},
		AllowedOperations: []string{"system.facts", "file.read"},
		PolicyFingerprint: "sha256:abc123",
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
	gleipnirv1.RegisterTunnelServer(srv, &tunnelServer{policy: cache})
	conn := newBufconnConn(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := gleipnirv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	if err := stream.Send(&gleipnirv1.DaemonMessage{
		Body: &gleipnirv1.DaemonMessage_Hello{
			Hello: &gleipnirv1.Hello{NodeId: certNodeID},
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

	if err := stream.Send(&gleipnirv1.DaemonMessage{
		Body: &gleipnirv1.DaemonMessage_Policy{
			Policy: &gleipnirv1.PolicySnapshot{
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
