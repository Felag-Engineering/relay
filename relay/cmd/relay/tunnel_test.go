package main

import (
	"context"
	"net"
	"testing"
	"time"

	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
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
