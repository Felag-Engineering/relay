package main

import (
	"context"
	"net"
	"testing"
	"time"

	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestTunnelOpen_HelloPing(t *testing.T) {
	lis := bufconn.Listen(1 << 20)

	srv := grpc.NewServer()
	gleipnirv1.RegisterTunnelServer(srv, &tunnelServer{})
	go srv.Serve(lis) //nolint:errcheck
	defer srv.Stop()

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
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stream, err := gleipnirv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	err = stream.Send(&gleipnirv1.DaemonMessage{
		Body: &gleipnirv1.DaemonMessage_Hello{
			Hello: &gleipnirv1.Hello{
				NodeId:        "test-node-1",
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
