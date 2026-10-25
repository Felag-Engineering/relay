package main

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// blackHoleConn is a net.Conn whose link can be made to die silently: once
// hole is set, writes are discarded as if the network dropped them, and reads
// block until Close, so the peer never sees a ping or an acknowledgement.
type blackHoleConn struct {
	net.Conn
	hole   *atomic.Bool
	closed chan struct{}
	once   sync.Once
}

func (c *blackHoleConn) Write(p []byte) (int, error) {
	if c.hole.Load() {
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *blackHoleConn) Read(p []byte) (int, error) {
	if c.hole.Load() {
		<-c.closed
		return 0, net.ErrClosed
	}
	return c.Conn.Read(p)
}

func (c *blackHoleConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

// Only keepalive can end this stream: the Tunnel's own heartbeat deadline is
// left at its three-minute default. grpc-go clamps a server keepalive Time
// below one second up to one second, so the shortest values this test can use
// are one second each, and a dead link is noticed within about two.
func TestKeepalive_RelayClosesADeadLinkAndMarksTheNodeOffline(t *testing.T) {
	const nodeID = "node-dead-link"
	reg := registry.NewInMemory()
	opts := []grpc.ServerOption{grpc.ChainStreamInterceptor(injectNodeIDInterceptor(nodeID))}
	opts = append(opts, transport.KeepaliveServerOptions(transport.KeepaliveParams{
		Time:          time.Second,
		Timeout:       time.Second,
		MinClientPing: transport.KeepaliveMinClientPingInterval,
	})...)
	srv := grpc.NewServer(opts...)
	relayv1.RegisterTunnelServer(srv, &tunnelServer{reg: reg})

	lis := bufconn.Listen(1 << 20)
	go srv.Serve(lis)
	t.Cleanup(srv.Stop)

	var hole atomic.Bool
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			c, err := lis.DialContext(ctx)
			if err != nil {
				return nil, err
			}
			return &blackHoleConn{Conn: c, hole: &hole, closed: make(chan struct{})}, nil
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	openNodeStream(ctx, t, conn, nodeID)
	if n, _ := reg.Get(nodeID); !n.Connected {
		t.Fatal("node not connected before the link died")
	}

	hole.Store(true)
	waitUntil(t, "the Relay to close the dead link and mark the node not connected", 10*time.Second, func() bool {
		n, _ := reg.Get(nodeID)
		return !n.Connected
	})
	if !nodeMarkedOffline(t, reg, nodeID) {
		t.Fatal("a node whose link died does not carry the offline marker")
	}
}
