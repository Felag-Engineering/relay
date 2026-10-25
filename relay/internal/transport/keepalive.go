package transport

import (
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

// HTTP/2 keepalive for the Node-plane listener. The Relay pings a silent
// daemon and closes a transport that does not answer, so a dead link underneath
// a Tunnel ends the stream and marks the Node offline without waiting for TCP
// to give up. They are constants, not settings, so no configuration can loosen
// them.
const (
	// KeepaliveTime is how long a daemon connection may sit with no
	// activity before the Relay pings it.
	KeepaliveTime = 30 * time.Second

	// KeepaliveTimeout is how long the Relay waits for the ping's
	// acknowledgement before closing the transport.
	KeepaliveTimeout = 20 * time.Second

	// KeepaliveMinClientPingInterval is the shortest interval at which the
	// Relay tolerates a daemon's own pings. grpc-go's default is 5 minutes, so a
	// daemon pinging every 60 s would be sent GOAWAY too_many_pings. The daemon's
	// keepalive interval must stay at least twice this; a cross-tree test
	// pins the relation.
	KeepaliveMinClientPingInterval = 30 * time.Second
)

// KeepaliveParams are the Relay's server-side keepalive values. They are a
// parameter of KeepaliveServerOptions so a test can use short ones; the Relay's
// composition root only ever passes ProductionKeepalive.
type KeepaliveParams struct {
	Time          time.Duration
	Timeout       time.Duration
	MinClientPing time.Duration
}

// ProductionKeepalive returns the values the Relay's Node-plane server runs with.
func ProductionKeepalive() KeepaliveParams {
	return KeepaliveParams{
		Time:          KeepaliveTime,
		Timeout:       KeepaliveTimeout,
		MinClientPing: KeepaliveMinClientPingInterval,
	}
}

// KeepaliveServerOptions returns the grpc.ServerOptions that apply p. Pings are
// permitted with no stream open because the daemon's channel also carries the
// renewal RPC. Credentials and interceptors are separate options and are
// untouched (invariant 6).
func KeepaliveServerOptions(p KeepaliveParams) []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: p.Time, Timeout: p.Timeout}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             p.MinClientPing,
			PermitWithoutStream: true,
		}),
	}
}
