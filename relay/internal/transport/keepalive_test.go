package transport_test

import (
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/transport"
)

// The Relay pings a Node connection idle for 30 s and closes it after 20 s
// without an answer, and tolerates a daemon that pings every 30 s. That the
// Node-plane server is built from these values is read from its construction in
// the composition root, which no test can read back from a grpc.Server.
// Proves NC-10.
func TestKeepalive_ProductionValuesAreThirtyAndTwentySeconds(t *testing.T) {
	got := transport.ProductionKeepalive()
	want := transport.KeepaliveParams{Time: 30 * time.Second, Timeout: 20 * time.Second, MinClientPing: 30 * time.Second}
	if got != want {
		t.Errorf("ProductionKeepalive() = %+v, want %+v", got, want)
	}
	if transport.KeepaliveTime != want.Time || transport.KeepaliveTimeout != want.Timeout ||
		transport.KeepaliveMinClientPingInterval != want.MinClientPing {
		t.Errorf("exported constants = %v, %v, %v, want %v, %v, %v",
			transport.KeepaliveTime, transport.KeepaliveTimeout, transport.KeepaliveMinClientPingInterval,
			want.Time, want.Timeout, want.MinClientPing)
	}
}
