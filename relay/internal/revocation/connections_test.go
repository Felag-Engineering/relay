package revocation_test

import (
	"context"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/revocation"
)

func TestConnections_TrackReturnsLiveContext(t *testing.T) {
	c := revocation.NewConnections()
	ctx, release := c.Track(context.Background(), "node-1")
	defer release()

	select {
	case <-ctx.Done():
		t.Error("context should not be canceled immediately after Track")
	default:
	}
}

func TestConnections_DisconnectCancelsContext(t *testing.T) {
	c := revocation.NewConnections()
	ctx, release := c.Track(context.Background(), "node-1")
	defer release()

	c.Disconnect("node-1")

	select {
	case <-ctx.Done():
		// expected
	case <-time.After(time.Second):
		t.Error("context should have been canceled by Disconnect")
	}
}

func TestConnections_ReleaseIsIdempotent(t *testing.T) {
	c := revocation.NewConnections()
	ctx, release := c.Track(context.Background(), "node-1")

	// release must be safe to call multiple times.
	release()
	release()
	release()

	select {
	case <-ctx.Done():
		// expected
	case <-time.After(time.Second):
		t.Error("context should have been canceled by release")
	}
}

func TestConnections_ReleaseSafeAfterDisconnect(t *testing.T) {
	c := revocation.NewConnections()
	ctx, release := c.Track(context.Background(), "node-1")

	c.Disconnect("node-1")
	// release after Disconnect must not panic and must be idempotent.
	release()
	release()

	select {
	case <-ctx.Done():
		// expected
	case <-time.After(time.Second):
		t.Error("context should have been canceled")
	}
}

func TestConnections_MultipleTracksForSameNode(t *testing.T) {
	c := revocation.NewConnections()
	ctx1, release1 := c.Track(context.Background(), "node-1")
	ctx2, release2 := c.Track(context.Background(), "node-1")
	defer release1()
	defer release2()

	c.Disconnect("node-1")

	select {
	case <-ctx1.Done():
		// expected
	case <-time.After(time.Second):
		t.Error("ctx1 should have been canceled by Disconnect")
	}
	select {
	case <-ctx2.Done():
		// expected
	case <-time.After(time.Second):
		t.Error("ctx2 should have been canceled by Disconnect")
	}
}

func TestConnections_DisconnectUnknownNodeIsNoOp(t *testing.T) {
	c := revocation.NewConnections()
	// Should not panic.
	c.Disconnect("unknown-node")
}

// TestConnections_Count is the "connected Nodes" gauge source: it counts
// distinct node_ids with at least one live Tunnel stream, not the number of
// tracked streams (a Node with two concurrent streams still counts once).
func TestConnections_Count(t *testing.T) {
	c := revocation.NewConnections()
	if got := c.Count(); got != 0 {
		t.Fatalf("Count on empty tracker = %d, want 0", got)
	}

	_, release1 := c.Track(context.Background(), "node-1")
	defer release1()
	if got := c.Count(); got != 1 {
		t.Errorf("Count after tracking node-1 = %d, want 1", got)
	}

	// A second concurrent stream for the SAME node must not double-count.
	_, release1b := c.Track(context.Background(), "node-1")
	defer release1b()
	if got := c.Count(); got != 1 {
		t.Errorf("Count after a second stream for node-1 = %d, want 1 (distinct node_ids only)", got)
	}

	_, release2 := c.Track(context.Background(), "node-2")
	defer release2()
	if got := c.Count(); got != 2 {
		t.Errorf("Count after tracking node-2 = %d, want 2", got)
	}

	c.Disconnect("node-1")
	if got := c.Count(); got != 1 {
		t.Errorf("Count after disconnecting node-1 = %d, want 1", got)
	}
}
