package main

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
)

// ---------------------------------------------------------------------------
// dispatcher — test-only taskSink implementation
//
// dispatcher implements the taskSink interface. It records the outbound send
// function for each connected node (so tests can push Tasks), and collects
// inbound TaskResults (so tests can assert on outcomes).
//
// This is the ONLY concrete taskSink. Production code never sets tunnel.sink,
// so the interface and dispatcher are unreachable in the production binary.
// ---------------------------------------------------------------------------

type dispatcher struct {
	mu      sync.Mutex
	senders map[string]func(*gleipnirv1.RelayMessage) error
	results map[string]chan *gleipnirv1.TaskResult
}

func newDispatcher() *dispatcher {
	return &dispatcher{
		senders: make(map[string]func(*gleipnirv1.RelayMessage) error),
		results: make(map[string]chan *gleipnirv1.TaskResult),
	}
}

// register implements taskSink. Called by tunnelServer.Open after Ping is sent.
// Returns an unregister cleanup func (called on stream teardown).
func (d *dispatcher) register(nodeID string, send func(*gleipnirv1.RelayMessage) error) func() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.senders[nodeID] = send
	if _, ok := d.results[nodeID]; !ok {
		d.results[nodeID] = make(chan *gleipnirv1.TaskResult, 32)
	}
	return func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		delete(d.senders, nodeID)
	}
}

// deliver implements taskSink. Called by tunnelServer.Open when a TaskResult
// arrives on the inbound stream. Buffered channel (32) avoids blocking the
// stream goroutine while the test goroutine reads.
func (d *dispatcher) deliver(nodeID string, result *gleipnirv1.TaskResult) {
	d.mu.Lock()
	ch := d.results[nodeID]
	d.mu.Unlock()
	if ch != nil {
		ch <- result
	}
}

// waitForNode polls until the node registers a sender or the deadline expires.
// Used as the startup sync point: ensures the daemon's Hello→Ping handshake is
// complete before the test dispatches Tasks.
func (d *dispatcher) waitForNode(nodeID string, deadline time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("waitForNode(%q): timeout after %v", nodeID, deadline)
		case <-time.After(5 * time.Millisecond):
			d.mu.Lock()
			_, ok := d.senders[nodeID]
			d.mu.Unlock()
			if ok {
				return nil
			}
		}
	}
}

// Dispatch sends a RelayMessage to the node identified by nodeID. Returns an
// error if the node is not (yet) registered or if stream.Send fails.
func (d *dispatcher) Dispatch(nodeID string, msg *gleipnirv1.RelayMessage) error {
	d.mu.Lock()
	send, ok := d.senders[nodeID]
	d.mu.Unlock()
	if !ok {
		return fmt.Errorf("dispatch: node %q not registered", nodeID)
	}
	return send(msg)
}

// ---------------------------------------------------------------------------
// Unit tests: dispatcher struct behaviour (hermetic, no gRPC)
// ---------------------------------------------------------------------------

func TestDispatcher_RegisterDeliverUnregister(t *testing.T) {
	d := newDispatcher()

	sent := make([]*gleipnirv1.RelayMessage, 0)
	mu := sync.Mutex{}
	fakeSend := func(msg *gleipnirv1.RelayMessage) error {
		mu.Lock()
		sent = append(sent, msg)
		mu.Unlock()
		return nil
	}

	// register delivers an unregister func; the node should be present.
	unregister := d.register("node-1", fakeSend)

	if err := d.Dispatch("node-1", &gleipnirv1.RelayMessage{
		Body: &gleipnirv1.RelayMessage_Ping{Ping: &gleipnirv1.Ping{}},
	}); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	mu.Lock()
	if len(sent) != 1 {
		t.Fatalf("want 1 sent message, got %d", len(sent))
	}
	mu.Unlock()

	// unregister removes the node from senders.
	unregister()
	if err := d.Dispatch("node-1", &gleipnirv1.RelayMessage{}); err == nil {
		t.Fatal("expected error after unregister, got nil")
	}
}

func TestDispatcher_Deliver(t *testing.T) {
	d := newDispatcher()
	unregister := d.register("node-2", func(*gleipnirv1.RelayMessage) error { return nil })
	defer unregister()

	want := &gleipnirv1.TaskResult{
		TaskId:  "task-xyz",
		Outcome: gleipnirv1.Outcome_OUTCOME_SUCCESS,
	}
	d.deliver("node-2", want)

	d.mu.Lock()
	ch := d.results["node-2"]
	d.mu.Unlock()

	select {
	case got := <-ch:
		if got.TaskId != want.TaskId {
			t.Errorf("TaskId: got %q, want %q", got.TaskId, want.TaskId)
		}
		if got.Outcome != want.Outcome {
			t.Errorf("Outcome: got %v, want %v", got.Outcome, want.Outcome)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout: no result delivered")
	}
}

func TestDispatcher_WaitForNodeTimeout(t *testing.T) {
	d := newDispatcher()
	// No node registered → must time out.
	err := d.waitForNode("node-absent", 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestDispatcher_DispatchUnknownNode(t *testing.T) {
	d := newDispatcher()
	err := d.Dispatch("unknown-node", &gleipnirv1.RelayMessage{})
	if err == nil {
		t.Fatal("expected error for unknown node, got nil")
	}
}

// TestTunnelSink_NilInProduction asserts that newServer does not set a taskSink
// on the tunnelServer — the production server must not wire a dispatcher.
// This protects ADR-0002: the dispatch seam is test-only.
func TestTunnelSink_NilInProduction(t *testing.T) {
	cfg := Config{
		Addr:                ":0",
		CADir:               t.TempDir(),
		Hostname:            "localhost",
		EnrollIPRate:        5,
		EnrollIPBurst:       3,
		EnrollGlobalRate:    50,
		EnrollGlobalBurst:   10,
		EnrollMaxTrackedIPs: 100000,
		MaxNodes:            110000,
	}
	_, deps, err := newServer(cfg)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	if deps.tunnel.sink != nil {
		t.Error("newServer must leave tunnel.sink nil in production")
	}
}
