package transport_test

import (
	"strings"
	"testing"

	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
)

// The Node plane's Tunnel is one RPC, Open, a bidirectional stream: the daemon
// dials it, so the Relay has no RPC it could call to reach a Node that has not
// connected.
// Proves NC-1.
func TestTunnel_OpenIsTheOneBidirectionalStream(t *testing.T) {
	tunnel := relayv1.File_relay_v1_relay_proto.Services().ByName("Tunnel")
	if tunnel == nil {
		t.Fatal("the contract has no Tunnel service")
	}
	methods := tunnel.Methods()
	if methods.Len() != 1 {
		t.Fatalf("Tunnel has %d methods, want exactly Open", methods.Len())
	}
	open := methods.Get(0)
	if open.Name() != "Open" {
		t.Errorf("Tunnel's method is %q, want Open", open.Name())
	}
	if !open.IsStreamingClient() || !open.IsStreamingServer() {
		t.Errorf("Tunnel.Open streaming client=%v server=%v, want a bidirectional stream", open.IsStreamingClient(), open.IsStreamingServer())
	}
}

// No message a daemon can send acknowledges a Task, and no Outcome is an
// acknowledgement, so the Relay learns of a Task only from its result: a Task
// sent to a Node that has silently died waits out the heartbeat deadline.
// Proves NC-12.
func TestNodePlane_NoMessageAcknowledgesATask(t *testing.T) {
	msg := (&relayv1.DaemonMessage{}).ProtoReflect().Descriptor()
	oneof := msg.Oneofs().ByName("body")
	if oneof == nil {
		t.Fatalf("%s has no oneof \"body\"; the contract changed shape", msg.FullName())
	}
	got := map[string]bool{}
	for i := 0; i < oneof.Fields().Len(); i++ {
		got[string(oneof.Fields().Get(i).Name())] = true
	}
	want := map[string]bool{
		"hello":          true, // the first message of a connection
		"heartbeat":      true, // liveness
		"task_result":    true, // the one message that answers a Task
		"stream_chunk":   true, // output of a running Task, not an acknowledgement of it
		"policy":         true, // the Node's own Policy snapshot
		"policy_verdict": true, // the answer to a PolicyQuery
		"templates":      true, // the Node's own Template snapshot
	}
	if !sameSet(got, want) {
		t.Errorf("DaemonMessage.body = %v, want %v: a new message must be checked against NC-12 (no message acknowledges a Task) before it is added to this set", keys(got), keys(want))
	}

	outcomes := relayv1.File_relay_v1_relay_proto.Enums().ByName("Outcome")
	if outcomes == nil {
		t.Fatal("the contract has no Outcome enum")
	}
	values := outcomes.Values()
	for i := 0; i < values.Len(); i++ {
		if name := string(values.Get(i).Name()); strings.Contains(strings.ToUpper(name), "ACK") {
			t.Errorf("Outcome value %s reads as an acknowledgement; a Task is acknowledged by no message", name)
		}
	}
}
