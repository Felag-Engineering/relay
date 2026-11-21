package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// probeRecordingSink is a fakeCapabilityAuditSink that keeps the Node ID of
// every read record, so a test can prove which Node a refused read was
// recorded against.
type probeRecordingSink struct {
	fakeCapabilityAuditSink
	nodeIDs []string
}

func (s *probeRecordingSink) RecordRead(_ context.Context, _ capability.Principal, _, _, nodeID, _ string) error {
	s.nodeIDs = append(s.nodeIDs, nodeID)
	return nil
}

func seedNodeRegistry(t *testing.T, nodes map[string]string) *registry.InMemory {
	t.Helper()
	reg := registry.NewInMemory()
	for id, hostname := range nodes {
		if _, err := reg.Upsert(registry.Report{NodeID: id, Facts: registry.Facts{Hostname: hostname}}); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	return reg
}

// TestHandleGetNode_ADisconnectedNodeIsReadFromItsLastRecordAndConnectedIsNotLastSeen
// proves that the single-Node read returns exactly the Node asked for, that a
// Node seen just now but holding no live Tunnel reads connected=false (never
// inferred from last_seen), and that a Node whose Tunnel dropped stays
// readable from its last record.
//
// Proves QRY-4.
func TestHandleGetNode_ADisconnectedNodeIsReadFromItsLastRecordAndConnectedIsNotLastSeen(t *testing.T) {
	reg := seedNodeRegistry(t, map[string]string{"node-a": "web-1", "node-b": "db-1"})
	if err := reg.RecordHeartbeat("node-a", fixedNow(), registry.ClockSkewReading{}); err != nil {
		t.Fatalf("RecordHeartbeat: %v", err)
	}
	h := newTestHandler(Deps{NodeReader: newNodeReaderLane(t, reg, &fakeCapabilityAuditSink{}, fixedNow, 0)})

	read := func(t *testing.T) nodeResponse {
		t.Helper()
		rec := do(t, h, http.MethodGet, "/api/v1/nodes/node-a", nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET node-a = %d (%s), want 200", rec.Code, rec.Body.String())
		}
		var out nodeResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if out.NodeID != "node-a" || out.Facts.Hostname != "web-1" {
			t.Fatalf("read %q / %q, want exactly node-a / web-1 (not node-b)", out.NodeID, out.Facts.Hostname)
		}
		return out
	}

	out := read(t)
	if out.LastSeen == "" {
		t.Error("last_seen is empty, want the heartbeat's time")
	}
	if out.Connected {
		t.Error("connected = true for a Node seen just now that never held a Tunnel, want false: connected is never inferred from last_seen")
	}

	reg.SetConnected("node-a", true)
	if out := read(t); !out.Connected {
		t.Error("connected = false for a Node holding a live Tunnel, want true")
	}

	reg.SetConnected("node-a", false)
	if out := read(t); out.Connected {
		t.Error("connected = true after the Tunnel dropped, want false; the record is still read")
	}
}

// TestHandleGetNode_AnUnknownNodeIsNoSuchNodeAndTheProbeIsRecorded proves that
// a well-formed but unknown Node ID is refused as no such Node and that the
// refused read is recorded with the probed ID.
//
// Proves QRY-21.
func TestHandleGetNode_AnUnknownNodeIsNoSuchNodeAndTheProbeIsRecorded(t *testing.T) {
	sink := &probeRecordingSink{}
	reg := seedNodeRegistry(t, map[string]string{"node-a": "web-1"})
	h := newTestHandler(Deps{NodeReader: newNodeReaderLane(t, reg, sink, fixedNow, 0)})

	rec := do(t, h, http.MethodGet, "/api/v1/nodes/node-guessed", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET node-guessed = %d (%s), want 404", rec.Code, rec.Body.String())
	}
	var p problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if p.Title != "no such node" {
		t.Errorf("problem title = %q, want %q", p.Title, "no such node")
	}
	if len(sink.nodeIDs) != 1 || sink.nodeIDs[0] != "node-guessed" {
		t.Errorf("recorded reads = %q, want exactly the probed id [node-guessed]", sink.nodeIDs)
	}
}

// TestHandleGetNode_AnUnauthenticatedCallerReceivesNoNode proves that the
// single-Node read is behind the Authenticator: a request with no credential
// is refused and never reaches the read lane.
//
// Proves QRY-19.
func TestHandleGetNode_AnUnauthenticatedCallerReceivesNoNode(t *testing.T) {
	sink := &fakeCapabilityAuditSink{}
	reg := seedNodeRegistry(t, map[string]string{"node-a": "web-1"})
	h := newTestHandler(Deps{NodeReader: newNodeReaderLane(t, reg, sink, fixedNow, 0)})

	// Armed: the same route answers 200 with the Node when authenticated.
	rec := do(t, h, http.MethodGet, "/api/v1/nodes/node-a", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "web-1") {
		t.Fatalf("authenticated GET = %d (%s), want 200 carrying the Node", rec.Code, rec.Body.String())
	}
	if sink.readCalls == 0 {
		t.Fatal("the authenticated read never reached the read lane, so the 0 check below would be vacuous")
	}
	sink.readCalls = 0

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/nodes/node-a", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated GET = %d, want 401", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, "web-1") || strings.Contains(body, "node_id") {
		t.Errorf("unauthenticated body = %s, want no Node data", body)
	}
	if sink.readCalls != 0 {
		t.Errorf("read lane reached %d time(s) without a credential, want 0", sink.readCalls)
	}
}
