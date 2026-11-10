package main

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"google.golang.org/grpc"
)

// capturedChange is one change the tunnel handed to a connectionObserver.
type capturedChange struct{ nodeID, before, after string }

// captureChanges is a connectionObserver that keeps what it was told.
type captureChanges struct {
	mu       sync.Mutex
	versions []capturedChange
	certs    []capturedChange
}

func (c *captureChanges) DaemonVersionChanged(nodeID, before, after string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.versions = append(c.versions, capturedChange{nodeID, before, after})
}

func (c *captureChanges) CertChanged(nodeID, before, after string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certs = append(c.certs, capturedChange{nodeID, before, after})
}

func (c *captureChanges) versionChanges() []capturedChange {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.versions)
}

func (c *captureChanges) certChanges() []capturedChange {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.certs)
}

// openAudited is one connect against reg with rec as the change observer. It
// returns after the Ping, so rec is complete without a wait.
func openAudited(t *testing.T, reg registry.Repository, rec connectionObserver, nodeID string, hello *relayv1.Hello) {
	t.Helper()
	openWithHelloServer(t, &tunnelServer{reg: reg, changes: rec}, nodeID, hello)
}

func wantVersionChanges(t *testing.T, rec *captureChanges, want ...capturedChange) {
	t.Helper()
	if got := rec.versionChanges(); !slices.Equal(got, want) {
		t.Fatalf("version changes = %+v, want %+v", got, want)
	}
}

// Proves NC-34.
func TestTunnelOpen_ChangedDaemonVersionWritesOneRecord(t *testing.T) {
	const nodeID = "cert-node-ver"
	reg, rec := registry.NewInMemory(), &captureChanges{}
	openAudited(t, reg, rec, nodeID, &relayv1.Hello{DaemonVersion: "0.1.0"})
	openAudited(t, reg, rec, nodeID, &relayv1.Hello{DaemonVersion: "0.2.0"})
	wantVersionChanges(t, rec, capturedChange{nodeID, "0.1.0", "0.2.0"})
	if got := rec.certChanges(); len(got) != 0 {
		t.Errorf("cert changes = %+v, want none", got)
	}

	openAudited(t, reg, rec, nodeID, &relayv1.Hello{DaemonVersion: "0.2.0"})
	wantVersionChanges(t, rec, capturedChange{nodeID, "0.1.0", "0.2.0"})
}

// Proves NC-34.
func TestTunnelOpen_LowerDaemonVersionIsPassedAsADowngrade(t *testing.T) {
	const nodeID = "cert-node-down"
	reg, rec := registry.NewInMemory(), &captureChanges{}
	openAudited(t, reg, rec, nodeID, &relayv1.Hello{DaemonVersion: "0.2.0"})
	openAudited(t, reg, rec, nodeID, &relayv1.Hello{DaemonVersion: "0.1.9"})
	wantVersionChanges(t, rec, capturedChange{nodeID, "0.2.0", "0.1.9"})
	c := rec.versionChanges()[0]
	if lower, comparable := registry.Downgrade(c.before, c.after); !lower || !comparable {
		t.Errorf("Downgrade(%q, %q) = %v, %v, want true, true", c.before, c.after, lower, comparable)
	}
}

// Proves NC-34.
func TestTunnelOpen_UnreportedDaemonVersionIsRecordedAsUnknownSide(t *testing.T) {
	const nodeID = "cert-node-unk"
	reg, rec := registry.NewInMemory(), &captureChanges{}
	openAudited(t, reg, rec, nodeID, &relayv1.Hello{DaemonVersion: "0.2.0"})
	// Refused by HelloReportFromProto, so recorded as not reported.
	openAudited(t, reg, rec, nodeID, &relayv1.Hello{DaemonVersion: "0.2.0 changes=9"})
	wantVersionChanges(t, rec, capturedChange{nodeID, "0.2.0", ""})
}

// Proves NC-34.
func TestTunnelOpen_FirstConnectWritesNoVersionRecord(t *testing.T) {
	t.Run("empty registry", func(t *testing.T) {
		const nodeID = "cert-node-first"
		reg, rec := registry.NewInMemory(), &captureChanges{}
		openAudited(t, reg, rec, nodeID, &relayv1.Hello{DaemonVersion: "0.2.0"})
		wantVersionChanges(t, rec)
		if n, _ := reg.Get(nodeID); n.FirstConnectedAt.IsZero() {
			t.Error("FirstConnectedAt is unset after the first connect")
		}
	})
	t.Run("enrolled but never connected", func(t *testing.T) {
		const nodeID = "cert-node-first-enrolled"
		reg, rec := registry.NewInMemory(), &captureChanges{}
		if _, err := reg.Upsert(registry.Report{NodeID: nodeID, CertFingerprint: strings.Repeat("a", 64)}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		openAudited(t, reg, rec, nodeID, &relayv1.Hello{DaemonVersion: "0.2.0"})
		wantVersionChanges(t, rec)
		if n, _ := reg.Get(nodeID); n.FirstConnectedAt.IsZero() {
			t.Error("FirstConnectedAt is unset after the first connect")
		}
	})
}

// Proves NC-34.
func TestTunnelOpen_FirstConnectReportingNothingCannotHideTheNextReport(t *testing.T) {
	const nodeID = "cert-node-evade"
	reg, rec := registry.NewInMemory(), &captureChanges{}
	openAudited(t, reg, rec, nodeID, &relayv1.Hello{})
	wantVersionChanges(t, rec)
	openAudited(t, reg, rec, nodeID, &relayv1.Hello{DaemonVersion: "0.2.0"})
	wantVersionChanges(t, rec, capturedChange{nodeID, "", "0.2.0"})
}

// The tunnel half of "a version below the minimum still connects": it
// consults no minimum, so the Ping arrives and the change is recorded.
//
// Proves NC-34.
func TestTunnelOpen_DaemonVersionBelowTheMinimumStillConnects(t *testing.T) {
	const nodeID = "cert-node-below"
	reg, rec := registry.NewInMemory(), &captureChanges{}
	openAudited(t, reg, rec, nodeID, &relayv1.Hello{DaemonVersion: "0.2.0"})
	openAudited(t, reg, rec, nodeID, &relayv1.Hello{DaemonVersion: "0.0.1"})
	wantVersionChanges(t, rec, capturedChange{nodeID, "0.2.0", "0.0.1"})
}

// failAppend is an audit repository whose every Append fails; the recorder
// reaches the repository through nothing else.
type failAppend struct{ audit.Repository }

func (failAppend) Append(context.Context, audit.Record) error {
	return errors.New("audit store down")
}

// A write that FAILS returns at once; this covers a fast failure, not a store
// that hangs (the recorder's own budget bounds that).
func TestTunnelOpen_FailedChangeRecordNeitherRefusesNorDelaysThePing(t *testing.T) {
	const nodeID = "cert-node-failrec"
	reg := registry.NewInMemory()
	rec := auditsink.NewConnectionRecorder(auditsink.New(failAppend{}), nil)
	openAudited(t, reg, rec, nodeID, &relayv1.Hello{DaemonVersion: "0.1.0"})

	// Dials by hand rather than through openWithHelloServer: the test needs the
	// stream to send the Heartbeat.
	srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(nodeID)))
	relayv1.RegisterTunnelServer(srv, &tunnelServer{reg: reg, changes: rec})
	conn := newBufconnConn(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	start := time.Now()
	if err := stream.Send(&relayv1.DaemonMessage{Body: &relayv1.DaemonMessage_Hello{
		Hello: &relayv1.Hello{DaemonVersion: "0.2.0"},
	}}); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv ping (connection refused?): %v", err)
	}
	if msg.GetPing() == nil {
		t.Fatalf("expected Ping, got %T", msg.Body)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("Ping took %v after a failed change record, want under 2s", d)
	}

	// The stream is still open: a Heartbeat is accepted.
	before, _ := reg.Get(nodeID)
	if err := stream.Send(&relayv1.DaemonMessage{Body: &relayv1.DaemonMessage_Heartbeat{
		Heartbeat: &relayv1.Heartbeat{UnixMillis: time.Now().UnixMilli()},
	}}); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}
	waitUntil(t, "LastSeen to advance", 5*time.Second, func() bool {
		n, _ := reg.Get(nodeID)
		return n.LastSeen.After(before.LastSeen)
	})
}

// failingUpsertRegistry is a registry whose Upsert fails.
type failingUpsertRegistry struct{ *registry.InMemory }

func (failingUpsertRegistry) Upsert(registry.Report) (registry.Node, error) {
	return registry.Node{}, errors.New("registry down")
}

func TestTunnelOpen_FailedUpsertWritesNoChangeRecord(t *testing.T) {
	const nodeID = "cert-node-failup"
	inner, rec := registry.NewInMemory(), &captureChanges{}
	seedMarkedNode(t, inner, nodeID, "0.1.0")
	openAudited(t, failingUpsertRegistry{inner}, rec, nodeID, &relayv1.Hello{DaemonVersion: "0.2.0"})
	wantVersionChanges(t, rec)
}

// failingMarkRegistry is a registry whose MarkConnected fails.
type failingMarkRegistry struct{ *registry.InMemory }

func (failingMarkRegistry) MarkConnected(string, time.Time) error {
	return errors.New("registry down")
}

func TestTunnelOpen_FailedFirstConnectMarkerStillConnectsAndRecords(t *testing.T) {
	const nodeID = "cert-node-failmark"
	inner, rec := registry.NewInMemory(), &captureChanges{}
	seedMarkedNode(t, inner, nodeID, "0.1.0")
	openAudited(t, failingMarkRegistry{inner}, rec, nodeID, &relayv1.Hello{DaemonVersion: "0.2.0"})
	wantVersionChanges(t, rec, capturedChange{nodeID, "0.1.0", "0.2.0"})
}

// seedMarkedNode stores a Node that has connected before, reporting version.
func seedMarkedNode(t *testing.T, reg *registry.InMemory, nodeID, version string) {
	t.Helper()
	if _, err := reg.Upsert(registry.Report{NodeID: nodeID, DaemonVersion: version}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := reg.MarkConnected(nodeID, time.Now()); err != nil {
		t.Fatalf("seed marker: %v", err)
	}
}

func TestChangesSinceLastConnect(t *testing.T) {
	marked := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fpA, fpB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	tests := []struct {
		name        string
		baseline    registry.Node
		version, fp string
		wantVersion *valueChange
		wantCert    *valueChange
	}{
		{"marker unset, version differs", registry.Node{DaemonVersion: "0.1.0"}, "0.2.0", "", nil, nil},
		{"marker unset, stored empty", registry.Node{}, "0.2.0", "", nil, nil},
		{"marker set, same version", registry.Node{FirstConnectedAt: marked, DaemonVersion: "0.1.0"}, "0.1.0", "", nil, nil},
		{"marker set, version differs", registry.Node{FirstConnectedAt: marked, DaemonVersion: "0.1.0"}, "0.2.0", "", &valueChange{"0.1.0", "0.2.0"}, nil},
		{"marker set, stored empty", registry.Node{FirstConnectedAt: marked}, "0.2.0", "", &valueChange{"", "0.2.0"}, nil},
		{"marker set, now empty", registry.Node{FirstConnectedAt: marked, DaemonVersion: "0.2.0"}, "", "", &valueChange{"0.2.0", ""}, nil},
		{"marker set, both empty", registry.Node{FirstConnectedAt: marked}, "", "", nil, nil},
		{"cert, baseline empty", registry.Node{}, "", fpA, nil, nil},
		{"cert, current empty", registry.Node{CertFingerprint: fpA}, "", "", nil, nil},
		{"cert, same", registry.Node{CertFingerprint: fpA}, "", fpA, nil, nil},
		{"cert, differs, marker unset", registry.Node{CertFingerprint: fpA}, "", fpB, nil, &valueChange{fpA, fpB}},
		{"cert, differs, marker set", registry.Node{FirstConnectedAt: marked, CertFingerprint: fpA}, "", fpB, nil, &valueChange{fpA, fpB}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := changesSinceLastConnect(tt.baseline, tt.version, tt.fp)
			if !reflect.DeepEqual(got.daemonVersion, tt.wantVersion) {
				t.Errorf("daemonVersion = %+v, want %+v", got.daemonVersion, tt.wantVersion)
			}
			if !reflect.DeepEqual(got.cert, tt.wantCert) {
				t.Errorf("cert = %+v, want %+v", got.cert, tt.wantCert)
			}
		})
	}
}

// firstUpsertGated blocks its first Upsert until released, after announcing
// that it was reached.
type firstUpsertGated struct {
	*registry.InMemory
	once    sync.Once
	reached chan struct{}
	release chan struct{}
}

func (g *firstUpsertGated) Upsert(r registry.Report) (registry.Node, error) {
	g.once.Do(func() {
		close(g.reached)
		<-g.release
	})
	return g.InMemory.Upsert(r)
}

// Proves NC-34.
func TestTunnelOpen_OverlappingConnectsOfOneNodeRecordThePersistedOrder(t *testing.T) {
	const nodeID = "cert-node-overlap"
	inner, rec := registry.NewInMemory(), &captureChanges{}
	seedMarkedNode(t, inner, nodeID, "0.1.0")
	reg := &firstUpsertGated{InMemory: inner, reached: make(chan struct{}), release: make(chan struct{})}
	ts := &tunnelServer{reg: reg, changes: rec}

	first, second := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(first)
		openWithHelloServer(t, ts, nodeID, &relayv1.Hello{DaemonVersion: "0.2.0"})
	}()
	<-reg.reached
	go func() {
		defer close(second)
		openWithHelloServer(t, ts, nodeID, &relayv1.Hello{DaemonVersion: "0.3.0"})
	}()
	// Without the per-Node lock the second connect finishes here against the
	// stale baseline; with it, it waits for the first.
	select {
	case <-second:
	case <-time.After(200 * time.Millisecond):
	}
	close(reg.release)
	<-first
	<-second

	wantVersionChanges(t, rec, capturedChange{nodeID, "0.1.0", "0.2.0"}, capturedChange{nodeID, "0.2.0", "0.3.0"})
}

func TestKeyedMutexSerializesOneKeyAndDropsIdleEntries(t *testing.T) {
	var k keyedMutex
	unlockA := k.lock("a")
	unlockB := k.lock("b") // a different key never waits on "a"

	acquired := make(chan func())
	go func() { acquired <- k.lock("a") }()
	select {
	case <-acquired:
		t.Fatal("second holder of the same key got in while it was held")
	case <-time.After(50 * time.Millisecond):
	}
	unlockA()
	unlockA2 := <-acquired
	unlockA2()
	unlockB()

	k.mu.Lock()
	defer k.mu.Unlock()
	if len(k.entries) != 0 {
		t.Fatalf("entries left after every holder released: %d", len(k.entries))
	}
}
