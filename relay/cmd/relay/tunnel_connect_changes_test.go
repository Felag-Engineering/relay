package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// capturedChange is one change the tunnel handed to a connectionObserver.
type capturedChange struct{ nodeID, before, after string }

// captureChanges is a connectionObserver that keeps what it was told.
type captureChanges struct {
	mu       sync.Mutex
	versions []capturedChange
	certs    []capturedChange
	policies []capturedPolicy
	replaced []string
}

// capturedPolicy is one Policy change the tunnel handed to a connectionObserver.
type capturedPolicy struct {
	nodeID string
	change auditsink.PolicyChange
}

func (c *captureChanges) PolicyChanged(nodeID string, change auditsink.PolicyChange) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.policies = append(c.policies, capturedPolicy{nodeID, change})
}

func (c *captureChanges) StreamReplaced(nodeID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.replaced = append(c.replaced, nodeID)
}

func (c *captureChanges) replacements() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.replaced)
}

func (c *captureChanges) policyChanges() []capturedPolicy {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.policies)
}

// wantPolicyChanges compares with DeepEqual because PolicyChange holds *bool.
func wantPolicyChanges(t *testing.T, rec *captureChanges, want ...capturedPolicy) {
	t.Helper()
	got := rec.policyChanges()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("policy changes = %+v, want %+v", got, want)
	}
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
// Proves NC-34, NC-26.
func TestTunnelOpen_DaemonVersionBelowTheMinimumStillConnects(t *testing.T) {
	const nodeID = "cert-node-below"
	reg, rec := registry.NewInMemory(), &captureChanges{}
	openAudited(t, reg, rec, nodeID, &relayv1.Hello{DaemonVersion: "0.2.0"})
	openAudited(t, reg, rec, nodeID, &relayv1.Hello{DaemonVersion: "0.0.1"})
	wantVersionChanges(t, rec, capturedChange{nodeID, "0.2.0", "0.0.1"})
}

// failAppendKinds is an audit repository whose every Append fails and which
// keeps the Kind of each record it refused, so a test can tell a write that was
// attempted and failed from one that was never attempted. The recorder reaches
// the repository through nothing else.
type failAppendKinds struct {
	audit.Repository
	mu    sync.Mutex
	kinds []string
}

func (f *failAppendKinds) Append(_ context.Context, r audit.Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kinds = append(f.kinds, r.Kind)
	return errors.New("audit store down")
}

func (f *failAppendKinds) refused() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.kinds)
}

// injectNodeAndCertInterceptor is injectNodeIDInterceptor plus a peer whose
// verified chain holds one certificate with the given raw bytes. It stands in
// for the verified leaf the mTLS listener supplies, so the tunnel derives a
// certificate fingerprint without real TLS.
func injectNodeAndCertInterceptor(nodeID string, leaf []byte) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx := transport.NewContextWithNodeID(ss.Context(), nodeID)
		p := &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			VerifiedChains: [][]*x509.Certificate{{{Raw: leaf}}},
		}}}
		if orig, ok := peer.FromContext(ctx); ok {
			p.Addr = orig.Addr
		}
		ctx = peer.NewContext(ctx, p)
		return handler(srv, testStreamWithContext{ServerStream: ss, ctx: ctx})
	}
}

// A change or replacement record whose write fails neither refuses nor delays
// the connection: the version, certificate and replacement records all fail
// here, and both streams get their Ping at once and keep accepting heartbeats.
// It covers a fast failure, not a store that hangs (the recorder's own budget
// bounds that). The Policy kind is
// TestTunnelOpen_FailedPolicyRecordKeepsTheStreamUp.
//
// Proves NC-39.
func TestTunnelOpen_FailedChangeRecordNeitherRefusesNorDelaysThePing(t *testing.T) {
	const nodeID = "cert-node-failrec"
	rawA, rawB := []byte("leaf-a"), []byte("leaf-b")
	sumA := sha256.Sum256(rawA)
	reg := registry.NewInMemory()
	// A certless connect stores an empty fingerprint, after which no
	// certificate change could follow, so the Node is seeded as one that has
	// connected before with a known leaf.
	if _, err := reg.Upsert(registry.Report{NodeID: nodeID, DaemonVersion: "0.1.0", CertFingerprint: hex.EncodeToString(sumA[:])}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := reg.MarkConnected(nodeID, time.Now()); err != nil {
		t.Fatalf("seed marker: %v", err)
	}
	kinds := &failAppendKinds{}
	rec := auditsink.NewConnectionRecorder(auditsink.New(kinds), nil)

	// Dials by hand rather than through openWithHelloServer: the test needs the
	// streams to send the Heartbeat. Both streams share one server, and so one
	// set of claims, or the second would not be a replacement.
	srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeAndCertInterceptor(nodeID, rawB)))
	relayv1.RegisterTunnelServer(srv, &tunnelServer{reg: reg, changes: rec})
	conn := newBufconnConn(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, name := range []string{"version and certificate change", "replacement"} {
		stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
		if err != nil {
			t.Fatalf("%s: open stream: %v", name, err)
		}
		start := time.Now()
		if err := stream.Send(&relayv1.DaemonMessage{Body: &relayv1.DaemonMessage_Hello{
			Hello: &relayv1.Hello{DaemonVersion: "0.2.0"},
		}}); err != nil {
			t.Fatalf("%s: send hello: %v", name, err)
		}
		msg, err := stream.Recv()
		if err != nil {
			t.Fatalf("%s: recv ping (connection refused?): %v", name, err)
		}
		if msg.GetPing() == nil {
			t.Fatalf("%s: expected Ping, got %T", name, msg.Body)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("%s: Ping took %v after a failed record, want under 2s", name, d)
		}

		// The stream is still open: a Heartbeat is accepted.
		before, _ := reg.Get(nodeID)
		if err := stream.Send(&relayv1.DaemonMessage{Body: &relayv1.DaemonMessage_Heartbeat{
			Heartbeat: &relayv1.Heartbeat{UnixMillis: time.Now().UnixMilli()},
		}}); err != nil {
			t.Fatalf("%s: send heartbeat: %v", name, err)
		}
		waitUntil(t, name+": LastSeen to advance", 5*time.Second, func() bool {
			n, _ := reg.Get(nodeID)
			return n.LastSeen.After(before.LastSeen)
		})
	}

	got := kinds.refused()
	for _, want := range []string{audit.KindNodeDaemonVersionChanged, audit.KindNodeCertChanged, audit.KindNodeStreamReplaced} {
		if !slices.Contains(got, want) {
			t.Errorf("no %s write was attempted; refused writes = %v", want, got)
		}
	}
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

func boolp(b bool) *bool { return &b }

func policyMsg(rawExec bool) *relayv1.DaemonMessage {
	return &relayv1.DaemonMessage{Body: &relayv1.DaemonMessage_Policy{
		Policy: &relayv1.PolicySnapshot{RawExecEnabled: rawExec},
	}}
}

func heartbeatMsg() *relayv1.DaemonMessage {
	return &relayv1.DaemonMessage{Body: &relayv1.DaemonMessage_Heartbeat{
		Heartbeat: &relayv1.Heartbeat{UnixMillis: time.Now().UnixMilli()},
	}}
}

func policyHello(fp string) *relayv1.Hello { return &relayv1.Hello{PolicyFingerprint: fp} }

// openThenEnd is one whole stream: Hello, the Ping, msgs, then a clean end.
// The client sees EOF only after the handler and every deferred step,
// including the end-of-stream Policy record, has run, so assertions after it
// need no polling.
func openThenEnd(t *testing.T, ts *tunnelServer, nodeID string, hello *relayv1.Hello, msgs ...*relayv1.DaemonMessage) {
	t.Helper()
	srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(nodeID)))
	relayv1.RegisterTunnelServer(srv, ts)
	conn := newBufconnConn(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if err := stream.Send(&relayv1.DaemonMessage{Body: &relayv1.DaemonMessage_Hello{Hello: hello}}); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv ping: %v", err)
	}
	if msg.GetPing() == nil {
		t.Fatalf("expected Ping, got %T", msg.Body)
	}
	for _, m := range msgs {
		if err := stream.Send(m); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("close send: %v", err)
	}
	for {
		if _, err := stream.Recv(); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("stream ended with %v, want a clean end", err)
			}
			return
		}
	}
}

func connectOnce(t *testing.T, reg registry.Repository, rec connectionObserver, nodeID string, hello *relayv1.Hello, msgs ...*relayv1.DaemonMessage) {
	t.Helper()
	openThenEnd(t, &tunnelServer{reg: reg, changes: rec}, nodeID, hello, msgs...)
}

func rawExecOf(reg registry.Repository, nodeID string) registry.RawExecReport {
	n, _ := reg.Get(nodeID)
	return n.ReportedRawExec
}

// Proves NC-33.
func TestTunnelOpen_ChangedPolicyFingerprintWritesOneRecord(t *testing.T) {
	const nodeID = "cert-node-pfp"
	fpA, fpB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	reg, rec := registry.NewInMemory(), &captureChanges{}
	connectOnce(t, reg, rec, nodeID, policyHello(fpA), policyMsg(false))
	connectOnce(t, reg, rec, nodeID, policyHello(fpB), policyMsg(false))
	want := capturedPolicy{nodeID, auditsink.PolicyChange{
		FingerprintBefore: fpA, FingerprintAfter: fpB, RawExecBefore: boolp(false), RawExecAfter: boolp(false),
	}}
	wantPolicyChanges(t, rec, want)

	connectOnce(t, reg, rec, nodeID, policyHello(fpB), policyMsg(false))
	wantPolicyChanges(t, rec, want)
	if got := rawExecOf(reg, nodeID); got != registry.RawExecReportedDisabled {
		t.Errorf("ReportedRawExec = %v, want disabled", got)
	}
}

// Proves NC-33.
func TestTunnelOpen_RawExecOnlyChangeWritesOneRecord(t *testing.T) {
	const nodeID = "cert-node-praw"
	fpA := strings.Repeat("a", 64)
	reg, rec := registry.NewInMemory(), &captureChanges{}
	connectOnce(t, reg, rec, nodeID, policyHello(fpA), policyMsg(false))
	connectOnce(t, reg, rec, nodeID, policyHello(fpA), policyMsg(true))
	wantPolicyChanges(t, rec, capturedPolicy{nodeID, auditsink.PolicyChange{
		FingerprintBefore: fpA, FingerprintAfter: fpA, RawExecBefore: boolp(false), RawExecAfter: boolp(true),
	}})
	if got := rawExecOf(reg, nodeID); got != registry.RawExecReportedEnabled {
		t.Errorf("ReportedRawExec = %v, want enabled", got)
	}
}

// Proves NC-33.
func TestTunnelOpen_PolicyFingerprintAndRawExecChangeWriteOneRecord(t *testing.T) {
	const nodeID = "cert-node-pboth"
	fpA, fpB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	reg, rec := registry.NewInMemory(), &captureChanges{}
	connectOnce(t, reg, rec, nodeID, policyHello(fpA), policyMsg(false))
	connectOnce(t, reg, rec, nodeID, policyHello(fpB), policyMsg(true))
	wantPolicyChanges(t, rec, capturedPolicy{nodeID, auditsink.PolicyChange{
		FingerprintBefore: fpA, FingerprintAfter: fpB, RawExecBefore: boolp(false), RawExecAfter: boolp(true),
	}})
}

// Proves NC-33.
func TestTunnelOpen_FirstConnectWritesNoPolicyRecord(t *testing.T) {
	fpA := strings.Repeat("a", 64)
	t.Run("empty registry", func(t *testing.T) {
		const nodeID = "cert-node-pfirst"
		reg, rec := registry.NewInMemory(), &captureChanges{}
		connectOnce(t, reg, rec, nodeID, policyHello(fpA), policyMsg(true))
		wantPolicyChanges(t, rec)
		if got := rawExecOf(reg, nodeID); got != registry.RawExecReportedEnabled {
			t.Errorf("ReportedRawExec = %v, want enabled", got)
		}
	})
	t.Run("enrolled but never connected", func(t *testing.T) {
		const nodeID = "cert-node-pfirst-enrolled"
		reg, rec := registry.NewInMemory(), &captureChanges{}
		if _, err := reg.Upsert(registry.Report{NodeID: nodeID, CertFingerprint: strings.Repeat("a", 64)}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		connectOnce(t, reg, rec, nodeID, policyHello(fpA), policyMsg(true))
		wantPolicyChanges(t, rec)
		if got := rawExecOf(reg, nodeID); got != registry.RawExecReportedEnabled {
			t.Errorf("ReportedRawExec = %v, want enabled", got)
		}
	})
}

// Proves NC-33.
func TestTunnelOpen_StreamEndingBeforeItsPolicySnapshotRecordsRawExecUnknown(t *testing.T) {
	const nodeID = "cert-node-pend"
	fpA, fpB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	reg, rec := registry.NewInMemory(), &captureChanges{}
	connectOnce(t, reg, rec, nodeID, policyHello(fpA), policyMsg(true))
	connectOnce(t, reg, rec, nodeID, policyHello(fpB))
	wantPolicyChanges(t, rec, capturedPolicy{nodeID, auditsink.PolicyChange{
		FingerprintBefore: fpA, FingerprintAfter: fpB, RawExecBefore: boolp(true),
	}})
	if got := rawExecOf(reg, nodeID); got != registry.RawExecNotReported {
		t.Errorf("ReportedRawExec = %v, want not reported", got)
	}
}

// Proves NC-33.
func TestTunnelOpen_OtherFirstMessageResolvesThePolicyRecordWithoutTheSnapshot(t *testing.T) {
	const nodeID = "cert-node-pother"
	fpA, fpB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	reg, rec := registry.NewInMemory(), &captureChanges{}
	connectOnce(t, reg, rec, nodeID, policyHello(fpA), policyMsg(false))
	connectOnce(t, reg, rec, nodeID, policyHello(fpB), heartbeatMsg(), policyMsg(true))
	want := capturedPolicy{nodeID, auditsink.PolicyChange{
		FingerprintBefore: fpA, FingerprintAfter: fpB, RawExecBefore: boolp(false),
	}}
	wantPolicyChanges(t, rec, want)
	if got := rawExecOf(reg, nodeID); got != registry.RawExecNotReported {
		t.Errorf("ReportedRawExec = %v, want not reported (the later snapshot is not stored)", got)
	}

	connectOnce(t, reg, rec, nodeID, policyHello(fpB), heartbeatMsg(), policyMsg(true))
	wantPolicyChanges(t, rec, want)
}

// A Policy record whose write fails leaves the stream up: the snapshot is
// stored and a later heartbeat is accepted.
//
// Proves NC-39.
func TestTunnelOpen_FailedPolicyRecordKeepsTheStreamUp(t *testing.T) {
	const nodeID = "cert-node-pfail"
	fpA, fpB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	reg := registry.NewInMemory()
	kinds := &failAppendKinds{}
	rec := auditsink.NewConnectionRecorder(auditsink.New(kinds), nil)
	connectOnce(t, reg, rec, nodeID, policyHello(fpA), policyMsg(false))

	srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(nodeID)))
	relayv1.RegisterTunnelServer(srv, &tunnelServer{reg: reg, changes: rec})
	conn := newBufconnConn(t, srv)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if err := stream.Send(&relayv1.DaemonMessage{Body: &relayv1.DaemonMessage_Hello{Hello: policyHello(fpB)}}); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	msg, err := stream.Recv()
	if err != nil || msg.GetPing() == nil {
		t.Fatalf("recv ping = %v, %v", msg, err)
	}
	// This snapshot's record write fails.
	if err := stream.Send(policyMsg(true)); err != nil {
		t.Fatalf("send policy: %v", err)
	}
	waitUntil(t, "the Raw Exec report to be stored", 5*time.Second, func() bool {
		return rawExecOf(reg, nodeID) == registry.RawExecReportedEnabled
	})
	waitUntil(t, "the Policy record write to be attempted", 5*time.Second, func() bool {
		return slices.Contains(kinds.refused(), audit.KindNodePolicyChanged)
	})
	before, _ := reg.Get(nodeID)
	if err := stream.Send(heartbeatMsg()); err != nil {
		t.Fatalf("send heartbeat: %v", err)
	}
	waitUntil(t, "LastSeen to advance", 5*time.Second, func() bool {
		n, _ := reg.Get(nodeID)
		return n.LastSeen.After(before.LastSeen)
	})
}

func TestTunnelOpen_FailedUpsertWritesNoPolicyRecord(t *testing.T) {
	const nodeID = "cert-node-pfailup"
	fpA, fpB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	inner, rec := registry.NewInMemory(), &captureChanges{}
	if _, err := inner.Upsert(registry.Report{NodeID: nodeID, PolicyFingerprint: fpA}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := inner.MarkConnected(nodeID, time.Now()); err != nil {
		t.Fatalf("seed marker: %v", err)
	}
	if err := inner.RecordPolicySnapshot(nodeID, false); err != nil {
		t.Fatalf("seed raw exec: %v", err)
	}
	connectOnce(t, failingUpsertRegistry{inner}, rec, nodeID, policyHello(fpB), policyMsg(true))
	wantPolicyChanges(t, rec)
	if got := rawExecOf(inner, nodeID); got != registry.RawExecReportedDisabled {
		t.Errorf("ReportedRawExec = %v, want disabled", got)
	}
}

// A Raw Exec-only change, which only a lying Node produces, is missed when the
// previous stream's snapshot was not stored: that stream ended before its
// PolicySnapshot, leaving the Raw Exec baseline unknown.
func TestTunnelOpen_RawExecOnlyChangeAfterAnUnreportedStreamIsMissed(t *testing.T) {
	const nodeID = "cert-node-pmiss"
	fpA := strings.Repeat("a", 64)
	reg, rec := registry.NewInMemory(), &captureChanges{}
	connectOnce(t, reg, rec, nodeID, policyHello(fpA), policyMsg(false))
	connectOnce(t, reg, rec, nodeID, policyHello(fpA))
	connectOnce(t, reg, rec, nodeID, policyHello(fpA), policyMsg(true))
	wantPolicyChanges(t, rec)
}

func TestPolicyChangeSinceLastConnect(t *testing.T) {
	marked := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	fpA, fpB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	snap := func(v bool) *relayv1.PolicySnapshot { return &relayv1.PolicySnapshot{RawExecEnabled: v} }
	node := func(fp string, raw registry.RawExecReport) registry.Node {
		return registry.Node{FirstConnectedAt: marked, PolicyFingerprint: fp, ReportedRawExec: raw}
	}
	tests := []struct {
		name     string
		baseline registry.Node
		fp       string
		snapshot *relayv1.PolicySnapshot
		want     *auditsink.PolicyChange
	}{
		{"marker unset", registry.Node{PolicyFingerprint: fpA}, fpB, snap(true), nil},
		{"same fingerprint, raw exec equal", node(fpA, registry.RawExecReportedDisabled), fpA, snap(false), nil},
		{"fingerprint differs, no snapshot", node(fpA, registry.RawExecReportedDisabled), fpB, nil,
			&auditsink.PolicyChange{FingerprintBefore: fpA, FingerprintAfter: fpB, RawExecBefore: boolp(false)}},
		{"same fingerprint, before unknown", node(fpA, registry.RawExecNotReported), fpA, snap(true), nil},
		{"same fingerprint, snapshot missing", node(fpA, registry.RawExecReportedEnabled), fpA, nil, nil},
		{"raw exec only", node(fpA, registry.RawExecReportedDisabled), fpA, snap(true),
			&auditsink.PolicyChange{FingerprintBefore: fpA, FingerprintAfter: fpA, RawExecBefore: boolp(false), RawExecAfter: boolp(true)}},
		{"both differ", node(fpA, registry.RawExecReportedEnabled), fpB, snap(false),
			&auditsink.PolicyChange{FingerprintBefore: fpA, FingerprintAfter: fpB, RawExecBefore: boolp(true), RawExecAfter: boolp(false)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := policyChangeSinceLastConnect(tt.baseline, tt.fp, tt.snapshot)
			if ok != (tt.want != nil) {
				t.Fatalf("changed = %v, want %v", ok, tt.want != nil)
			}
			if tt.want != nil && !reflect.DeepEqual(got, *tt.want) {
				t.Errorf("change = %+v, want %+v", got, *tt.want)
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

// A displaced stream's late PolicySnapshot writes neither the Raw Exec state
// nor a Policy record; the current stream's stand.
func TestTunnelOpen_DisplacedStreamsLateSnapshotWritesNothing(t *testing.T) {
	const nodeID = "cert-node-displaced"
	fpA, fpB, fpC := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	inner, rec := registry.NewInMemory(), &captureChanges{}
	connectOnce(t, inner, rec, nodeID, policyHello(fpA), policyMsg(false))
	ts := &tunnelServer{reg: inner, changes: rec}

	dial := func(hello *relayv1.Hello) (relayv1.Tunnel_OpenClient, func()) {
		srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(nodeID)))
		relayv1.RegisterTunnelServer(srv, ts)
		conn := newBufconnConn(t, srv)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if err := stream.Send(&relayv1.DaemonMessage{Body: &relayv1.DaemonMessage_Hello{Hello: hello}}); err != nil {
			t.Fatalf("hello: %v", err)
		}
		if _, err := stream.Recv(); err != nil {
			t.Fatalf("ping: %v", err)
		}
		return stream, cancel
	}
	drain := func(s relayv1.Tunnel_OpenClient) {
		if err := s.CloseSend(); err != nil {
			t.Fatalf("close send: %v", err)
		}
		for {
			if _, err := s.Recv(); err != nil {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("stream ended with %v, want a clean end", err)
				}
				return
			}
		}
	}

	a, cancelA := dial(policyHello(fpB))
	defer cancelA()
	b, cancelB := dial(policyHello(fpC))
	defer cancelB()
	if err := b.Send(policyMsg(true)); err != nil {
		t.Fatalf("send B snapshot: %v", err)
	}
	drain(b)
	if err := a.Send(policyMsg(false)); err != nil {
		t.Fatalf("send A snapshot: %v", err)
	}
	drain(a)

	if got := rawExecOf(inner, nodeID); got != registry.RawExecReportedEnabled {
		t.Errorf("ReportedRawExec = %v, want B's (enabled)", got)
	}
	wantPolicyChanges(t, rec, capturedPolicy{nodeID, auditsink.PolicyChange{
		// A's Hello cleared the stored Raw Exec state, so B's baseline is unknown.
		FingerprintBefore: fpB, FingerprintAfter: fpC, RawExecAfter: boolp(true),
	}})
}

// replacementProbe asks the claims for the Node's liveness from inside
// StreamReplaced, which cannot be answered while streamClaims.mu is held.
type replacementProbe struct {
	*captureChanges
	ts       *tunnelServer
	blocked  atomic.Bool
	liveSeen atomic.Bool
}

func (p *replacementProbe) StreamReplaced(nodeID string) {
	done := make(chan bool, 1)
	go func() { done <- p.ts.claims.anyLive(nodeID) }()
	select {
	case live := <-done:
		p.liveSeen.Store(live)
	case <-time.After(2 * time.Second):
		p.blocked.Store(true)
	}
	p.captureChanges.StreamReplaced(nodeID)
}

// The replacement is recorded after streamClaims.mu is released, so a
// recorder (or the registry behind it) may ask the claims about the Node.
func TestTunnelOpen_ReplacementIsReportedOutsideTheClaimsLock(t *testing.T) {
	const nodeID = "cert-node-outside-lock"
	probe := &replacementProbe{captureChanges: &captureChanges{}}
	ts := &tunnelServer{reg: registry.NewInMemory(), changes: probe}
	probe.ts = ts

	dial := func() {
		srv := grpc.NewServer(grpc.StreamInterceptor(injectNodeIDInterceptor(nodeID)))
		relayv1.RegisterTunnelServer(srv, ts)
		conn := newBufconnConn(t, srv)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		t.Cleanup(cancel)
		stream, err := relayv1.NewTunnelClient(conn).Open(ctx)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if err := stream.Send(&relayv1.DaemonMessage{Body: &relayv1.DaemonMessage_Hello{Hello: &relayv1.Hello{}}}); err != nil {
			t.Fatalf("hello: %v", err)
		}
		if _, err := stream.Recv(); err != nil {
			t.Fatalf("ping: %v", err)
		}
	}

	dial()
	if got := probe.replacements(); len(got) != 0 {
		t.Fatalf("replacements after the first stream = %v, want none", got)
	}
	dial()
	if probe.blocked.Load() {
		t.Error("StreamReplaced ran with streamClaims.mu held: anyLive did not return")
	}
	if !probe.liveSeen.Load() {
		t.Error("anyLive reported no live stream from inside StreamReplaced")
	}
	if got := probe.replacements(); !slices.Equal(got, []string{nodeID}) {
		t.Errorf("replacements = %v, want [%s]", got, nodeID)
	}
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

func TestStreamClaims_OpenReportsAnOverlap(t *testing.T) {
	var c streamClaims
	genA, overlapped := c.open(nil, "n")
	if overlapped {
		t.Error("first stream for a Node reported an overlap")
	}
	genB, overlapped := c.open(nil, "n")
	if !overlapped {
		t.Error("second live stream for a Node reported no overlap")
	}
	if _, overlapped := c.open(nil, "m"); overlapped {
		t.Error("a stream for another Node reported an overlap")
	}
	c.close(nil, "n", genA)
	c.close(nil, "n", genB)
	if _, overlapped := c.open(nil, "n"); overlapped {
		t.Error("a stream opened after every earlier one closed reported an overlap")
	}
}
