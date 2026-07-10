package main

import (
	"context"
	"io"
	"log/slog"
	"time"

	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/protoconv"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/registry"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/revocation"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// taskSink is a test/devharness-only seam for capturing Task dispatch and
// results in hermetic unit tests and the #112 cross-binary CI harness. It is
// nil in an untagged (production) build — newServer never sets it; only
// tests and installDevHarness (devharness-tagged build only) do.
//
// register is called after the Ping handshake completes; it records the
// outbound send function for the node and returns a cleanup func. deliver is
// called when a TaskResult arrives on the inbound stream. deliverVerdict is
// called when a PolicyVerdict arrives on the inbound stream (the daemon's
// answer to a PolicyQuery; ADR-0011 — the Relay only reads it, never evaluates
// Policy itself).
type taskSink interface {
	register(nodeID string, send func(*gleipnirv1.RelayMessage) error) (unregister func())
	deliver(nodeID string, result *gleipnirv1.TaskResult)
	deliverVerdict(nodeID string, verdict *gleipnirv1.PolicyVerdict)
}

type tunnelServer struct {
	gleipnirv1.UnimplementedTunnelServer
	conns *revocation.Connections
	reg   registry.Repository
	// policy is the display-only effective-Policy cache (#117, invariant 12 /
	// ADR-0002): the Relay records what a daemon reports in
	// DaemonMessage.policy and never evaluates or sets Policy itself. Nil-guarded
	// like reg/conns so existing tests that construct &tunnelServer{} directly
	// keep compiling; nil in any test that doesn't need the capture.
	policy *policyview.Cache
	// sink is nil in an untagged (production) build; only set in tests, or by
	// installDevHarness in a devharness-tagged build, to inject Tasks and
	// capture results. Never set by newServer.
	sink taskSink
}

func (s *tunnelServer) Open(stream grpc.BidiStreamingServer[gleipnirv1.DaemonMessage, gleipnirv1.RelayMessage]) error {
	first, err := stream.Recv()
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}

	hello := first.GetHello()
	if hello == nil {
		return status.Errorf(codes.InvalidArgument, "expected Hello as first message")
	}

	// node_id is authoritative only from the verified client certificate CN
	// (ADR-0006). The interceptor always injects it before the handler runs.
	// Fail closed: if it is absent the handler must not proceed.
	nodeID, ok := transport.NodeIDFromContext(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "no node identity")
	}

	// Sanity-check: warn if hello.NodeId disagrees with the cert identity, but
	// always use the cert identity and never let the wire value win.
	if hello.NodeId != "" && hello.NodeId != nodeID {
		slog.Warn("hello.node_id differs from cert identity; using cert",
			"cert_node_id", nodeID,
			"hello_node_id", hello.NodeId,
		)
	}

	hostname := ""
	if hello.Facts != nil {
		hostname = hello.Facts.Hostname
	}
	slog.Info("node connected",
		"node_id", nodeID,
		"daemon_version", hello.DaemonVersion,
		"hostname", hostname,
	)

	// Register this stream with the live-connection tracker so it can be torn
	// down immediately on revocation. The nil-guard keeps existing tunnel tests
	// (which construct &tunnelServer{} without conns) working unchanged.
	var cctx context.Context
	var release func()
	if s.conns != nil {
		cctx, release = s.conns.Track(stream.Context(), nodeID)
		defer release()
	} else {
		cctx = stream.Context()
	}

	// Record the Node's identity, facts, and node: labels in the registry.
	// CertFingerprint is recomputed from the verified leaf so the Upsert does
	// not blank the value that Enrollment stored (Upsert always overwrites it;
	// same cert → same fingerprint → no information loss).
	// EnrollingTokenID is intentionally omitted: Upsert's update path preserves
	// existing provenance (memory.go:93-94).
	// Nil-guard mirrors the conns nil-guard above so tests that build
	// &tunnelServer{} without a registry keep compiling and passing.
	if s.reg != nil {
		fp, _ := transport.PeerCertFingerprint(stream.Context())
		if _, err := s.reg.Upsert(registry.Report{
			NodeID:            nodeID,
			CertFingerprint:   fp,
			Facts:             protoconv.FactsFromProto(hello.Facts),
			NodeLabels:        nodeLabelsFromHello(hello.GetLabels()),
			PolicyFingerprint: hello.GetPolicyFingerprint(),
		}); err != nil {
			slog.Warn("registry upsert on hello failed", "node_id", nodeID, "err", err)
		}
	}

	// Send Ping after the registry Upsert so a client that receives the Ping is
	// guaranteed the registration is complete — tests use Ping as the sync point.
	if err := stream.Send(&gleipnirv1.RelayMessage{
		Body: &gleipnirv1.RelayMessage_Ping{
			Ping: &gleipnirv1.Ping{UnixMillis: time.Now().UnixMilli()},
		},
	}); err != nil {
		return status.Errorf(codes.Internal, "send ping: %v", err)
	}

	// Register the outbound send function with the test sink (if set).
	// In production s.sink is always nil; this block is a zero-cost no-op.
	if s.sink != nil {
		unregister := s.sink.register(nodeID, stream.Send)
		defer unregister()
	}

	// Run Recv in a goroutine so the select below can observe cctx cancellation.
	// grpc.ServerStream.Recv() does not unblock when a derived context is
	// cancelled; the select on cctx.Done() is the only way to deliver an
	// immediate revocation teardown signal.
	//
	// recvErr is buffered(1): when the handler returns the gRPC framework closes
	// the stream, which eventually causes stream.Recv() to return an error. The
	// goroutine must be able to send that error without blocking, otherwise it
	// would leak until the gRPC framework finalises the stream.
	recvErr := make(chan error, 1)
	recvMsg := make(chan *gleipnirv1.DaemonMessage)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				recvErr <- err
				return
			}
			select {
			case recvMsg <- m:
			case <-cctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-cctx.Done():
			return status.Error(codes.Unauthenticated, "node revoked")
		case err := <-recvErr:
			if err == io.EOF {
				return nil
			}
			return err
		case m := <-recvMsg:
			if hb := m.GetHeartbeat(); hb != nil {
				slog.Debug("heartbeat", "unix_millis", hb.UnixMillis)
				if s.reg != nil {
					if err := s.reg.UpdateLastSeen(nodeID, time.Now()); err != nil {
						slog.Warn("update last-seen failed", "node_id", nodeID, "err", err)
					}
				}
			}
			// Deliver TaskResult to the test sink (if set). In production
			// s.sink is always nil; this block is a zero-cost no-op.
			if s.sink != nil {
				if tr := m.GetTaskResult(); tr != nil {
					s.sink.deliver(nodeID, tr)
				}
			}
			// Deliver PolicyVerdict to the test sink (if set). In production
			// s.sink is always nil; this block is a zero-cost no-op.
			if s.sink != nil {
				if pv := m.GetPolicyVerdict(); pv != nil {
					s.sink.deliverVerdict(nodeID, pv)
				}
			}
			// Capture a reported PolicySnapshot into the display-only
			// policyview.Cache (#117). This RECORDS a report-only daemon
			// value for describe_node to display — it never sets or
			// modifies Node Policy (ADR-0002), exactly like the
			// PolicyFingerprint the registry already records on Hello.
			// Keyed by the cert-derived nodeID (never a wire value), like
			// every other write in this handler. Unconditional (not gated
			// by s.sink): this is the production capture path, not a
			// test-only seam.
			if ps := m.GetPolicy(); ps != nil && s.policy != nil {
				s.policy.Set(nodeID, snapshotFromProto(ps))
			}
		}
	}
}

// nodeLabelsFromHello extracts node-space labels from Hello labels, returning a
// map with bare keys (the "node:" prefix is stripped). Only keys with a "node:"
// prefix and a non-empty bare key are accepted; all other keys are silently
// dropped.
//
// WHY relay: labels are dropped: per ADR-0006 and the two-namespace label model,
// the Relay is the sole authority for relay: labels. A relay-daemon can never set
// relay-space labels, regardless of what it sends on the wire. Dropping (rather
// than rejecting with an error) keeps the tunnel resilient — a stray relay: label
// never tears down a long-lived connection.
func nodeLabelsFromHello(labels []*gleipnirv1.Label) map[string]string {
	result := make(map[string]string)
	for _, l := range labels {
		bare, ok := protoconv.ParseNodeLabel(l.GetKey())
		if !ok {
			continue // silently drop non-node: labels (see WHY above)
		}
		result[bare] = l.GetValue()
	}
	return result
}

// snapshotFromProto converts a daemon-reported gleipnirv1.PolicySnapshot into
// the proto-free policyview.Snapshot the display-only cache stores, keeping
// the policyview package itself free of a proto dependency (mirrors
// protoconv.FactsFromProto's role for registry.Facts). Display-only: this
// conversion never evaluates or validates the Policy it carries (ADR-0002,
// invariant 12) — it only reshapes the reported values for storage.
func snapshotFromProto(ps *gleipnirv1.PolicySnapshot) policyview.Snapshot {
	return policyview.Snapshot{
		RawExecEnabled:    ps.GetRawExecEnabled(),
		RawAllowPatterns:  ps.GetRawAllowPatterns(),
		RawDenyPatterns:   ps.GetRawDenyPatterns(),
		AllowedOperations: ps.GetAllowedOperations(),
		PolicyFingerprint: ps.GetPolicyFingerprint(),
	}
}
