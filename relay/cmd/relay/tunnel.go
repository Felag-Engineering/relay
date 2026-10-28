package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/dispatch"
	"github.com/Felag-Engineering/relay/relay/internal/nodevocab"
	"github.com/Felag-Engineering/relay/relay/internal/policyview"
	"github.com/Felag-Engineering/relay/relay/internal/protoconv"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/revocation"
	"github.com/Felag-Engineering/relay/relay/internal/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// taskSink is the seam for capturing Task dispatch and results: hermetic
// unit tests, the cross-binary CI harness (installDevHarness,
// devharness-tagged build only), and newServer itself, which
// sets it to the real dispatch.Router (via routerSink, dispatch_wiring.go)
// whenever Config.ControlEnabled, so Tasks dispatched through the capability
// pipeline actually reach connected daemons over this mTLS Tunnel. Nil when
// the control plane is disabled (execution off).
//
// register is called after the Ping handshake completes; it records the
// outbound send function for the node and returns a cleanup func; the options
// say how the registration ends (dispatch.WithLiveStreamCheck). streamEnded is
// called instead, at teardown, by a stream that never registered; live says
// whether any stream still claims the Node (dispatch.Router.StreamEnded).
// deliver is called when a TaskResult arrives on the inbound stream.
// deliverVerdict is called when a PolicyVerdict arrives on the inbound stream (the daemon's
// answer to a PolicyQuery; ADR-0011 — the Relay only reads it, never evaluates
// Policy itself).
type taskSink interface {
	register(nodeID string, send func(*relayv1.RelayMessage) error, opts ...dispatch.RegisterOption) (unregister func())
	streamEnded(nodeID string, live func() bool)
	deliver(nodeID string, result *relayv1.TaskResult)
	deliverVerdict(nodeID string, verdict *relayv1.PolicyVerdict)
}

// heartbeatInterval is the relay-daemon's built-in heartbeat period. It is not
// a setting: the daemon's HEARTBEAT_INTERVAL carries the same value, and
// TestLivenessConstants_AgreeWithTheDaemon pins the two together.
const heartbeatInterval = 60 * time.Second

// missedHeartbeatAllowance is how many heartbeat intervals may pass with no
// Heartbeat before the Relay marks a Node offline and closes its stream. Three
// tolerates a late or lost heartbeat, and the daemon's jitter, without a
// false offline.
const missedHeartbeatAllowance = 3

// streamClaims records, per Node, which Tunnel streams are live, so that only
// the end of a Node's last live stream marks it offline. A Node that
// reconnects while its old stream is still tearing down has two streams at
// once, and the old stream's end must never clear the connectedness the new
// stream set: that is node-connection's "closing a replaced stream never marks
// the Node offline", for the registry's connected flag. Equally, a new stream
// that fails before it is established must not clear the connectedness of an
// older stream still live. The Router asks the same question (anyLive) at a
// stream's end, to learn whether the Node is offline. The zero value is ready
// for use.
//
// The mutex is held across the registry write on purpose. The last-claim check
// and the write must be atomic against a newer stream's open, or an old stream
// could decide it is the last, lose the CPU to the new stream's
// SetConnected(true), then write false over it. SetConnected is in-memory and
// its event publication does not block, so the critical section stays short.
// anyLive is called with the Router's lock held, so nothing holding
// streamClaims.mu may call into the Router.
type streamClaims struct {
	mu   sync.Mutex
	next uint64
	live map[string]map[uint64]struct{}
}

// open records a new live stream for nodeID, marks the Node connected, and
// returns the stream's generation. A uint64 generation, not a pointer, is the
// identity: Go does not promise distinct pointers to distinct zero-size values.
func (c *streamClaims) open(reg registry.Repository, nodeID string) uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.live == nil {
		c.live = make(map[string]map[uint64]struct{})
	}
	c.next++
	if c.live[nodeID] == nil {
		c.live[nodeID] = make(map[uint64]struct{})
	}
	c.live[nodeID][c.next] = struct{}{}
	if reg != nil {
		reg.SetConnected(nodeID, true)
	}
	return c.next
}

// close ends the claim gen. If it was nodeID's last live stream it marks the
// Node not connected and reports true; while another stream is live it is a
// no-op on the registry and reports false.
func (c *streamClaims) close(reg registry.Repository, nodeID string, gen uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	streams := c.live[nodeID]
	delete(streams, gen)
	if len(streams) > 0 {
		return false
	}
	delete(c.live, nodeID)
	if reg != nil {
		reg.SetConnected(nodeID, false)
	}
	return true
}

// anyLive reports whether any stream for nodeID is live.
func (c *streamClaims) anyLive(nodeID string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.live[nodeID]) > 0
}

type tunnelServer struct {
	relayv1.UnimplementedTunnelServer
	conns *revocation.Connections
	reg   registry.Repository
	// policy is the display-only effective-Policy cache (invariant 12 /
	// ADR-0002): the Relay records what a daemon reports in
	// DaemonMessage.policy and never evaluates or sets Policy itself. Nil-guarded
	// like reg/conns so existing tests that construct &tunnelServer{} directly
	// keep compiling; nil in any test that doesn't need the capture.
	policy *policyview.Cache
	// vocab is the per-Node Template Operation vocabulary cache (ADR-0021): the Relay records what a daemon reports in
	// DaemonMessage.templates so describe_node/list_operations can show a
	// Node's live vocabulary, and so a Template dispatch can resolve its
	// fan-out and class (ADR-0042). It never sets a Node's templates, exactly as it
	// never sets Policy (ADR-0002). Nil-guarded like policy/reg/conns.
	vocab *nodevocab.Cache
	// sink is set by newServer when Config.ControlEnabled (production
	// execution), by installDevHarness in a devharness-tagged build, or
	// injected directly by tests; nil when the control plane is disabled.
	sink taskSink

	// heartbeatDeadline is how long a stream may go without a Heartbeat before
	// the Relay closes it. Zero means missedHeartbeatAllowance heartbeat
	// intervals; only tests set it, and no setting exists.
	heartbeatDeadline time.Duration

	// claims tracks each Node's live streams. See streamClaims.
	claims streamClaims
}

// livenessDeadline is how long a stream may go without a Heartbeat.
func (s *tunnelServer) livenessDeadline() time.Duration {
	if s.heartbeatDeadline > 0 {
		return s.heartbeatDeadline
	}
	return missedHeartbeatAllowance * heartbeatInterval
}

func (s *tunnelServer) Open(stream grpc.BidiStreamingServer[relayv1.DaemonMessage, relayv1.RelayMessage]) error {
	first, err := stream.Recv()
	if err == io.EOF { //nolint:errorlint // grpc-go returns io.EOF unwrapped from Recv at a clean end of stream
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

	// Every self-reported field is accepted only in the shape a well-behaved
	// relay-daemon sends; what fails is recorded as not reported, so the log
	// and the registry below carry only bounded values.
	report, refusedFields := protoconv.HelloReportFromProto(hello)

	// Sanity-check: warn if hello.NodeId disagrees with the cert identity, but
	// always use the cert identity and never let the wire value win.
	if hello.NodeId != "" && hello.NodeId != nodeID {
		slog.Warn("hello.node_id differs from cert identity; using cert",
			"cert_node_id", nodeID,
			"hello_node_id", fmt.Sprintf("%q", boundedLogValue(hello.NodeId)),
		)
	}

	slog.Info("node connected",
		"node_id", nodeID,
		"daemon_version", report.DaemonVersion,
		"hostname", report.Facts.Hostname,
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

	// Mark the Node connected for as long as this stream lives.
	//
	// This is the seam that makes "connected now?" a fact the registry holds
	// rather than a guess from LastSeen. The deferred teardown is what makes it
	// true in the direction that matters: the close of the Node's last live
	// stream flips the answer immediately, however it ended — clean
	// shutdown, network drop, missed heartbeats, revocation teardown, or
	// panic.
	//
	// Claimed BEFORE the Upsert so there is no window in which a Node is in
	// the registry but not yet marked connected; a reader landing in that gap
	// would see a Node that is plainly here as offline.
	gen := s.claims.open(s.reg, nodeID)

	// The teardown order is load-bearing. The claim ends first, clearing
	// connectedness only if this was the Node's last live stream, so a
	// reconnect during the offline resolution sets it after the clear and the
	// Node reads connected throughout. Only then does the Router learn the
	// stream ended: a registration's unregister removes the conn, and a stream
	// that never registered reports its end (streamEnded). Either way the
	// Router decides whether the Node is now offline, asking the claims
	// whether any stream is still live, and if it is offline resolves the
	// Tasks in flight to it and fails the waiters. The revocation release,
	// deferred earlier, runs last.
	//
	// A stream that ends while another holds the Node leaves the Node to that
	// one: it may register and re-send the Tasks in flight for their result,
	// or it too may end, and the last stream to end runs the offline
	// resolution whether or not it ever registered.
	var unregister func()
	live := func() bool { return s.claims.anyLive(nodeID) }
	defer func() {
		s.claims.close(s.reg, nodeID, gen)
		switch {
		case unregister != nil:
			unregister()
		case s.sink != nil:
			s.sink.streamEnded(nodeID, live)
		}
	}()

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
		labels, refused := nodeLabelsFromHello(hello.GetLabels())
		// One bounded warning per connect, never one per refused label: a
		// hostile or misconfigured Node can send an unbounded number of
		// labels, and this is the one place that count would otherwise be
		// attacker-controlled log volume.
		//
		// The key is BOUNDED BEFORE IT IS QUOTED, and the two do different
		// jobs: %q bounds control characters and newlines, and the
		// truncation bounds LENGTH. Quoting alone does not — a wire key is
		// attacker-controlled up to gRPC's 4 MiB message limit, so a
		// reconnect-looping Node could write megabytes per connect.
		// enroll/handler.go reached the same conclusion for its
		// attacker-controlled TokenID and fixed it with looksLikeTokenID,
		// exact shape validation, rather than with quoting.
		//
		// The VALUE is never logged: it is exactly the self-reported
		// string this check just decided not to trust.
		if len(refused) > 0 {
			slog.Warn("refused malformed node labels", "node_id", nodeID,
				"refused_count", len(refused),
				"first_refused_key", fmt.Sprintf("%q", boundedLogValue(refused[0])))
		}
		// A set over the per-Node cap is recorded as not reported, never
		// truncated: keeping the previous set would serve a self-report the
		// Node no longer makes. One line per connect, counts only.
		if !registry.WithinNodeLabelCap(len(labels)) {
			slog.Warn("refused node labels over the per-Node limit; recorded as not reported",
				"node_id", nodeID, "count", len(labels), "limit", registry.MaxNodeLabels)
			labels = map[string]string{}
		}
		// Field names from a closed set, never a value, once per connect: the
		// refused value is exactly what this check decided not to trust.
		if len(refusedFields) > 0 {
			slog.Warn("refused malformed Hello fields; recorded as not reported",
				"node_id", nodeID, "refused_fields", refusedFields)
		}
		if _, err := s.reg.Upsert(registry.Report{
			NodeID:            nodeID,
			CertFingerprint:   fp,
			Facts:             report.Facts,
			PolicyFingerprint: report.PolicyFingerprint,
			DaemonVersion:     report.DaemonVersion,
			// Report-only, beside the Policy fingerprint (ADR-0021): the
			// fleet-wide template-drift signal. Recording it never gives the
			// Relay the power to change it (ADR-0002).
			TemplateSetFingerprint: report.TemplateSetFingerprint,
		}.WithNodeLabels(labels)); err != nil {
			slog.Warn("registry upsert on hello failed", "node_id", nodeID, "err", err)
		}
	}

	// Send Ping after the registry Upsert so a client that receives the Ping is
	// guaranteed the registration is complete — tests use Ping as the sync point.
	if err := stream.Send(&relayv1.RelayMessage{
		Body: &relayv1.RelayMessage_Ping{
			Ping: &relayv1.Ping{UnixMillis: time.Now().UnixMilli()},
		},
	}); err != nil {
		return status.Errorf(codes.Internal, "send ping: %v", err)
	}

	// Register the outbound send function with the sink (if set). Nil, and
	// this block a zero-cost no-op, when the control plane is disabled
	// (execution off); the real production sink when it's enabled.
	//
	// A newer registration for the Node displaces this one, and this stream
	// then ends: it will never register again, and left live it would hold
	// the Node, so the newer stream's end could not find the Node offline.
	displaced := make(chan struct{})
	var displaceOnce sync.Once
	if s.sink != nil {
		unregister = s.sink.register(nodeID, stream.Send, dispatch.WithLiveStreamCheck(live),
			dispatch.WithOnDisplaced(func() { displaceOnce.Do(func() { close(displaced) }) }))
	}

	// The Node is connected while its Heartbeats arrive within the deadline.
	// The clock starts once registration completes, so a registration that
	// waits behind the previous stream's offline resolution never counts
	// against it. Only a Heartbeat resets it.
	deadline := s.livenessDeadline()
	timer := time.NewTimer(deadline)
	defer timer.Stop()

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
	recvMsg := make(chan *relayv1.DaemonMessage)
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
		case <-displaced:
			slog.Info("node stream replaced by a newer stream for the same node; closing it", "node_id", nodeID)
			return status.Error(codes.Aborted, "replaced by a newer stream for this node")
		case <-timer.C:
			slog.Warn("node offline: no heartbeat within the missed-heartbeat allowance; closing its stream",
				"node_id", nodeID, "deadline", deadline)
			return status.Errorf(codes.Unavailable, "no heartbeat within %s", deadline)
		case err := <-recvErr:
			if err == io.EOF { //nolint:errorlint // grpc-go returns io.EOF unwrapped from Recv at a clean end of stream
				return nil
			}
			return err
		case m := <-recvMsg:
			if hb := m.GetHeartbeat(); hb != nil {
				slog.Debug("heartbeat", "unix_millis", hb.UnixMillis)
				timer.Reset(deadline)
				if s.reg != nil {
					if err := s.reg.UpdateLastSeen(nodeID, time.Now()); err != nil {
						slog.Warn("update last-seen failed", "node_id", nodeID, "err", err)
					}
				}
			}
			// Deliver TaskResult to the sink (if set) — the real production
			// sink is how a dispatched Task's result reaches the
			// waiting Router.Dispatch call. Nil, and this block a zero-cost
			// no-op, when the control plane is disabled.
			if s.sink != nil {
				if tr := m.GetTaskResult(); tr != nil {
					s.sink.deliver(nodeID, tr)
				}
			}
			// Deliver PolicyVerdict to the sink (if set); nil-guarded like
			// deliver above.
			if s.sink != nil {
				if pv := m.GetPolicyVerdict(); pv != nil {
					s.sink.deliverVerdict(nodeID, pv)
				}
			}
			// Capture a reported PolicySnapshot into the display-only
			// policyview.Cache. This RECORDS a report-only daemon
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
			// Capture a reported TemplateSnapshot into the nodevocab.Cache.
			// Same posture as the PolicySnapshot capture above: it
			// RECORDS a report-only daemon value — for discovery, and since
			// ADR-0042 as the input to a Template dispatch's fan-out and
			// class — and can never set or modify the Node's templates
			// (ADR-0002, ADR-0021). Keyed by the cert-derived nodeID, never a
			// wire value.
			if ts := m.GetTemplates(); ts != nil && s.vocab != nil {
				s.vocab.Set(nodeID, vocabFromProto(ts))
			}
		}
	}
}

// nodeLabelsFromHello extracts node-space labels from Hello labels, returning
// a map with bare keys (the "node:" prefix is stripped) and the RAW WIRE KEYS
// of every label that ParseNodeLabel refused. Only keys with a "node:"
// prefix, a non-empty bare key, and a well-formed (bare key, value) pair
// (registry.WellFormedLabel) are accepted; everything else is
// omitted from the map, never sanitised into it.
//
// WHY relay: labels are dropped: per ADR-0006 and the two-namespace label model,
// the Relay is the sole authority for relay: labels. A relay-daemon can never set
// relay-space labels, regardless of what it sends on the wire. Dropping (rather
// than rejecting with an error) keeps the tunnel resilient — a stray relay: label
// never tears down a long-lived connection.
//
// WHY a malformed node: label is dropped rather than sanitised (ADR-0017):
// sanitising "role=web x" to "role=webx" would make the Node match a Selector
// NOBODY WROTE — the Relay itself manufacturing the attracting value, ADR-0017's
// forge-to-attract cell — while omission can only produce forge-to-evade, which
// ADR-0017 already accepts as a residual a compromised Node has for free by
// reporting a well-formed lie instead. Omission is per-label: one malformed
// site does not cost a Node every other label it reported, and refusing the
// DATA rather than the connection means an unreachable Node — one that could
// never be inspected, quarantined or remediated — is never the outcome of a
// typo in one label's value.
func nodeLabelsFromHello(labels []*relayv1.Label) (result map[string]string, refused []string) {
	result = make(map[string]string)
	for _, l := range labels {
		bare, ok := protoconv.ParseNodeLabel(l.GetKey(), l.GetValue())
		if !ok {
			if strings.HasPrefix(l.GetKey(), "node:") {
				// Only a node:-prefixed key that failed well-formedness is a
				// refusal worth surfacing; every other prefix (relay:, tag:,
				// state:, or none) is the ordinary non-node: drop above and
				// was never going anywhere near the registry regardless.
				refused = append(refused, l.GetKey())
			}
			continue
		}
		result[bare] = l.GetValue()
	}
	return result, refused
}

// snapshotFromProto converts a daemon-reported relayv1.PolicySnapshot into
// the proto-free policyview.Snapshot the display-only cache stores, keeping
// the policyview package itself free of a proto dependency (mirrors
// protoconv.FactsFromProto's role for registry.Facts). Display-only: this
// conversion never evaluates or validates the Policy it carries (ADR-0002,
// invariant 12) — it only reshapes the reported values for storage.
func snapshotFromProto(ps *relayv1.PolicySnapshot) policyview.Snapshot {
	var operationRules []policyview.OperationRule
	for _, r := range ps.GetOperationRules() {
		operationRules = append(operationRules, policyview.OperationRule{
			Name:        r.GetName(),
			AllowedArgs: argMatchersToArgSets(r.GetAllowedArgs()),
		})
	}
	var denyRules []policyview.DenyRule
	for _, r := range ps.GetDenyRules() {
		denyRules = append(denyRules, policyview.DenyRule{
			Name: r.GetName(),
			Args: argMatchersToArgSets(r.GetArgs()),
		})
	}
	return policyview.Snapshot{
		RawExecEnabled:    ps.GetRawExecEnabled(),
		RawAllowPatterns:  ps.GetRawAllowPatterns(),
		RawDenyPatterns:   ps.GetRawDenyPatterns(),
		AllowedOperations: ps.GetAllowedOperations(),
		PolicyFingerprint: ps.GetPolicyFingerprint(),
		OperationRules:    operationRules,
		DenyRules:         denyRules,
	}
}

// vocabFromProto converts a daemon-reported relayv1.TemplateSnapshot into the
// proto-free nodevocab.Snapshot the vocabulary cache stores, keeping that
// package proto-free (mirrors snapshotFromProto's role for policyview).
// This conversion never validates a slot, renders a body (there is no body on
// the wire), or decides anything (ADR-0011, invariant 12).
func vocabFromProto(ts *relayv1.TemplateSnapshot) nodevocab.Snapshot {
	templates := make([]nodevocab.Template, 0, len(ts.GetTemplates()))
	for _, t := range ts.GetTemplates() {
		slots := make([]nodevocab.Slot, 0, len(t.GetSlots()))
		for _, sl := range t.GetSlots() {
			slots = append(slots, nodevocab.Slot{
				Name:       sl.GetName(),
				Type:       sl.GetType(),
				EnumValues: append([]string(nil), sl.GetEnumValues()...),
			})
		}
		templates = append(templates, nodevocab.Template{
			Name:      t.GetName(),
			RiskClass: int32(t.GetRiskClass()),
			Slots:     slots,
		})
	}
	return nodevocab.Snapshot{
		Fingerprint: ts.GetTemplateSetFingerprint(),
		Templates:   templates,
	}
}

// argMatchersToArgSets converts a repeated relayv1.ArgMatcher into the
// positional [][]string shape policyview carries, deep-copying each
// position's values so no proto-owned backing array escapes the cache.
// Display-only conversion (ADR-0002) — never resolves wildcards.
func argMatchersToArgSets(matchers []*relayv1.ArgMatcher) [][]string {
	if matchers == nil {
		return nil
	}
	out := make([][]string, len(matchers))
	for i, m := range matchers {
		out[i] = append([]string(nil), m.GetValues()...)
	}
	return out
}

// boundedLogValue bounds an attacker-controlled wire string for a log. It
// delegates to registry.BoundLogKey, which owns the one rune-safe truncation
// for this one hazard — see that function for why a second copy is not allowed.
func boundedLogValue(k string) string {
	bounded, _ := registry.BoundLogKey(k)
	return bounded
}
