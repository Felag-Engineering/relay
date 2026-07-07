//go:build devharness

// Package main: devharness.go is the ENTIRE dev-harness dispatch/control
// surface for #112's cross-binary CI test. It is a deliberate dev backdoor on
// an RCE control plane (it lets a local unix-socket client mint an Enrollment
// Token, wait for a Node to register, dispatch Tasks, and read registry
// state) and MUST NOT exist in production builds.
//
// Exclusion is structural, not a runtime flag:
//   - All logic lives in this file, gated by the `devharness` build tag.
//   - devharness_stub.go supplies the production no-op under `!devharness`.
//   - Even in a devharness-tagged build, installDevHarness is inert unless
//     RELAY_DEVHARNESS_SOCKET is explicitly set (defense in depth).
//   - scripts/devharness-absent-check.sh mechanically asserts the untagged
//     binary contains neither the serveDevHarnessSocket symbol nor the
//     RELAY_DEVHARNESS_SOCKET string literal.
//
// The control protocol is newline-delimited JSON over a unix domain socket
// (not proto-on-the-wire): this file is the sole place that translates
// to/from gleipnirv1, keeping the harness client trivial and this file
// self-auditing. It never evaluates or mutates Policy (ADR-0002/0011) — it
// only mints a Token, reads the registry, and forwards raw Tasks; the daemon's
// live engine remains the sole source of Policy verdicts.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	gleipnirv1 "github.com/Felag-Engineering/gleipnir-relay/relay/internal/gleipnir/v1"
)

// harnessSink implements taskSink (tunnel.go:28-32) for the dev-harness
// socket. It is an independent, compact copy of dispatch_test.go's
// `dispatcher` — the gated binary must not depend on _test.go code (a
// different compilation unit) — and only tracks what the control protocol
// needs: outbound send funcs and inbound TaskResults. PolicyVerdicts have no
// consumer here (the protocol has no PolicyQuery op), so deliverVerdict is a
// no-op.
type harnessSink struct {
	mu      sync.Mutex
	senders map[string]func(*gleipnirv1.RelayMessage) error
	results map[string]chan *gleipnirv1.TaskResult
}

func newHarnessSink() *harnessSink {
	return &harnessSink{
		senders: make(map[string]func(*gleipnirv1.RelayMessage) error),
		results: make(map[string]chan *gleipnirv1.TaskResult),
	}
}

// register implements taskSink. Called by tunnelServer.Open after Ping is sent.
func (h *harnessSink) register(nodeID string, send func(*gleipnirv1.RelayMessage) error) func() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.senders[nodeID] = send
	if _, ok := h.results[nodeID]; !ok {
		h.results[nodeID] = make(chan *gleipnirv1.TaskResult, 32)
	}
	return func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		delete(h.senders, nodeID)
	}
}

// deliver implements taskSink. Buffered (32) so the stream goroutine never
// blocks waiting on the socket client to read.
func (h *harnessSink) deliver(nodeID string, result *gleipnirv1.TaskResult) {
	h.mu.Lock()
	ch := h.results[nodeID]
	h.mu.Unlock()
	if ch != nil {
		ch <- result
	}
}

// deliverVerdict implements taskSink. No-op: the dev-harness control
// protocol has no PolicyQuery op, so there is nothing to deliver a
// PolicyVerdict to.
func (h *harnessSink) deliverVerdict(string, *gleipnirv1.PolicyVerdict) {}

// waitForNode polls until any Node registers a sender or deadline expires.
// Mirrors dispatch_test.go's waitForNode: the harness cannot know the
// cert-derived node_id in advance, so it watches for the first registration.
func (h *harnessSink) waitForNode(deadline time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	for {
		h.mu.Lock()
		for id := range h.senders {
			h.mu.Unlock()
			return id, nil
		}
		h.mu.Unlock()
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("wait_node: timeout after %v", deadline)
		case <-time.After(5 * time.Millisecond):
		}
	}
}

// dispatch sends msg to nodeID's registered sender.
func (h *harnessSink) dispatch(nodeID string, msg *gleipnirv1.RelayMessage) error {
	h.mu.Lock()
	send, ok := h.senders[nodeID]
	h.mu.Unlock()
	if !ok {
		return fmt.Errorf("dispatch: node %q not registered", nodeID)
	}
	return send(msg)
}

// resultChan returns nodeID's TaskResult channel, or nil if never registered.
func (h *harnessSink) resultChan(nodeID string) chan *gleipnirv1.TaskResult {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.results[nodeID]
}

// installDevHarness wires the dev-harness control socket into deps, iff
// RELAY_DEVHARNESS_SOCKET is set. If it is empty, this is a no-op — even a
// devharness-tagged binary is inert by default (defense in depth).
//
// Sets deps.tunnel.sink BEFORE the socket starts serving, and strictly before
// main's srv.Serve is called (installDevHarness runs between newServer and
// Serve), so there is no concurrency with the tunnel handler at the moment
// the sink is assigned.
func installDevHarness(deps *appDeps) (stop func(), err error) {
	sockPath := os.Getenv("RELAY_DEVHARNESS_SOCKET")
	if sockPath == "" {
		return func() {}, nil
	}

	sink := newHarnessSink()
	deps.tunnel.sink = sink

	if dir := filepath.Dir(sockPath); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("devharness: create socket dir: %w", err)
		}
	}
	// Best-effort: remove a stale socket file from a previous unclean shutdown.
	os.Remove(sockPath)

	lis, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("devharness: listen on %q: %w", sockPath, err)
	}
	if err := os.Chmod(sockPath, 0600); err != nil {
		lis.Close()
		return nil, fmt.Errorf("devharness: chmod socket: %w", err)
	}

	slog.Warn("devharness control socket active — CI/dev-only backdoor, never run in production",
		"socket", sockPath)

	go serveDevHarnessSocket(lis, deps, sink)

	stop = func() {
		lis.Close()
		os.Remove(sockPath)
	}
	return stop, nil
}

// serveDevHarnessSocket accepts connections on lis and handles each with the
// newline-delimited JSON control protocol. It returns when lis is closed
// (installDevHarness's stop func).
//
// //go:noinline is load-bearing: this is the SOLE symbol
// scripts/devharness-absent-check.sh greps for via `go tool nm` to prove the
// gated surface is absent from production builds. Without it the compiler
// could inline this small function away, making the check vacuous.
//
//go:noinline
func serveDevHarnessSocket(lis net.Listener, deps *appDeps, sink *harnessSink) {
	for {
		conn, err := lis.Accept()
		if err != nil {
			// Expected on stop(): lis.Close() causes Accept to return an error.
			return
		}
		go handleDevHarnessConn(conn, deps, sink)
	}
}

// harnessRequest is one line of the newline-delimited JSON control protocol.
type harnessRequest struct {
	Op             string            `json:"op"`
	Labels         []string          `json:"labels,omitempty"`
	TTLSeconds     int64             `json:"ttl_seconds,omitempty"`
	TimeoutSeconds int64             `json:"timeout_seconds,omitempty"`
	NodeID         string            `json:"node_id,omitempty"`
	TaskID         string            `json:"task_id,omitempty"`
	Operation      string            `json:"operation,omitempty"`
	Args           map[string]string `json:"args,omitempty"`
}

// harnessResponse is one line of the newline-delimited JSON control protocol
// reply. Only the fields relevant to the request's op are populated.
type harnessResponse struct {
	Token             string `json:"token,omitempty"`
	NodeID            string `json:"node_id,omitempty"`
	TaskID            string `json:"task_id,omitempty"`
	Outcome           string `json:"outcome,omitempty"`
	Stdout            string `json:"stdout,omitempty"`
	Stderr            string `json:"stderr,omitempty"`
	PolicyFingerprint string `json:"policy_fingerprint,omitempty"`
	// NodeLabels/RelayLabels intentionally have no `omitempty`: an empty-but-
	// present map (get_node on a Node with no labels) must still round-trip as
	// `{}`, not be silently dropped from the response.
	NodeLabels  map[string]string `json:"node_labels"`
	RelayLabels map[string]string `json:"relay_labels"`
	Error       string            `json:"error,omitempty"`
}

// handleDevHarnessConn reads newline-delimited JSON requests off conn and
// writes newline-delimited JSON responses, one per request, until the client
// disconnects or a write fails.
func handleDevHarnessConn(conn net.Conn, deps *appDeps, sink *harnessSink) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	enc := json.NewEncoder(conn)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req harnessRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			enc.Encode(harnessResponse{Error: fmt.Sprintf("invalid request: %v", err)}) //nolint:errcheck
			continue
		}
		resp := dispatchHarnessRequest(context.Background(), deps, sink, req)
		if err := enc.Encode(resp); err != nil {
			slog.Warn("devharness: write response failed", "err", err)
			return
		}
	}
}

// dispatchHarnessRequest routes req to its op handler. Every op is read-only
// with respect to Policy: it never evaluates or mutates it (ADR-0002/0011).
func dispatchHarnessRequest(ctx context.Context, deps *appDeps, sink *harnessSink, req harnessRequest) harnessResponse {
	switch req.Op {
	case "create_token":
		return harnessCreateToken(ctx, deps, req)
	case "wait_node":
		return harnessWaitNode(sink, req)
	case "dispatch":
		return harnessDispatch(sink, req)
	case "get_node":
		return harnessGetNode(deps, req)
	default:
		return harnessResponse{Error: fmt.Sprintf("unknown op %q", req.Op)}
	}
}

// harnessCreateToken mints an Enrollment Token via the real enroll.Service
// (enroll/token.go:174) and returns its plaintext credential.
//
// SECURITY: the plaintext token is returned to the socket client but MUST
// NEVER be logged (CLAUDE.md: never log secrets).
func harnessCreateToken(ctx context.Context, deps *appDeps, req harnessRequest) harnessResponse {
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = time.Hour
	}
	_, plaintext, err := deps.tokens.Create(ctx, req.Labels, ttl)
	if err != nil {
		slog.Warn("devharness: create_token failed", "err", err)
		return harnessResponse{Error: err.Error()}
	}
	return harnessResponse{Token: plaintext}
}

// harnessWaitNode blocks (up to timeout_seconds, default 30s) until a Node
// completes Hello->Ping registration, mirroring the poll at
// tunnel_dispatch_e2e_test.go:224-235.
func harnessWaitNode(sink *harnessSink, req harnessRequest) harnessResponse {
	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	nodeID, err := sink.waitForNode(timeout)
	if err != nil {
		return harnessResponse{Error: err.Error()}
	}
	return harnessResponse{NodeID: nodeID}
}

// harnessDispatch builds and sends a single-Operation TaskRequest to node_id
// and blocks (up to timeout_seconds, default 15s) for its TaskResult. It
// never evaluates Policy itself — the outcome (including
// OUTCOME_DENIED_BY_POLICY) comes from the daemon's live engine over the
// real wire (ADR-0011).
func harnessDispatch(sink *harnessSink, req harnessRequest) harnessResponse {
	if req.NodeID == "" || req.TaskID == "" || req.Operation == "" {
		return harnessResponse{Error: "dispatch: node_id, task_id, and operation are required"}
	}
	timeoutSeconds := req.TimeoutSeconds
	if timeoutSeconds <= 0 {
		timeoutSeconds = 15
	}
	resultCh := sink.resultChan(req.NodeID)
	if resultCh == nil {
		return harnessResponse{Error: fmt.Sprintf("dispatch: node %q not registered", req.NodeID)}
	}

	task := &gleipnirv1.RelayMessage{
		Body: &gleipnirv1.RelayMessage_Task{
			Task: &gleipnirv1.TaskRequest{
				TaskId:         req.TaskID,
				TimeoutSeconds: int32(timeoutSeconds),
				Action: &gleipnirv1.TaskRequest_Operation{
					Operation: &gleipnirv1.Operation{
						Name: req.Operation,
						Args: req.Args,
					},
				},
			},
		},
	}
	if err := sink.dispatch(req.NodeID, task); err != nil {
		return harnessResponse{Error: err.Error()}
	}

	select {
	case result := <-resultCh:
		return harnessResponse{
			TaskID:  result.TaskId,
			Outcome: result.Outcome.String(),
			Stdout:  string(result.Stdout),
			Stderr:  string(result.Stderr),
		}
	case <-time.After(time.Duration(timeoutSeconds) * time.Second):
		return harnessResponse{Error: fmt.Sprintf("dispatch: timeout waiting for TaskResult %q", req.TaskID)}
	}
}

// harnessGetNode reads the registry (registry.go:102) for node_id and
// returns its Policy fingerprint and labels. No get_ca op exists (plan-review
// BLOCKING-1): the harness client reads the CA bundle directly from
// <ca-dir>/ca-cert.pem, which ca.Open writes to disk during newServer,
// strictly before installDevHarness opens this socket.
func harnessGetNode(deps *appDeps, req harnessRequest) harnessResponse {
	if req.NodeID == "" {
		return harnessResponse{Error: "get_node: node_id is required"}
	}
	node, ok := deps.registry.Get(req.NodeID)
	if !ok {
		return harnessResponse{Error: fmt.Sprintf("get_node: node %q not found", req.NodeID)}
	}
	return harnessResponse{
		NodeID:            node.NodeID,
		PolicyFingerprint: node.PolicyFingerprint,
		NodeLabels:        node.NodeLabels,
		RelayLabels:       node.RelayLabels,
	}
}
