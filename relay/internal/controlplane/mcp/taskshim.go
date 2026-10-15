package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/logctx"
	"github.com/Felag-Engineering/relay/relay/internal/mcptask"
)

// taskshim.go is the ONE place Relay touches raw MCP wire JSON, and the
// highest-risk file in the v0.5.1 milestone (ADR-0028). Read this header
// before changing anything in it.
//
// # Why it exists
//
// SEP-2663 says a server that has parked a call returns a `CreateTaskResult`
// instead of a tool result. The SDK cannot express that: `CallToolResult`'s
// `resultType` is an unexported field admitting only `complete` and
// `input_required`, and `Result` is sealed by an unexported `isResult()`. So
// there is no way to return a task result through the SDK's tool path.
// ADR-0028 chose to shim rather than fork — a fork would make us maintainer of
// a security-critical protocol library forever, while a shim is bounded code
// with a written removal condition (go-sdk#626).
//
// `mcp.New` returns an `http.Handler` we mount ourselves, so the shim wraps it
// and reshapes exactly one response.
//
// # Why rewriting wire JSON is tractable HERE and nowhere else
//
// Two facts about this deployment, both of which ADR-0028 names as PRECONDITIONS
// whose violation voids this design:
//
//   - The SDK rejects JSON-RPC batching for protocol >= 2025-06-18, and
//   - Relay runs the handler with Stateless: true, JSONResponse: true.
//
// So every request is exactly one JSON-RPC message and every reply exactly one
// JSON object. The shim is a single-message response transformer, not a
// protocol reimplementation. If either fact changes, this file's assumption is
// void and ADR-0028 must be revisited before it is trusted again; [5/6]'s wire
// tests pin both so the change announces itself as a build failure.
//
// A pre-2025-06-18 client could still batch — but such a client cannot have
// advertised the Tasks capability, and the shim only ever inspects traffic from
// clients that did. It never touches the rest.
//
// # The rule this file lives by
//
// **When in any doubt, pass through untouched.** Every branch below that is not
// a confident, fully-identified parked result falls back to the byte-identical
// response the SDK produced. A half-rewritten response is worse than an
// un-rewritten one: the un-rewritten one is the universal `pending_approval`
// path, which works, and which ADR-0027 decision 2 requires never to be
// hard-depended upon anyway.
//
// # What this file structurally cannot do
//
// It is a strict READ file under no_dispatch_test.go: it may not name a
// capability identifier at all. It parses JSON and writes JSON. It cannot
// resolve a Selector, build an Action, reach the Job engine, or construct a
// dispatch — not by convention, but because the AST guard fails the build if it
// tries. That matters because this code sits on the `/mcp` RCE path and sees
// every request.

const (
	// tasksExtensionName is SEP-2663's capability identifier. A client that has
	// not advertised it is never sent a task result — the SEP requires this,
	// and it is also ADR-0027 decision 2 at the protocol level: the universal
	// path must stay whole for clients that know nothing about Tasks.
	tasksExtensionName = "io.modelcontextprotocol/tasks"

	// metaKeyClientCapabilities is where a >= 2026-07-28 client restates its
	// capabilities on every request (SEP-2575). Relay is stateless, so this
	// per-request restatement is the ONLY place the capability is knowable —
	// there is no session carrying the initialize handshake forward.
	metaKeyClientCapabilities = "io.modelcontextprotocol/clientCapabilities"

	// resultTypeTask is SEP-2663's discriminator. The SDK emits "complete" for
	// an ordinary tool result; this is what replaces it.
	resultTypeTask = "task"

	// maxShimBodyBytes bounds what the shim will hold in memory, on the request
	// and the response alike. A body larger than this is passed through
	// UNINSPECTED rather than buffered: an RCE surface must not let a caller
	// size the server's heap by sending a large tools/call.
	maxShimBodyBytes = 1 << 20 // 1 MiB
)

// withTaskShim wraps next so that a parked tool result is rewritten into a
// SEP-2663 task result, for clients that advertised the Tasks extension.
//
// The wrapper is deliberately a no-op object for everything else: a request
// that is not a Tasks-capable `tools/call` never enters the buffering path at
// all and reaches next holding the ORIGINAL http.ResponseWriter. Non-`tools/call`
// methods, error responses, plans, ordinary runs, and every client that did not
// advertise the extension are therefore not merely "passed through" — they are
// never processed, which is a stronger property and a much smaller blast radius
// for a bug in this file.
//
// now is a seam so the shim's ttlMs arithmetic is testable, mirroring the
// capability Approvals' clock. Production passes time.Now().UTC().
func withTaskShim(next http.Handler, now func() time.Time, log *slog.Logger) http.Handler {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := readShimBody(r)
		if !ok || !isTasksCapableToolCall(body) {
			next.ServeHTTP(w, r)
			return
		}

		capture := &shimCapture{header: http.Header{}}
		next.ServeHTTP(capture, r)

		rewritten, taskID, ok := rewriteParkedResult(capture, now())
		if !ok {
			capture.passThrough(w)
			return
		}

		// The shim's usage signal. This is the deployment's answer to
		// "is anyone actually using Tasks?", which is the question that decides
		// when the shim can be DELETED — a temporary shim nobody can tell is
		// unused becomes a permanent one. It logs only on a real rewrite, so
		// silence in the log is the meaningful reading: no Tasks-capable client
		// has driven a gated dispatch through this Relay.
		//
		// One line per park, and a park is a human-gated event, so this cannot
		// become chatty. It carries the task id and nothing about the Plan: the
		// approval trail already records what was parked, and this is routing
		// metadata, not content.
		logctx.Or(log).InfoContext(r.Context(), "mcp task result issued",
			"task_id", taskID, "shim", "sep-2663", "removal_condition", "go-sdk#626")

		writeShimResponse(w, capture, rewritten)
	})
}

// readShimBody reads r's body up to the cap and restores it for the handler
// underneath, which must see exactly the bytes the client sent.
//
// ok is false when the body is absent or larger than the cap. In the oversized
// case the bytes already read are spliced back in front of the remainder, so
// the handler still receives the complete request — the shim gives up on
// inspecting it, never on serving it.
func readShimBody(r *http.Request) ([]byte, bool) {
	if r.Method != http.MethodPost || r.Body == nil {
		return nil, false
	}

	limited := io.LimitReader(r.Body, maxShimBodyBytes+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		// Splice back what was read so the handler sees the same failure the
		// shim did, rather than a truncated body it might accept.
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(buf), r.Body), r.Body}
		return nil, false
	}
	if len(buf) > maxShimBodyBytes {
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(buf), r.Body), r.Body}
		return nil, false
	}

	r.Body = io.NopCloser(bytes.NewReader(buf))
	return buf, true
}

// shimRequest is the minimum of a JSON-RPC request the shim needs. Everything
// else about the message is none of its business.
type shimRequest struct {
	Method string `json:"method"`
	Params struct {
		Meta map[string]json.RawMessage `json:"_meta"`
	} `json:"params"`
}

// isTasksCapableToolCall reports whether body is a single `tools/call` from a
// client that advertised the Tasks extension.
//
// Every failure to parse is a false: an unreadable request is one the shim has
// no business reshaping the answer to. Note it does NOT attempt to handle a
// JSON-RPC batch (a top-level array) — such a client is pre-2025-06-18 and
// cannot have advertised Tasks, so the array simply fails to unmarshal into the
// object below and the request passes through, which is correct.
func isTasksCapableToolCall(body []byte) bool {
	var req shimRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return false
	}
	if req.Method != "tools/call" {
		return false
	}

	raw, ok := req.Params.Meta[metaKeyClientCapabilities]
	if !ok {
		return false
	}
	var caps struct {
		Extensions map[string]json.RawMessage `json:"extensions"`
	}
	if err := json.Unmarshal(raw, &caps); err != nil {
		return false
	}
	_, advertised := caps.Extensions[tasksExtensionName]
	return advertised
}

// shimCapture buffers a response so it can be inspected before being sent.
//
// It is only ever installed for a candidate request (see withTaskShim), so the
// response it holds is a single tool result. If one somehow exceeds the cap it
// stops buffering and records the fact; the shim then passes the whole thing
// through unmodified, which is the safe direction.
type shimCapture struct {
	header    http.Header
	status    int
	body      bytes.Buffer
	overflow  bool
	wroteHead bool
}

func (c *shimCapture) Header() http.Header { return c.header }

func (c *shimCapture) WriteHeader(status int) {
	if c.wroteHead {
		return
	}
	c.status, c.wroteHead = status, true
}

func (c *shimCapture) Write(p []byte) (int, error) {
	if !c.wroteHead {
		c.WriteHeader(http.StatusOK)
	}
	if c.overflow || c.body.Len()+len(p) > maxShimBodyBytes {
		c.overflow = true
		// Keep accepting the bytes so the handler below never sees a short
		// write, but stop retaining them: passThrough will replay what we have
		// and the response is abandoned as a rewrite candidate. In practice a
		// parked result is a few hundred bytes and this never fires.
		return len(p), nil
	}
	return c.body.Write(p)
}

// passThrough replays the captured response onto the real writer, byte for
// byte. This is the fallback every uncertain branch takes.
func (c *shimCapture) passThrough(w http.ResponseWriter) {
	for k, vs := range c.header {
		w.Header()[k] = vs
	}
	status := c.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(c.body.Bytes())
}

// shimResponse is the minimum of a JSON-RPC response the shim needs.
// Result and Error carry omitempty because a JSON-RPC response has one or the
// other and never both. Without it the rewritten response would ship
// `"error": null` beside its result — well-formed JSON that is a malformed
// JSON-RPC response, and exactly the kind of thing a strict client rejects
// while a lenient one quietly accepts.
type shimResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// parkedStructuredContent is the parked tool result as it appears on the wire —
// the same shape PendingApprovalOutput renders.
//
// Identification is by the STRUCTURED status field, never by sniffing prose.
// The summary is Relay-authored text about a fleet action; matching on it would
// make the wire contract depend on wording, and wording changes.
type parkedStructuredContent struct {
	PendingApproval *struct {
		Status        string `json:"status"`
		TaskID        string `json:"task_id"`
		TaskExpiresAt string `json:"task_expires_at"`
	} `json:"pending_approval"`
}

// taskResultBody is SEP-2663's CreateTaskResult, flat like the SDK's own
// `input_required` result (which carries `inputRequests` at the result's top
// level beside `resultType`).
type taskResultBody struct {
	Meta           json.RawMessage `json:"_meta,omitempty"`
	ResultType     string          `json:"resultType"`
	TaskID         string          `json:"taskId"`
	Status         string          `json:"status"`
	CreatedAt      string          `json:"createdAt"`
	LastUpdatedAt  string          `json:"lastUpdatedAt"`
	TTLMs          int64           `json:"ttlMs"`
	PollIntervalMs int64           `json:"pollIntervalMs"`
}

// rewriteParkedResult produces the task-shaped response body, or ok=false to
// leave the captured response alone.
//
// Read the false branches as the specification: a non-200, a non-JSON
// content type, an unparseable envelope, a JSON-RPC error, a result that is not
// a parked dispatch, a park with no handle attached — every one of them is a
// case where the shim cannot be certain, and every one of them keeps the
// working universal response.
func rewriteParkedResult(c *shimCapture, now time.Time) (body []byte, taskID string, ok bool) {
	if c.overflow {
		return nil, "", false
	}
	if status := c.status; status != 0 && status != http.StatusOK {
		return nil, "", false
	}
	if ct := c.header.Get("Content-Type"); ct != "" && !isJSONContentType(ct) {
		return nil, "", false
	}

	var resp shimResponse
	if err := json.Unmarshal(c.body.Bytes(), &resp); err != nil {
		return nil, "", false
	}
	if len(resp.Error) > 0 || len(resp.Result) == 0 {
		return nil, "", false
	}

	var result struct {
		Meta              json.RawMessage         `json:"_meta"`
		StructuredContent parkedStructuredContent `json:"structuredContent"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, "", false
	}
	parked := result.StructuredContent.PendingApproval
	if parked == nil || parked.Status != statusPendingApproval || parked.TaskID == "" {
		return nil, "", false
	}

	// ttlMs comes from the HANDLE's own expiry, which the Relay computed and
	// sent — never from the approval's expiry and never derived here. A shim
	// that worked out a lifetime for itself would be a second copy of the cap
	// in mcptask, and the two would drift.
	ttl := int64(0)
	if expires, err := time.Parse(time.RFC3339, parked.TaskExpiresAt); err == nil {
		ttl = mcptask.TTLMillis(expires, now)
	}

	stamp := now.Format(time.RFC3339)
	taskResult, err := json.Marshal(taskResultBody{
		Meta:       result.Meta,
		ResultType: resultTypeTask,
		TaskID:     parked.TaskID,
		// The dispatch is parked and nothing has run, which is `working`. The
		// authoritative status is always recomputed by tasks/get from the live
		// approval Request; this is the value at the instant of the park, and
		// the client's very next poll re-derives it.
		Status: mcptask.StatusWorking.String(),
		// The park happened in the response being rewritten, so "now" is when
		// this handle was created and last updated.
		CreatedAt:      stamp,
		LastUpdatedAt:  stamp,
		TTLMs:          ttl,
		PollIntervalMs: defaultPollIntervalMs,
	})
	if err != nil {
		return nil, "", false
	}

	out, err := json.Marshal(shimResponse{JSONRPC: resp.JSONRPC, ID: resp.ID, Result: taskResult})
	if err != nil {
		return nil, "", false
	}
	return out, parked.TaskID, true
}

// writeShimResponse sends the rewritten body, correcting Content-Length since
// the rewrite changes the size.
func writeShimResponse(w http.ResponseWriter, c *shimCapture, body []byte) {
	for k, vs := range c.header {
		w.Header()[k] = vs
	}
	w.Header().Del("Content-Length")
	status := c.status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// isJSONContentType reports whether ct is a JSON media type, ignoring
// parameters such as "; charset=utf-8".
func isJSONContentType(ct string) bool {
	if i := indexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return trimSpace(ct) == "application/json"
}

// indexByte and trimSpace avoid importing strings into this file for two
// trivial operations; keeping the import set minimal is part of what makes the
// shim easy to audit.
func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	start := 0
	for start < len(s) && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	end := len(s)
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}
