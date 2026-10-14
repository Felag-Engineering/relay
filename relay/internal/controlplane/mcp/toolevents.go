package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"unicode/utf8"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tool-call observability (D9 in docs/design/console/99-open-decisions.md).
//
// The audit trail (readaudit.go) and this seam answer different
// questions: readaudit is a durable, append-only record of the four
// non-dispatching read tools; this is a best-effort, in-process feed for the
// Admin Console's live view, covering EVERY tool call — read and execution
// alike, including run_operation/raw_exec — through one choke point (the
// receiving middleware below) rather than a call site per tool.
//
// **Arguments only, never results.** A ToolCallEvent says who called which
// tool with what arguments — file paths, Selectors, and for raw_exec the
// full argv, which is the entire point of this publisher — and never what
// came back. Adding a result/output/content field to ToolCallEvent is
// precisely the failure internal/events' no_read_output_test.go (and this
// package's own TestToolCallEventHasNoResultField, no_dispatch_test.go)
// exist to catch structurally, not just by convention (ADR-0025).
//
// Mirrors readaudit.go's shape exactly: a data struct, a write-only
// interface, and a helper — naming no capability identifier, so this file
// classifies STRICT in no_dispatch_test.go's partition even though it sits
// on the execution tools' call path too.

// ToolCallEvent is one MCP tools/call invocation. toolCallMiddleware
// publishes it before calling the handler, by convention (see that
// function's doc comment for what is and is not structurally enforced);
// the field allowlist below is what actually guarantees a result can never
// be stored on it.
type ToolCallEvent struct {
	// Tool is the MCP tool name, e.g. "raw_exec", capped at
	// maxToolNameBytes by boundedToolName — this is observed BEFORE the SDK
	// has validated params.Name against the registered tool set, so an
	// unbounded caller-supplied name must never reach it (or, in turn, any
	// consumer that logs or renders it, e.g. cmd/relay's toolCallObserver).
	Tool string

	// Arguments renders each top-level argument as compact JSON text
	// (string values unquoted), bounded by argumentsFromRaw's
	// maxArgumentsBytes budget.
	Arguments map[string]string

	// ArgumentsTruncated is true when one or more arguments were dropped to
	// stay inside the budget — raw_exec's argv is caller-controlled, and
	// the bus behind this seam holds 1,000 of these per ring.
	ArgumentsTruncated bool
}

// ToolCallObserver records one tools/call invocation. The composition root
// supplies an adapter that resolves the acting Account from ctx and
// publishes to the event bus.
//
// No error return — unlike ReadAuditor, which fails a read closed on an
// unauditable access (ADR-0025 decision 4), this seam is best-effort
// observability and must never be able to fail a tool call: a Console
// watcher going down must never take execution down with it.
type ToolCallObserver interface {
	ToolCall(ctx context.Context, e ToolCallEvent)
}

// maxArgumentsBytes bounds the total rendered size of one ToolCallEvent's
// Arguments — KEYS as well as values (S2, review-feedback.md cycle 2): a
// budget that only charged rendered values let a caller send many huge keys
// with empty values and retain unbounded bytes while reporting
// truncated=false. Bounding matters: the event bus's ring holds 1,000 of
// these, and raw_exec's argv is caller-controlled.
const maxArgumentsBytes = 4096

// maxArgumentEntries caps the number of Arguments entries published per
// event, independent of maxArgumentsBytes: a flood of tiny (even
// zero-length) key/value pairs advances the byte budget only slowly but
// still costs one map entry apiece.
const maxArgumentEntries = 64

// maxToolNameBytes bounds the published MCP tool name. This middleware
// observes the call BEFORE the SDK has validated that params.Name names a
// registered tool, so an unbounded caller-supplied string must not reach
// the bus unchecked.
const maxToolNameBytes = 128

// toolCallMiddleware returns a receiving middleware that publishes a
// ToolCallEvent for every "tools/call" request (the SDK's unexported
// methodCallTool literal — sdkmcp does not export the constant, so this
// compares against the literal method name directly) and nothing else, then
// calls next.
//
// Publishing BEFORE next runs backstops internal/events' stdlib-only import
// and ToolCallEvent's closed field set, but — unlike those two, which the
// AST guards in no_read_output_test.go/no_dispatch_test.go actually
// enforce — it is a convention held in this one function body, not
// something the guards verify (S4, review-feedback.md cycle 2): this
// closure DOES receive next's return value below, so a future edit could
// move the o.ToolCall call after it. What stops a result being stored even
// then is ToolCallEvent's closed field set, which has nowhere to put one.
func toolCallMiddleware(o ToolCallObserver) sdkmcp.Middleware {
	return func(next sdkmcp.MethodHandler) sdkmcp.MethodHandler {
		return func(ctx context.Context, method string, req sdkmcp.Request) (sdkmcp.Result, error) {
			if method == "tools/call" {
				if params, ok := req.GetParams().(*sdkmcp.CallToolParamsRaw); ok {
					args, truncated := argumentsFromRaw(params.Arguments)
					o.ToolCall(ctx, ToolCallEvent{
						Tool:               boundedToolName(params.Name),
						Arguments:          args,
						ArgumentsTruncated: truncated,
					})
				}
			}
			return next(ctx, method, req)
		}
	}
}

// argumentsFromRaw unmarshals raw (a tools/call request's raw JSON
// arguments object) into a flat map of rendered values: a JSON string value
// is unquoted, everything else (number, bool, object, array, null) is
// rendered as compact JSON text.
//
// Keys are visited in sorted order so the budget below truncates
// deterministically. The budget charges BOTH the key and the rendered
// value against maxArgumentsBytes — charging values alone let a caller
// send many huge keys with empty values and retain unbounded bytes while
// truncated stayed false (S2, review-feedback.md cycle 2). Once adding an
// entry would exceed maxArgumentsBytes, or maxArgumentEntries entries have
// already been added, that entry (and every one after it, in sorted order)
// is dropped and truncated is reported true — an entry large enough to
// blow the budget by itself (raw_exec's argv, most plausibly) is dropped
// whole rather than emitted as a partial, possibly-malformed JSON fragment.
func argumentsFromRaw(raw json.RawMessage) (args map[string]string, truncated bool) {
	if len(raw) == 0 {
		return nil, false
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		// Not a JSON object (or not valid JSON at all) — nothing to render.
		return nil, false
	}

	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	args = make(map[string]string, len(fields))
	var total int
	for _, k := range keys {
		if len(args) >= maxArgumentEntries {
			truncated = true
			break
		}
		rendered := renderArgumentValue(fields[k])
		entryBytes := len(k) + len(rendered)
		if total+entryBytes > maxArgumentsBytes {
			truncated = true
			break
		}
		args[k] = rendered
		total += entryBytes
	}
	return args, truncated
}

// boundedToolName caps name at maxToolNameBytes, truncating at a UTF-8 rune
// boundary so the published Tool field is always valid UTF-8.
func boundedToolName(name string) string {
	if len(name) <= maxToolNameBytes {
		return name
	}
	b := []byte(name)[:maxToolNameBytes]
	for len(b) > 0 && !utf8.RuneStart(b[len(b)-1]) {
		b = b[:len(b)-1]
	}
	return string(b)
}

// renderArgumentValue renders one JSON value as a string: unquoted for a
// JSON string, otherwise its compact JSON text.
func renderArgumentValue(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err == nil {
		return buf.String()
	}
	return string(raw)
}
