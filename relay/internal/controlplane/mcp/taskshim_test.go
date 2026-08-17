package mcp

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// taskshim_test.go exercises the shim over synthetic bytes, where every branch
// can be reached deliberately. The real-wire proof — that the SDK actually
// emits the shape matched here — is cmd/relay's e2e; these two together are the
// argument that the shim is correct.
//
// The bias of this file is toward the PASS-THROUGH cases. Rewriting is the
// interesting behaviour but leaving a response alone is the safe one, and the
// failure that would matter on this surface is a response mangled by a shim
// that thought it recognised something.

const shimNow = "2026-08-17T09:00:00Z"

func shimClock() time.Time {
	t, _ := time.Parse(time.RFC3339, shimNow)
	return t
}

// tasksCapableRequest is a tools/call from a client advertising the extension.
func tasksCapableRequest() string {
	return `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{` +
		`"_meta":{"` + metaKeyClientCapabilities + `":{"extensions":{"` + tasksExtensionName + `":{}}}},` +
		`"name":"run_operation","arguments":{}}}`
}

// parkedResponse is the SDK's own shape for a parked dispatch, captured from
// the real wire (see cmd/relay's dump in the #375 work) and reproduced here.
func parkedResponse(taskID, taskExpiresAt string) string {
	return `{"jsonrpc":"2.0","id":2,"result":{` +
		`"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"relay","version":"0.1.0"}},` +
		`"content":[{"type":"text","text":"..."}],` +
		`"structuredContent":{"pending_approval":{` +
		`"status":"pending_approval","request_id":"req-1","plan_hash":"abc",` +
		`"task_id":"` + taskID + `","task_expires_at":"` + taskExpiresAt + `"},"results":[]},` +
		`"resultType":"complete"}}`
}

// serveShim runs one request through the shim wrapping a handler that returns
// the given response, and returns what the client would see.
func serveShim(t *testing.T, requestBody, responseBody string, opts ...func(http.ResponseWriter)) *httptest.ResponseRecorder {
	t.Helper()
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Assert the handler underneath still sees the original bytes: the shim
		// consumes the body to inspect it and must put it back intact.
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("inner handler read body: %v", err)
		}
		if string(got) != requestBody {
			t.Errorf("handler saw body %q, want the client's original %q", got, requestBody)
		}
		w.Header().Set("Content-Type", "application/json")
		for _, o := range opts {
			o(w)
		}
		_, _ = io.WriteString(w, responseBody)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(requestBody))
	withTaskShim(inner, shimClock).ServeHTTP(rec, req)
	return rec
}

// decodeTaskResult pulls the rewritten result out of a JSON-RPC response.
func decodeTaskResult(t *testing.T, body string) taskResultBody {
	t.Helper()
	var resp shimResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode response: %v; body = %s", err, body)
	}
	var out taskResultBody
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		t.Fatalf("decode result: %v; result = %s", err, resp.Result)
	}
	return out
}

// TestShimRewritesAParkedResultForACapableClient is the happy path.
func TestShimRewritesAParkedResultForACapableClient(t *testing.T) {
	expires := shimClock().Add(30 * time.Minute).Format(time.RFC3339)
	rec := serveShim(t, tasksCapableRequest(), parkedResponse("task-1", expires))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	got := decodeTaskResult(t, rec.Body.String())

	if got.ResultType != resultTypeTask {
		t.Errorf("resultType = %q, want %q", got.ResultType, resultTypeTask)
	}
	if got.TaskID != "task-1" {
		t.Errorf("taskId = %q, want task-1", got.TaskID)
	}
	if got.Status != "working" {
		t.Errorf("status = %q, want working", got.Status)
	}
	if got.PollIntervalMs != defaultPollIntervalMs {
		t.Errorf("pollIntervalMs = %d, want %d", got.PollIntervalMs, defaultPollIntervalMs)
	}
	if got.CreatedAt == "" || got.LastUpdatedAt == "" {
		t.Errorf("timestamps = %q/%q, want both set", got.CreatedAt, got.LastUpdatedAt)
	}
	// ttlMs comes from the HANDLE's expiry the Relay sent, not from a lifetime
	// the shim worked out for itself.
	if got.TTLMs <= 0 || got.TTLMs > (30*time.Minute).Milliseconds() {
		t.Errorf("ttlMs = %d, want a positive value no larger than the handle's remaining 30m", got.TTLMs)
	}

	// The JSON-RPC envelope is preserved: a rewritten result must still answer
	// the request it belongs to.
	var resp shimResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.JSONRPC != "2.0" || string(resp.ID) != "2" {
		t.Errorf("envelope = jsonrpc %q id %s, want 2.0 / 2", resp.JSONRPC, resp.ID)
	}
	if len(resp.Error) != 0 {
		t.Error("a rewritten result carried an error member")
	}
}

// TestShimPassesThroughWhenUncertain is the file's real subject. Each case is a
// response the shim must leave byte-identical, and each is a way a
// half-rewriting shim would corrupt a working surface.
func TestShimPassesThroughWhenUncertain(t *testing.T) {
	expires := shimClock().Add(time.Hour).Format(time.RFC3339)

	cases := map[string]struct{ request, response string }{
		"client did not advertise tasks": {
			request:  `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{},"name":"run_operation"}}`,
			response: parkedResponse("task-1", expires),
		},
		"client advertised other extensions only": {
			request: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"_meta":{"` +
				metaKeyClientCapabilities + `":{"extensions":{"acme/other":{}}}},"name":"run_operation"}}`,
			response: parkedResponse("task-1", expires),
		},
		"not a tools/call": {
			request:  `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"` + metaKeyClientCapabilities + `":{"extensions":{"` + tasksExtensionName + `":{}}}}}}`,
			response: parkedResponse("task-1", expires),
		},
		"tasks/get is not reshaped by the shim": {
			request:  `{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"_meta":{"` + metaKeyClientCapabilities + `":{"extensions":{"` + tasksExtensionName + `":{}}}},"taskId":"task-1"}}`,
			response: `{"jsonrpc":"2.0","id":1,"result":{"taskId":"task-1","status":"working"}}`,
		},
		"an ordinary completed run": {
			request:  tasksCapableRequest(),
			response: `{"jsonrpc":"2.0","id":2,"result":{"structuredContent":{"job_id":"job-1","results":[]},"resultType":"complete"}}`,
		},
		"a plan": {
			request:  tasksCapableRequest(),
			response: `{"jsonrpc":"2.0","id":2,"result":{"structuredContent":{"plan":{"verdicts":[]},"results":[]},"resultType":"complete"}}`,
		},
		"a JSON-RPC error": {
			request:  tasksCapableRequest(),
			response: `{"jsonrpc":"2.0","id":2,"error":{"code":-32602,"message":"bad params"}}`,
		},
		"a tool error": {
			request:  tasksCapableRequest(),
			response: `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"boom"}],"isError":true,"resultType":"complete"}}`,
		},
		"a park with no handle attached": {
			request:  tasksCapableRequest(),
			response: parkedResponse("", expires),
		},
		"a malformed response body": {
			request:  tasksCapableRequest(),
			response: `{"jsonrpc":"2.0","id":2,"result":{"structuredContent":`,
		},
		"a malformed request body": {
			request:  `{"jsonrpc":"2.0","id":2,"method":`,
			response: parkedResponse("task-1", expires),
		},
		"a JSON-RPC batch": {
			request:  `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}]`,
			response: parkedResponse("task-1", expires),
		},
		"a status field that is not pending_approval": {
			request: tasksCapableRequest(),
			response: `{"jsonrpc":"2.0","id":2,"result":{"structuredContent":{"pending_approval":` +
				`{"status":"something_else","task_id":"task-1"}}}}`,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rec := serveShim(t, tc.request, tc.response)
			if rec.Body.String() != tc.response {
				t.Errorf("the shim modified a response it should have left alone:\n got:  %s\n want: %s",
					rec.Body.String(), tc.response)
			}
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want 200", rec.Code)
			}
		})
	}
}

// TestShimIdentifiesByStatusNotByProse: matching on the summary text would make
// the wire contract depend on wording, and the summary is Relay-authored prose
// about a fleet action that will be reworded.
func TestShimIdentifiesByStatusNotByProse(t *testing.T) {
	// A completed run whose captured OUTPUT happens to contain the words a
	// prose-sniffing shim would look for.
	response := `{"jsonrpc":"2.0","id":2,"result":{"structuredContent":{"job_id":"job-1","results":` +
		`[{"node_id":"node-a","stdout":"pending_approval task_id request awaiting approval"}]},"resultType":"complete"}}`

	rec := serveShim(t, tasksCapableRequest(), response)
	if rec.Body.String() != response {
		t.Errorf("the shim rewrote a completed run because its OUTPUT mentioned approval:\n got: %s", rec.Body.String())
	}
}

// TestShimPassesThroughNonJSONAndNonOK: the SDK may answer with something that
// is not a JSON-RPC reply at all — an auth failure, a protocol-version refusal.
// None of it is the shim's business.
func TestShimPassesThroughNonJSONAndNonOK(t *testing.T) {
	t.Run("non-200", func(t *testing.T) {
		body := parkedResponse("task-1", shimClock().Add(time.Hour).Format(time.RFC3339))
		rec := serveShim(t, tasksCapableRequest(), body, func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusUnauthorized)
		})
		if rec.Code != http.StatusUnauthorized || rec.Body.String() != body {
			t.Errorf("status = %d, body = %s, want the response untouched", rec.Code, rec.Body)
		}
	})

	t.Run("non-JSON content type", func(t *testing.T) {
		const body = "not json at all"
		rec := serveShim(t, tasksCapableRequest(), body, func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/event-stream")
		})
		if rec.Body.String() != body {
			t.Errorf("body = %q, want it untouched", rec.Body)
		}
	})
}

// TestShimDoesNotBufferAnOversizedRequest: an RCE surface must not let a caller
// size the server's heap. An oversized body is passed through UNINSPECTED, and
// the handler underneath must still receive every byte.
func TestShimDoesNotBufferAnOversizedRequest(t *testing.T) {
	huge := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"pad":"` +
		strings.Repeat("x", maxShimBodyBytes+1) + `"}}`

	var seen int
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		seen = len(got)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(huge))
	withTaskShim(inner, shimClock).ServeHTTP(rec, req)

	if seen != len(huge) {
		t.Errorf("handler saw %d bytes, want all %d — the shim must give up on inspecting, never on serving", seen, len(huge))
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// TestShimPassesThroughAnOversizedResponse: the capture stops retaining beyond
// the cap, and an un-retained response cannot be a rewrite candidate.
func TestShimPassesThroughAnOversizedResponse(t *testing.T) {
	c := &shimCapture{header: http.Header{}}
	c.Header().Set("Content-Type", "application/json")
	if _, err := c.Write(make([]byte, maxShimBodyBytes+1)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !c.overflow {
		t.Fatal("an oversized response did not mark the capture overflowed")
	}
	if _, _, ok := rewriteParkedResult(c, shimClock()); ok {
		t.Error("an overflowed capture was treated as a rewrite candidate")
	}
}

// TestShimTTLNeverNegative: a handle whose expiry has already passed must not
// advertise a negative window a client would read as garbage.
func TestShimTTLNeverNegative(t *testing.T) {
	past := shimClock().Add(-time.Hour).Format(time.RFC3339)
	rec := serveShim(t, tasksCapableRequest(), parkedResponse("task-1", past))

	got := decodeTaskResult(t, rec.Body.String())
	if got.TTLMs != 0 {
		t.Errorf("ttlMs = %d for an already-expired handle, want 0", got.TTLMs)
	}

	t.Run("unparseable expiry", func(t *testing.T) {
		rec := serveShim(t, tasksCapableRequest(), parkedResponse("task-1", "not-a-timestamp"))
		got := decodeTaskResult(t, rec.Body.String())
		if got.TTLMs != 0 {
			t.Errorf("ttlMs = %d, want 0 when the expiry cannot be read", got.TTLMs)
		}
		if got.TaskID != "task-1" {
			t.Error("an unreadable expiry lost the task id; the handle is still valid")
		}
	})
}
