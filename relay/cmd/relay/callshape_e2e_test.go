// Package main: callshape_e2e_test.go proves, against the real composition
// root, that a malformed call is refused by the capability layer and rendered
// the same on both surfaces, with each refusal audited and no Job created.
package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// TestControlAPI_CallShapeRefusalRendersIdenticallyOnBothSurfaces drives a
// Native call with an unknown or missing argument name and a Raw Exec call with
// an empty or omitted argv through the Control API and the MCP tools. Each is a
// 400 "invalid operation request" on the Control API and a tool error on MCP
// carrying the same text, and every call leaves exactly one refusal record and
// no dispatch.
//
// Proves EX-64, EX-67.
func TestControlAPI_CallShapeRefusalRendersIdenticallyOnBothSurfaces(t *testing.T) {
	f := startRelay(t, WithControlPlane())
	// A Node must match, so the dispatch reaches the stage the call-shape
	// refusal is acted on (after no_nodes_matched).
	if _, err := f.Deps.registry.Upsert(linuxNode("node-callshape-1")); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	client := f.Client()
	session := relaytest.Connect(t, f.ControlBase, client)

	cases := []struct {
		name    string
		route   string
		tool    string
		body    map[string]any
		wantSub string
	}{
		{
			name: "unknown Native argument name", route: "/api/v1/operations", tool: "run_operation",
			body:    map[string]any{"selector": e2eFleetSelector, "operation": "service.restart", "args": map[string]string{"unitt": "nginx"}},
			wantSub: "unitt",
		},
		{
			name: "missing Native argument", route: "/api/v1/operations", tool: "run_operation",
			body:    map[string]any{"selector": e2eFleetSelector, "operation": "service.restart"},
			wantSub: "unit",
		},
		{
			name: "empty Raw Exec argv", route: "/api/v1/raw-exec", tool: "raw_exec",
			body:    map[string]any{"selector": e2eFleetSelector, "argv": []string{}},
			wantSub: "argv is empty",
		},
		{
			name: "omitted Raw Exec argv", route: "/api/v1/raw-exec", tool: "raw_exec",
			body:    map[string]any{"selector": e2eFleetSelector},
			wantSub: "argv is empty",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := controlAPIRequest(t, client, http.MethodPost, f.ControlBase+tc.route, f.Credential, tc.body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("Control API status = %d, want 400", resp.StatusCode)
			}
			var problem struct {
				Title  string `json:"title"`
				Detail string `json:"detail"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&problem); err != nil {
				t.Fatalf("decode problem: %v", err)
			}
			if problem.Title != "invalid operation request" {
				t.Errorf("title = %q, want %q", problem.Title, "invalid operation request")
			}
			if !strings.Contains(problem.Detail, "malformed call") || !strings.Contains(problem.Detail, tc.wantSub) {
				t.Errorf("detail = %q, want a malformed-call refusal naming %q", problem.Detail, tc.wantSub)
			}

			res := relaytest.CallTool(t, session, tc.tool, tc.body)
			if !res.IsError {
				t.Fatalf("MCP %s: IsError = false, want a tool error", tc.tool)
			}
			if got := mcpToolText(t, res); got != problem.Detail {
				t.Errorf("MCP text = %q, want the Control API detail %q", got, problem.Detail)
			}
		})
	}

	refusals := 0
	for _, rec := range auditList(t, f.Deps.audit) {
		switch rec.Kind {
		case audit.KindRefusal:
			refusals++
		case audit.KindDispatch, audit.KindDispatchIntent:
			t.Errorf("found a %s record for a malformed call: %+v", rec.Kind, rec)
		}
	}
	if want := 2 * len(cases); refusals != want {
		t.Errorf("refusal records = %d, want %d: one per call on each surface", refusals, want)
	}
}
