package mcp_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	schema "github.com/google/jsonschema-go/jsonschema"
)

// TestMCP_ExecutionToolsInputSchemaConstraints is the schema half of the
// #120 legibility floor (#189): raw_exec/run_operation's advertised
// InputSchema must be STRICTER than the reflect-inferred defaults on the two
// fields the reflector gets wrong for this RCE surface — raw_exec.argv must
// never advertise a "null" variant (argv is required) and timeout_seconds
// must advertise the real [0, 86400] bound (ADR-0012's documented default),
// not the int32 min/max a bare int32 field infers to. InputSchema arrives
// over the transport as map[string]any (json.RawMessage decoded generically
// by the SDK), so it is re-marshalled into a *jsonschema.Schema here for a
// clean assertion rather than poking at the map directly.
func TestMCP_ExecutionToolsInputSchemaConstraints(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	schemas := make(map[string]*schema.Schema, len(res.Tools))
	for _, tool := range res.Tools {
		s := toolSchema(t, tool.Name, tool.InputSchema)
		schemas[tool.Name] = s
	}

	rawExec, ok := schemas["raw_exec"]
	if !ok {
		t.Fatalf("no InputSchema found for tool %q", "raw_exec")
	}
	argv, ok := rawExec.Properties["argv"]
	if !ok {
		t.Fatalf("raw_exec InputSchema has no %q property", "argv")
	}
	if argv.Type != "array" {
		t.Errorf("raw_exec argv Type = %q, want %q", argv.Type, "array")
	}
	if len(argv.Types) != 0 {
		t.Errorf("raw_exec argv Types = %v, want none (no null variant — argv is required)", argv.Types)
	}

	for _, toolName := range []string{"raw_exec", "run_operation"} {
		s, ok := schemas[toolName]
		if !ok {
			t.Fatalf("no InputSchema found for tool %q", toolName)
		}
		timeout, ok := s.Properties["timeout_seconds"]
		if !ok {
			t.Fatalf("%s InputSchema has no %q property", toolName, "timeout_seconds")
		}
		if timeout.Minimum == nil || *timeout.Minimum != 0 {
			t.Errorf("%s timeout_seconds Minimum = %v, want 0", toolName, timeout.Minimum)
		}
		if timeout.Maximum == nil || *timeout.Maximum != 86400 {
			t.Errorf("%s timeout_seconds Maximum = %v, want 86400", toolName, timeout.Maximum)
		}

		wait, ok := s.Properties["wait_seconds"]
		if !ok {
			t.Fatalf("%s InputSchema has no %q property", toolName, "wait_seconds")
		}
		if wait.Minimum == nil || *wait.Minimum != 0 {
			t.Errorf("%s wait_seconds Minimum = %v, want 0", toolName, wait.Minimum)
		}
		if wait.Maximum == nil || *wait.Maximum != 300 {
			t.Errorf("%s wait_seconds Maximum = %v, want 300", toolName, wait.Maximum)
		}

		key, ok := s.Properties["idempotency_key"]
		if !ok {
			t.Fatalf("%s InputSchema has no %q property", toolName, "idempotency_key")
		}
		if key.MaxLength == nil || *key.MaxLength != 128 {
			t.Errorf("%s idempotency_key MaxLength = %v, want 128", toolName, key.MaxLength)
		}
	}
}

// TestMCP_ResultShapeSemanticsAdvertisedInOutputSchema is #207/#253's
// documented-contract floor: the presence/absence semantics the result
// shapes now rely on — exit_code omitted when no process ran, job_id omitted
// when no Job was created, allowed_args always an array and never null —
// must be stated in the tools' advertised OutputSchema, so an MCP client can
// learn them from the schema text instead of by trial-and-error (the exact
// probing behavior ADR-0001/0003's legibility posture is meant to prevent).
// Asserted as substrings of the whole marshalled schema document, so the
// test stays robust to $ref/$defs layout.
func TestMCP_ResultShapeSemanticsAdvertisedInOutputSchema(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	outputSchemas := make(map[string]string, len(res.Tools))
	for _, tool := range res.Tools {
		if tool.OutputSchema == nil {
			continue
		}
		raw, err := json.Marshal(tool.OutputSchema)
		if err != nil {
			t.Fatalf("marshal %s OutputSchema: %v", tool.Name, err)
		}
		outputSchemas[tool.Name] = string(raw)
	}

	tests := []struct {
		tool        string
		wantPhrases []string
	}{
		{"run_operation", []string{
			"exit_code",
			"Present only when a process actually ran and exited with a status",
			"Present only when a Job was created",
			"an absent job_id always means nothing was dispatched",
			"running while any Task is unresolved",
			"true when this call dispatched nothing",
		}},
		{"raw_exec", []string{
			"exit_code",
			"Present only when a process actually ran and exited with a status",
			"Present only when a Job was created",
			"an absent job_id always means nothing was dispatched",
			"running while any Task is unresolved",
			"true when this call dispatched nothing",
		}},
		{"get_job", []string{
			"exit_code",
			"Present only when a process actually ran and exited with a status",
			"running while any Task is unresolved",
		}},
		{"describe_node", []string{
			"allowed_args",
			"Always an array, never null",
			"an empty array means the Operation is allowed with zero arguments only",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			doc, ok := outputSchemas[tt.tool]
			if !ok {
				t.Fatalf("tool %q advertises no OutputSchema", tt.tool)
			}
			for _, phrase := range tt.wantPhrases {
				if !strings.Contains(doc, phrase) {
					t.Errorf("%s OutputSchema does not contain %q — the documented contract must state the "+
						"presence/absence semantics the emitted shape relies on. Schema: %s", tt.tool, phrase, doc)
				}
			}
		})
	}
}

// toolSchema re-marshals a Tool.InputSchema (a map[string]any as received
// over the transport) into a *jsonschema.Schema for structured assertions.
func toolSchema(t *testing.T, toolName string, inputSchema any) *schema.Schema {
	t.Helper()
	raw, err := json.Marshal(inputSchema)
	if err != nil {
		t.Fatalf("marshal %s InputSchema: %v", toolName, err)
	}
	var s schema.Schema
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("unmarshal %s InputSchema: %v", toolName, err)
	}
	return &s
}
