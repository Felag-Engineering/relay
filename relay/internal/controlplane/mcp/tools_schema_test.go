package mcp_test

import (
	"context"
	"encoding/json"
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
