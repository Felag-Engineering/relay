package mcp_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
)

// fieldFlagger reports whether a struct field breaches the property under
// test; the returned string is the reason, "" meaning clean.
type fieldFlagger func(reflect.StructField) string

// walkFields visits every field reachable from t — recursing into struct
// fields and following pointer, slice, array and map element types — and
// returns the reasons flag gave, plus the number of fields visited.
//
// The visit count is what makes an absence assertion honest: a walker that
// silently failed to descend would otherwise report a clean sweep over
// nothing at all.
func walkFields(t reflect.Type, flag fieldFlagger) (flags []string, visited int) {
	seen := map[reflect.Type]bool{}
	var walk func(reflect.Type)
	walk = func(rt reflect.Type) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice ||
			rt.Kind() == reflect.Array || rt.Kind() == reflect.Map {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || seen[rt] {
			return
		}
		seen[rt] = true
		for i := range rt.NumField() {
			f := rt.Field(i)
			visited++
			if reason := flag(f); reason != "" {
				flags = append(flags, reason)
			}
			walk(f.Type)
		}
	}
	walk(t)
	return flags, visited
}

// jsonTagOf returns a field's json name (the part before the first comma),
// falling back to the Go field name when the tag is absent.
func jsonTagOf(f reflect.StructField) string {
	tag, ok := f.Tag.Lookup("json")
	if !ok {
		return f.Name
	}
	if i := strings.IndexByte(tag, ','); i >= 0 {
		tag = tag[:i]
	}
	if tag == "" {
		return f.Name
	}
	return tag
}

// flagBodyField is QRY-12's structural predicate: no field of
// list_operations' result may be, or contain, a template body.
func flagBodyField(f reflect.StructField) string {
	if name := strings.ToLower(jsonTagOf(f)); strings.Contains(name, "body") {
		return "field " + f.Name + " renders as JSON key " + jsonTagOf(f)
	}
	return ""
}

// TestMCP_ListOperations_NeverCarriesATemplateBody proves QRY-12's body half
// (docs/specs/query.md): with a Node ID, list_operations adds that Node's
// Template Operations — names, risk classes and typed slots — and never a
// template body. A body never crosses the wire at all (ADR-0021); only the
// daemon renders one.
//
// The same "body"-absent assertion TestMCP_DescribeNode makes, on the surface
// QRY-12 actually names. Each JSON leg is armed first: without asserting that
// Operations were really rendered into the response, an absence over a
// response that listed nothing would pass for the wrong reason.
//
// Residual: both legs prove rendering and shape on this surface. The
// structural reason a body can never appear — nodevocab.Template has no body
// field and /proto's template descriptor carries none — is asserted nowhere
// in this change, and nothing in the tree pins that proto field set.
func TestMCP_ListOperations_NeverCarriesATemplateBody(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	t.Run("with a node_id, listing that Node's templates", func(t *testing.T) {
		res := callTool(t, session, "list_operations", map[string]any{"node_id": ts.nodeA})

		// Armed: the absence below means nothing unless templates were
		// actually rendered into this response.
		var out mcp.ListOperationsOutput
		decodeResult(t, res, &out)
		if !out.TemplatesReported {
			t.Fatal("TemplatesReported = false — node A's template snapshot did not reach this response, " +
				"so an absent body proves nothing")
		}
		var templates int
		for _, op := range out.Operations {
			if op.Source == "template" {
				templates++
			}
		}
		if templates == 0 {
			t.Fatal("no Operation with source \"template\" in the response — an absent body proves nothing")
		}

		if text := resultText(t, res); strings.Contains(text, `"body"`) {
			t.Errorf("list_operations JSON = %s, must never carry a template body", text)
		}
	})

	t.Run("without a node_id, natives only", func(t *testing.T) {
		res := callTool(t, session, "list_operations", nil)

		// Armed the same way: an empty operations array would satisfy the
		// absence below for the wrong reason.
		var out mcp.ListOperationsOutput
		decodeResult(t, res, &out)
		var natives int
		for _, op := range out.Operations {
			if op.Source == "native" {
				natives++
			}
		}
		if natives == 0 {
			t.Fatalf("no Operation with source \"native\" in the %d-entry fleet-wide response — "+
				"an absent body proves nothing", len(out.Operations))
		}

		if text := resultText(t, res); strings.Contains(text, `"body"`) {
			t.Errorf("list_operations JSON = %s, must never carry a template body", text)
		}
	})

	t.Run("structurally, no field of the result can be a body", func(t *testing.T) {
		// Armed: a type that deliberately violates the property, one level
		// down a slice so the recursion itself is exercised.
		type bodyBearingControl struct {
			Name string `json:"name"`
			Body string `json:"body"`
		}
		type bodyBearingWrapper struct {
			Items []bodyBearingControl `json:"items"`
		}
		controlFlags, controlVisited := walkFields(reflect.TypeOf(bodyBearingWrapper{}), flagBodyField)
		if len(controlFlags) == 0 {
			t.Fatal("the walker did not flag the deliberately body-bearing control type — it cannot fail and proves nothing")
		}
		if controlVisited == 0 {
			t.Fatal("the walker visited no field of the control type — it did not descend")
		}

		flags, visited := walkFields(reflect.TypeOf(mcp.ListOperationsOutput{}), flagBodyField)
		if visited == 0 {
			t.Fatal("the walker visited no field of ListOperationsOutput — a clean sweep over nothing")
		}
		if len(flags) != 0 {
			t.Errorf("ListOperationsOutput can carry a template body: %v", flags)
		}
	})
}

// flagPeerCountField is QRY-5's last-sentence predicate: no field of
// describe_node's result may report a fingerprint-peer count.
func flagPeerCountField(f reflect.StructField) string {
	for _, token := range []string{"peer", "shared"} {
		if strings.Contains(strings.ToLower(f.Name), token) ||
			strings.Contains(strings.ToLower(jsonTagOf(f)), token) {
			return "field " + f.Name + " renders as JSON key " + jsonTagOf(f)
		}
	}
	return ""
}

// TestMCP_DescribeNode_ReportsNoFingerprintPeerCounts pins QRY-5's last
// sentence (docs/specs/query.md): the capability read lane computes the
// fingerprint-peer counts and the Console renders them, but MCP describe_node
// does not report them today.
//
// Residual: this is a statement about TODAY. QRY-5 names the MCP half as
// *Future work*, so read this as pinning the current gap, not as forbidding
// the field forever — the change that adds it replaces this test rather than
// working around it.
func TestMCP_DescribeNode_ReportsNoFingerprintPeerCounts(t *testing.T) {
	ts := newTestServer(t)
	session := ts.connect(t)

	t.Run("the rendered JSON names no peer count", func(t *testing.T) {
		res := callTool(t, session, "describe_node", map[string]any{"node_id": ts.nodeA})
		text := resultText(t, res)
		for _, key := range []string{`"policy_peers"`, `"template_peers"`} {
			if strings.Contains(text, key) {
				t.Errorf("describe_node JSON = %s, carries %s — QRY-5 says MCP does not report the peer counts today", text, key)
			}
		}
	})

	t.Run("structurally, no field of the result is a peer count", func(t *testing.T) {
		// Armed, one level down a pointer so the recursion is exercised.
		type peerCountControl struct {
			PolicyPeers int `json:"policy_peers"`
		}
		type peerCountWrapper struct {
			Counts *peerCountControl `json:"counts"`
		}
		controlFlags, controlVisited := walkFields(reflect.TypeOf(peerCountWrapper{}), flagPeerCountField)
		if len(controlFlags) == 0 {
			t.Fatal("the walker did not flag the deliberately peer-count-bearing control type — it cannot fail and proves nothing")
		}
		if controlVisited == 0 {
			t.Fatal("the walker visited no field of the control type — it did not descend")
		}

		flags, visited := walkFields(reflect.TypeOf(mcp.DescribeNodeOutput{}), flagPeerCountField)
		if visited == 0 {
			t.Fatal("the walker visited no field of DescribeNodeOutput — a clean sweep over nothing")
		}
		if len(flags) != 0 {
			t.Errorf("DescribeNodeOutput reports a fingerprint-peer count: %v", flags)
		}
	})
}
