package mcp

import (
	"encoding/json"
	"testing"
)

// TestDescribeNodeOutput_JSONShapeIsFlattened is the golden-JSON assertion
// #161's plan requires: DescribeNodeOutput's anonymous, tagless embedding of
// NodeItem must still flatten NodeItem's fields directly into the top-level
// JSON object — never nest them under a "NodeItem" (or "node_item") key —
// now that both types are exported. Every field is set to a distinct,
// recognizable value so a field silently going missing (or nesting under an
// embed key) would show up as an exact-string mismatch, not just a "some key
// is missing" assertion.
func TestDescribeNodeOutput_JSONShapeIsFlattened(t *testing.T) {
	out := DescribeNodeOutput{
		NodeItem: NodeItem{
			NodeID:      "node-a",
			NodeLabels:  map[string]string{"role": "web"},
			RelayLabels: map[string]string{"quarantine": "on"},
			Facts: FactsOutput{
				Hostname:    "web-1",
				OS:          "linux",
				Kernel:      "6.1.0",
				Arch:        "amd64",
				IPAddresses: []string{"10.0.0.1"},
			},
			LastSeen:          "2024-01-01T00:00:00Z",
			PolicyFingerprint: "sha256:node-a-fingerprint",
			Revoked:           false,
		},
		EffectivePolicy: EffectivePolicyOutput{
			RawExecEnabled:    true,
			RawAllowPatterns:  []string{`^/usr/bin/systemctl restart .+$`},
			RawDenyPatterns:   []string{`.*rm -rf.*`},
			AllowedOperations: []string{"system.facts"},
			PolicyFingerprint: "sha256:node-a-fingerprint",
			Reported:          true,
		},
	}

	got, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	want := `{"node_id":"node-a","node_labels":{"role":"web"},"relay_labels":{"quarantine":"on"},` +
		`"facts":{"hostname":"web-1","os":"linux","kernel":"6.1.0","arch":"amd64","ip_addresses":["10.0.0.1"]},` +
		`"last_seen":"2024-01-01T00:00:00Z","policy_fingerprint":"sha256:node-a-fingerprint","revoked":false,` +
		`"effective_policy":{"raw_exec_enabled":true,"raw_allow_patterns":["^/usr/bin/systemctl restart .+$"],` +
		`"raw_deny_patterns":[".*rm -rf.*"],"allowed_operations":["system.facts"],` +
		`"policy_fingerprint":"sha256:node-a-fingerprint","reported":true}}`

	if string(got) != want {
		t.Errorf("json.Marshal(DescribeNodeOutput) =\n%s\nwant\n%s\n(NodeItem's fields must flatten into the "+
			"top level — describe_node's wire shape must stay byte-identical now that DescribeNodeOutput/NodeItem "+
			"are exported)", got, want)
	}
}
