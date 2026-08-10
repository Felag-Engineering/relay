package mcp

import (
	"encoding/json"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/policyview"
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
			LastSeen:               "2024-01-01T00:00:00Z",
			PolicyFingerprint:      "sha256:node-a-fingerprint",
			TemplateSetFingerprint: "sha256:node-a-template-set",
			Revoked:                false,
			Outdated:               true,
		},
		EffectivePolicy: EffectivePolicyOutput{
			RawExecEnabled:    true,
			RawAllowPatterns:  []string{`^/usr/bin/systemctl restart .+$`},
			RawDenyPatterns:   []string{`.*rm -rf.*`},
			AllowedOperations: []string{"system.facts"},
			PolicyFingerprint: "sha256:node-a-fingerprint",
			Reported:          true,
			OperationRules: []OperationRuleOutput{
				{Name: "service.restart", AllowedArgs: [][]string{{"nginx", "php-fpm"}}},
			},
			DenyRules: []DenyRuleOutput{
				{Name: "file.read", Args: [][]string{{"/etc/shadow"}}},
			},
		},
		TemplateVocabulary: TemplateVocabularyOutput{
			Fingerprint: "sha256:node-a-template-set",
			Reported:    true,
			Templates: []TemplateOperationOutput{
				{
					Name:      "log.tail",
					RiskClass: "read",
					Slots: []TemplateSlotOutput{
						{Name: "lines", Type: "integer", EnumValues: []string{}},
					},
				},
			},
		},
	}

	got, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	want := `{"node_id":"node-a","node_labels":{"role":"web"},"relay_labels":{"quarantine":"on"},` +
		`"facts":{"hostname":"web-1","os":"linux","kernel":"6.1.0","arch":"amd64","ip_addresses":["10.0.0.1"]},` +
		`"last_seen":"2024-01-01T00:00:00Z","policy_fingerprint":"sha256:node-a-fingerprint",` +
		`"template_set_fingerprint":"sha256:node-a-template-set","revoked":false,` +
		`"outdated":true,` +
		`"effective_policy":{"raw_exec_enabled":true,"raw_allow_patterns":["^/usr/bin/systemctl restart .+$"],` +
		`"raw_deny_patterns":[".*rm -rf.*"],"allowed_operations":["system.facts"],` +
		`"policy_fingerprint":"sha256:node-a-fingerprint","reported":true,` +
		`"operation_rules":[{"name":"service.restart","allowed_args":[["nginx","php-fpm"]]}],` +
		`"deny_rules":[{"name":"file.read","args":[["/etc/shadow"]]}]},` +
		`"template_vocabulary":{"template_set_fingerprint":"sha256:node-a-template-set","reported":true,` +
		`"templates":[{"name":"log.tail","risk_class":"read",` +
		`"slots":[{"name":"lines","type":"integer","enum_values":[]}]}]}}`

	if string(got) != want {
		t.Errorf("json.Marshal(DescribeNodeOutput) =\n%s\nwant\n%s\n(NodeItem's fields must flatten into the "+
			"top level — describe_node's wire shape must stay byte-identical now that DescribeNodeOutput/NodeItem "+
			"are exported)", got, want)
	}
}

// TestOperationRuleOutputs_ArgSetsNeverNull is #207/#253 item 3's golden-JSON
// assertion: describe_node's operation_rules/deny_rules — and every rule's
// allowed_args/args — render as JSON arrays, never null, whatever the
// policyview snapshot carried. A zero-arg rule arrives from the daemon with
// nil arg sets (proto empty repeated field) and means exactly "allowed (or
// denied) with zero arguments", the same thing an explicit [] means — so a
// consumer must never have to branch on null vs [], and "no constraint" is
// only ever spelled as the explicit per-position "*" wildcard.
func TestOperationRuleOutputs_ArgSetsNeverNull(t *testing.T) {
	opRules := operationRuleOutputsFromSnapshot([]policyview.OperationRule{
		{Name: "service.restart", AllowedArgs: [][]string{{"nginx", "php-fpm"}}},
		{Name: "system.facts", AllowedArgs: nil}, // zero-arg Operation: nil from the wire
		{Name: "file.read", AllowedArgs: [][]string{{"*"}}},
	})
	got, err := json.Marshal(opRules)
	if err != nil {
		t.Fatalf("json.Marshal(operation rules): %v", err)
	}
	want := `[{"name":"service.restart","allowed_args":[["nginx","php-fpm"]]},` +
		`{"name":"system.facts","allowed_args":[]},` +
		`{"name":"file.read","allowed_args":[["*"]]}]`
	if string(got) != want {
		t.Errorf("operation_rules JSON = %s, want %s (allowed_args must always be an array, never null)", got, want)
	}

	denyRules := denyRuleOutputsFromSnapshot([]policyview.DenyRule{
		{Name: "service.restart", Args: nil}, // whole-Operation deny: nil from the wire
	})
	got, err = json.Marshal(denyRules)
	if err != nil {
		t.Fatalf("json.Marshal(deny rules): %v", err)
	}
	want = `[{"name":"service.restart","args":[]}]`
	if string(got) != want {
		t.Errorf("deny_rules JSON = %s, want %s (args must always be an array, never null)", got, want)
	}

	// A snapshot with no rule blocks at all still renders arrays, never null.
	if b, _ := json.Marshal(operationRuleOutputsFromSnapshot(nil)); string(b) != `[]` {
		t.Errorf("operation_rules (no blocks) JSON = %s, want []", b)
	}
	if b, _ := json.Marshal(denyRuleOutputsFromSnapshot(nil)); string(b) != `[]` {
		t.Errorf("deny_rules (no blocks) JSON = %s, want []", b)
	}
}
