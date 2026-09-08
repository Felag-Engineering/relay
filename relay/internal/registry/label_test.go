package registry

import "testing"

// TestWellFormedNodeLabel is named row-by-row for the mutation that turns it
// red (see the plan's TEST STRATEGY): each case pins one hazard from
// WellFormedNodeLabel's doc, not just "valid" vs "invalid" in the abstract.
func TestWellFormedNodeLabel(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		want  bool
	}{
		{"plain key and value accepted", "role", "web", true},
		{"empty value accepted — a bare RELAY_NODE_LABELS marker", "role", "", true},
		{"empty key rejected", "", "web", false},
		{"the measured payload: comma-injected second term rejected", "role", "web, relay:quarantine=on", false},
		// Isolated single-hazard cases below: the measured payload above is a
		// realistic COMPOUND value (comma, space, colon and equals all at
		// once), so a mutation that widens just ONE of those bytes would NOT
		// turn it red by itself — the other three hazards in the same string
		// would still reject it. Each case below carries exactly one hazard
		// byte and nothing else, so it goes red on the ONE mutation that
		// admits it and no other.
		{"comma alone in value rejected (isolated)", "role", "a,b", false},
		{"space alone in value rejected (isolated)", "role", "web server", false},
		{"tab in value rejected (isolated)", "role", "web\t", false},
		{"colon alone in value rejected (isolated)", "role", "a:b", false},
		{"colon alone in key rejected (isolated)", "relay:quarantine", "on", false},
		{"equals alone in value rejected (isolated)", "role", "a=b", false},
		{"equals in key rejected — the key-side split hazard (isolated)", "role=x", "y", false},
		{"braille pattern blank (U+2800) rejected", "role", "web⠀", false},
		{"hangul filler (U+3164) rejected", "role", "webㅤ", false},
		{"zero width space (U+200B) rejected", "role", "web\u200b", false},
		{"non-ASCII letter rejected", "role", "süd", false},
		{"newline in value rejected", "role", "web\n", false},
		{"dot, underscore and hyphen accepted", "site-name.a_b", "us-east-1.a_b", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := WellFormedNodeLabel(tc.key, tc.value)
			if got != tc.want {
				t.Errorf("WellFormedNodeLabel(%q, %q) = %v, want %v", tc.key, tc.value, got, tc.want)
			}
		})
	}
}
