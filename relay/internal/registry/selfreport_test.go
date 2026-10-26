package registry

import (
	"strings"
	"testing"
)

func TestWellFormedFingerprint(t *testing.T) {
	tests := []struct {
		name string
		fp   string
		want bool
	}{
		{"64 a", strings.Repeat("a", 64), true},
		{"all hex digits", strings.Repeat("0123456789abcdef", 4), true},
		{"empty", "", false},
		{"63 hex", strings.Repeat("a", 63), false},
		{"65 hex", strings.Repeat("a", 65), false},
		{"uppercase", strings.Repeat("A", 64), false},
		{"sha256 prefix", "sha256:" + strings.Repeat("a", 64), false},
		{"U+202E in 64 bytes", "abcdefghij\u202e" + strings.Repeat("a", 51), false},
		{"1 MiB", strings.Repeat("a", 1<<20), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WellFormedFingerprint(tt.fp); got != tt.want {
				t.Errorf("WellFormedFingerprint(%.20q) = %v, want %v", tt.fp, got, tt.want)
			}
		})
	}
}

func TestWellFormedSelfReportedText(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		{"empty", "", true},
		{"hostname", "web-01.prod.example.com", true},
		{"kernel", "6.6.0+", true},
		{"253 bytes", strings.Repeat("a", 253), true},
		{"254 bytes", strings.Repeat("a", 254), false},
		{"space", "a b", false},
		{"U+202E", "web\u202e01", false},
		{"NUL", "a\x00b", false},
		{"DEL", "a\x7fb", false},
		{"tab", "\t", false},
		{"1 MiB", strings.Repeat("a", 1<<20), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WellFormedSelfReportedText(tt.s); got != tt.want {
				t.Errorf("WellFormedSelfReportedText(%.20q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

// TestLabelBoundsMatchTagBounds pins the selectors-and-labels Limits so the
// node: and tag: bounds cannot silently diverge from each other.
func TestLabelBoundsMatchTagBounds(t *testing.T) {
	if MaxTagKeyLen != MaxLabelKeyLen || MaxLabelKeyLen != 63 {
		t.Errorf("key bounds: tag %d, label %d, want both 63", MaxTagKeyLen, MaxLabelKeyLen)
	}
	if MaxTagValueLen != MaxLabelValueLen || MaxLabelValueLen != 255 {
		t.Errorf("value bounds: tag %d, label %d, want both 255", MaxTagValueLen, MaxLabelValueLen)
	}
}
