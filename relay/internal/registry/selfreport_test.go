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

func TestWellFormedNodeLabel(t *testing.T) {
	tests := []struct {
		name       string
		key, value string
		want       bool
	}{
		{"short", "role", "web", true},
		{"key and value at the bounds", strings.Repeat("k", MaxLabelKeyLen), strings.Repeat("v", MaxLabelValueLen), true},
		{"key over", strings.Repeat("k", MaxLabelKeyLen+1), "web", false},
		{"value over", "role", strings.Repeat("v", MaxLabelValueLen+1), false},
		{"alphabet still applies", "role", "web, relay:quarantine=on", false},
		{"empty key", "", "web", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WellFormedNodeLabel(tt.key, tt.value); got != tt.want {
				t.Errorf("WellFormedNodeLabel(%.20q, %.20q) = %v, want %v", tt.key, tt.value, got, tt.want)
			}
		})
	}
}

// TestDeclineMalformedSelfReport pins the one rule the ingress and the
// read-back share: a field that fails is omitted and named, in a fixed order,
// and a well-formed report comes back untouched with nothing named.
func TestDeclineMalformedSelfReport(t *testing.T) {
	good := SelfReport{
		Facts: Facts{Hostname: "web-01", OS: "linux", Kernel: "6.1.0", Arch: "x86_64",
			IPAddresses: []string{"10.0.0.1", "fd00::1"}},
		PolicyFingerprint:      strings.Repeat("a", 64),
		TemplateSetFingerprint: TemplateUnloadable,
		DaemonVersion:          "1.4.2",
	}
	got, omitted := DeclineMalformedSelfReport(good)
	if len(omitted) != 0 || got.Facts.Hostname != good.Facts.Hostname || got.PolicyFingerprint != good.PolicyFingerprint ||
		got.TemplateSetFingerprint != good.TemplateSetFingerprint || got.DaemonVersion != good.DaemonVersion ||
		strings.Join(got.Facts.IPAddresses, ",") != "10.0.0.1,fd00::1" {
		t.Errorf("well-formed report: got %+v, omitted %v; want it unchanged, nothing omitted", got, omitted)
	}

	bad := SelfReport{
		Facts: Facts{Hostname: "web\u202e01", OS: "linux os", Kernel: strings.Repeat("k", 254), Arch: "x86_64",
			IPAddresses: []string{"10.0.0.1", "fe80::1%eth0"}},
		PolicyFingerprint:      strings.ToUpper(strings.Repeat("a", 64)),
		TemplateSetFingerprint: "tmpl-1",
		DaemonVersion:          "not-semver",
	}
	got, omitted = DeclineMalformedSelfReport(bad)
	want := []string{FieldHostname, FieldOS, FieldKernel, FieldIPAddresses,
		FieldPolicyFingerprint, FieldTemplateSetFingerprint, FieldDaemonVersion}
	if strings.Join(omitted, ",") != strings.Join(want, ",") {
		t.Errorf("omitted = %v, want %v", omitted, want)
	}
	if got.Facts.Hostname != "" || got.Facts.OS != "" || got.Facts.Kernel != "" || got.Facts.Arch != "x86_64" ||
		strings.Join(got.Facts.IPAddresses, ",") != "10.0.0.1" ||
		got.PolicyFingerprint != "" || got.TemplateSetFingerprint != "" || got.DaemonVersion != "" {
		t.Errorf("malformed report: got %.200v; want each failing field omitted and arch kept", got)
	}

	if got, _ := DeclineMalformedSelfReport(SelfReport{Facts: Facts{IPAddresses: []string{"x"}}}); got.Facts.IPAddresses != nil {
		t.Errorf("all-dropped IPAddresses = %#v, want nil", got.Facts.IPAddresses)
	}
	if got, _ := DeclineMalformedSelfReport(SelfReport{Facts: Facts{IPAddresses: []string{}}}); got.Facts.IPAddresses == nil {
		t.Error("an empty, non-nil IPAddresses came back nil; the nil-versus-empty distinction must hold")
	}
}

// TestInMemory_DeclinesOverLongNodeLabelOnRead: the fake declines a stored
// node: Label over the length bounds exactly as the store's read-back does.
func TestInMemory_DeclinesOverLongNodeLabelOnRead(t *testing.T) {
	r := NewInMemory()
	atKey := strings.Repeat("k", MaxLabelKeyLen)
	n, err := r.Upsert(Report{NodeID: "node-a"}.WithNodeLabels(map[string]string{
		atKey:                                 "web",
		strings.Repeat("k", MaxLabelKeyLen+1): "web",
		"role":                                strings.Repeat("v", MaxLabelValueLen+1),
	}))
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	got, _ := r.Get("node-a")
	for what, node := range map[string]Node{"Upsert": n, "Get": got, "List": r.List()[0]} {
		if len(node.NodeLabels) != 1 || node.NodeLabels[atKey] != "web" {
			t.Errorf("%s NodeLabels has %d entries, want only the one within the bounds", what, len(node.NodeLabels))
		}
	}
}
