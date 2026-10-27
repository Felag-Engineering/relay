package protoconv_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/protoconv"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
)

func TestFactsFromProto(t *testing.T) {
	t.Run("nil input returns zero-value Facts", func(t *testing.T) {
		got := protoconv.FactsFromProto(nil)
		if got.Hostname != "" || got.OS != "" || got.Kernel != "" || got.Arch != "" || len(got.IPAddresses) != 0 {
			t.Errorf("expected zero-value Facts, got %+v", got)
		}
	})

	t.Run("populated input maps all fields", func(t *testing.T) {
		pf := &relayv1.Facts{
			Hostname:    "host1",
			Os:          "linux",
			Kernel:      "6.1.0",
			Arch:        "amd64",
			IpAddresses: []string{"10.0.0.1", "192.168.1.2"},
		}
		got := protoconv.FactsFromProto(pf)
		if got.Hostname != "host1" {
			t.Errorf("Hostname: got %q, want %q", got.Hostname, "host1")
		}
		if got.OS != "linux" {
			t.Errorf("OS: got %q, want %q", got.OS, "linux")
		}
		if got.Kernel != "6.1.0" {
			t.Errorf("Kernel: got %q, want %q", got.Kernel, "6.1.0")
		}
		if got.Arch != "amd64" {
			t.Errorf("Arch: got %q, want %q", got.Arch, "amd64")
		}
		if len(got.IPAddresses) != 2 || got.IPAddresses[0] != "10.0.0.1" || got.IPAddresses[1] != "192.168.1.2" {
			t.Errorf("IPAddresses: got %v, want [10.0.0.1 192.168.1.2]", got.IPAddresses)
		}
	})

	t.Run("IPAddresses is an independent copy", func(t *testing.T) {
		pf := &relayv1.Facts{
			IpAddresses: []string{"10.0.0.1"},
		}
		got := protoconv.FactsFromProto(pf)
		// Mutating the returned slice must not affect the source proto slice.
		got.IPAddresses[0] = "mutated"
		if pf.IpAddresses[0] != "10.0.0.1" {
			t.Errorf("mutating returned IPAddresses affected proto slice: got %q", pf.IpAddresses[0])
		}
	})

	t.Run("empty IPAddresses", func(t *testing.T) {
		pf := &relayv1.Facts{Hostname: "h"}
		got := protoconv.FactsFromProto(pf)
		if got.IPAddresses != nil {
			t.Errorf("expected nil IPAddresses, got %#v", got.IPAddresses)
		}
	})

	// #1068: every text field is bounded at the ingress; a value that fails is
	// not recorded, never rewritten.
	t.Run("a 254-byte hostname is not recorded, a 253-byte one is", func(t *testing.T) {
		if got := protoconv.FactsFromProto(&relayv1.Facts{Hostname: strings.Repeat("a", 254)}); got.Hostname != "" {
			t.Errorf("254-byte hostname recorded as %d bytes", len(got.Hostname))
		}
		long := strings.Repeat("a", 253)
		if got := protoconv.FactsFromProto(&relayv1.Facts{Hostname: long}); got.Hostname != long {
			t.Errorf("253-byte hostname not kept")
		}
	})

	t.Run("a hostname carrying U+202E is not recorded", func(t *testing.T) {
		if got := protoconv.FactsFromProto(&relayv1.Facts{Hostname: "web\u202e01"}); got.Hostname != "" {
			t.Errorf("Hostname = %q, want not recorded", got.Hostname)
		}
	})

	t.Run("a kernel release with a plus is kept", func(t *testing.T) {
		if got := protoconv.FactsFromProto(&relayv1.Facts{Kernel: "6.6.0+"}); got.Kernel != "6.6.0+" {
			t.Errorf("Kernel = %q, want 6.6.0+", got.Kernel)
		}
	})

	t.Run("addresses that are not plain IPs are dropped, order kept", func(t *testing.T) {
		got := protoconv.FactsFromProto(&relayv1.Facts{
			IpAddresses: []string{"10.0.0.1", "not-an-ip", "fe80::1%eth0", "fe80::1"},
		})
		want := []string{"10.0.0.1", "fe80::1"}
		if !slices.Equal(got.IPAddresses, want) {
			t.Errorf("IPAddresses = %v, want %v", got.IPAddresses, want)
		}
	})

	t.Run("all addresses dropped yields nil, not an empty slice", func(t *testing.T) {
		got := protoconv.FactsFromProto(&relayv1.Facts{IpAddresses: []string{"not-an-ip"}})
		if got.IPAddresses != nil {
			t.Errorf("IPAddresses = %#v, want nil", got.IPAddresses)
		}
	})
}

// FactsFromProtoWithRefusals names what it refused from the Field* closed set
// and never echoes a wire value (#1068).
func TestFactsFromProtoWithRefusals(t *testing.T) {
	t.Run("nil and well-formed refuse nothing", func(t *testing.T) {
		if _, refused := protoconv.FactsFromProtoWithRefusals(nil); len(refused) != 0 {
			t.Errorf("nil refused %v", refused)
		}
		_, refused := protoconv.FactsFromProtoWithRefusals(&relayv1.Facts{Hostname: "h", IpAddresses: []string{"10.0.0.1"}})
		if len(refused) != 0 {
			t.Errorf("well-formed Facts refused %v", refused)
		}
	})

	t.Run("each refused field is named, the value never", func(t *testing.T) {
		hostile := "web\u202e01"
		facts, refused := protoconv.FactsFromProtoWithRefusals(&relayv1.Facts{
			Hostname: hostile, Os: "linux", IpAddresses: []string{"10.0.0.1", "fe80::1%eth0"},
		})
		want := []string{protoconv.FieldHostname, protoconv.FieldIPAddresses}
		if !slices.Equal(refused, want) {
			t.Errorf("refused = %v, want %v", refused, want)
		}
		for _, r := range refused {
			if strings.Contains(r, hostile) {
				t.Errorf("refused entry %q carries the wire value", r)
			}
		}
		if facts.Hostname != "" || facts.OS != "linux" || !slices.Equal(facts.IPAddresses, []string{"10.0.0.1"}) {
			t.Errorf("facts = %+v, want hostname dropped, os and the plain address kept", facts)
		}
	})
}

func TestHelloReportFromProto(t *testing.T) {
	good := strings.Repeat("0123456789abcdef", 4)
	other := strings.Repeat("fedcba9876543210", 4)
	huge := strings.Repeat("a", 1<<20)
	bidi := "abcdefghij\u202e" + strings.Repeat("a", 51)

	tests := []struct {
		name        string
		hello       *relayv1.Hello
		want        protoconv.HelloReport
		wantRefused []string
		wireValue   string // must appear in no refused entry
	}{
		{
			name: "well-formed is unchanged",
			hello: &relayv1.Hello{
				PolicyFingerprint: good, TemplateSetFingerprint: other,
				DaemonVersion: "0.0.1-test", Facts: &relayv1.Facts{Hostname: "h"},
			},
			want: protoconv.HelloReport{
				PolicyFingerprint: good, TemplateSetFingerprint: other,
				DaemonVersion: "0.0.1-test", Facts: registry.Facts{Hostname: "h"},
			},
		},
		{
			name:        "a 1 MiB policy fingerprint is not reported",
			hello:       &relayv1.Hello{PolicyFingerprint: huge},
			wantRefused: []string{protoconv.FieldPolicyFingerprint},
			wireValue:   huge,
		},
		{
			name:        "a policy fingerprint carrying U+202E is not reported",
			hello:       &relayv1.Hello{PolicyFingerprint: bidi},
			wantRefused: []string{protoconv.FieldPolicyFingerprint},
			wireValue:   bidi,
		},
		{
			name:        "a sha256-prefixed policy fingerprint is not reported",
			hello:       &relayv1.Hello{PolicyFingerprint: "sha256:" + good},
			wantRefused: []string{protoconv.FieldPolicyFingerprint},
			wireValue:   "sha256:" + good,
		},
		{
			name:        "an uppercase policy fingerprint is not reported",
			hello:       &relayv1.Hello{PolicyFingerprint: strings.ToUpper(good)},
			wantRefused: []string{protoconv.FieldPolicyFingerprint},
			wireValue:   strings.ToUpper(good),
		},
		{
			name:  "the unloadable template fingerprint is kept",
			hello: &relayv1.Hello{TemplateSetFingerprint: "unloadable"},
			want:  protoconv.HelloReport{TemplateSetFingerprint: "unloadable"},
		},
		{
			name:  "an empty template fingerprint is kept and not refused",
			hello: &relayv1.Hello{TemplateSetFingerprint: ""},
		},
		{
			name:        "a malformed template fingerprint is recorded as none loaded",
			hello:       &relayv1.Hello{TemplateSetFingerprint: bidi},
			wantRefused: []string{protoconv.FieldTemplateSetFingerprint},
			wireValue:   bidi,
		},
		{
			name:        "a daemon version that is not semver is not reported",
			hello:       &relayv1.Hello{DaemonVersion: "1.4.2, tag:x=y"},
			wantRefused: []string{protoconv.FieldDaemonVersion},
			wireValue:   "1.4.2, tag:x=y",
		},
		{
			name:        "an over-long daemon version is not reported",
			hello:       &relayv1.Hello{DaemonVersion: "1.0.0-" + strings.Repeat("a", 300)},
			wantRefused: []string{protoconv.FieldDaemonVersion},
			wireValue:   "1.0.0-" + strings.Repeat("a", 300),
		},
		{
			name:        "a facts failure is named with its field",
			hello:       &relayv1.Hello{Facts: &relayv1.Facts{Hostname: "web\u202e01", Os: "linux"}},
			want:        protoconv.HelloReport{Facts: registry.Facts{OS: "linux"}},
			wantRefused: []string{protoconv.FieldHostname},
			wireValue:   "web\u202e01",
		},
		{name: "nil Hello is the zero value", hello: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, refused := protoconv.HelloReportFromProto(tt.hello)
			if got.PolicyFingerprint != tt.want.PolicyFingerprint ||
				got.TemplateSetFingerprint != tt.want.TemplateSetFingerprint ||
				got.DaemonVersion != tt.want.DaemonVersion ||
				got.Facts.Hostname != tt.want.Facts.Hostname ||
				got.Facts.OS != tt.want.Facts.OS {
				t.Errorf("report = %.200q, want %.200q", got, tt.want)
			}
			if !slices.Equal(refused, tt.wantRefused) {
				t.Errorf("refused = %v, want %v", refused, tt.wantRefused)
			}
			for _, r := range refused {
				if tt.wireValue != "" && strings.Contains(r, tt.wireValue) {
					t.Errorf("refused entry carries the wire value")
				}
			}
		})
	}
}

func TestParseNodeLabel(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    string
		wantBare string
		wantOK   bool
	}{
		{
			name:     "valid node: label",
			key:      "node:role",
			value:    "web",
			wantBare: "role",
			wantOK:   true,
		},
		{
			name:     "relay: prefix is rejected",
			key:      "relay:env",
			value:    "prod",
			wantBare: "",
			wantOK:   false,
		},
		{
			// A Node cannot report a tag: label (invariant 7, ADR-0050): the
			// Hello ingress drops it, as it drops relay:.
			name:     "tag: prefix is rejected",
			key:      "tag:env",
			value:    "prod",
			wantBare: "",
			wantOK:   false,
		},
		{
			name:     "node: with empty bare key is rejected",
			key:      "node:",
			value:    "x",
			wantBare: "",
			wantOK:   false,
		},
		{
			name:     "no prefix is rejected",
			key:      "role",
			value:    "web",
			wantBare: "",
			wantOK:   false,
		},
		{
			name:     "empty value is a compatibility floor",
			key:      "node:role",
			value:    "",
			wantBare: "role",
			wantOK:   true,
		},
		{
			name:     "the measured payload — comma-injected second term is rejected",
			key:      "node:role",
			value:    "web, relay:quarantine=on",
			wantBare: "",
			wantOK:   false,
		},
		{
			name:     "a key of exactly the Label key bound is accepted",
			key:      "node:" + strings.Repeat("k", registry.MaxLabelKeyLen),
			value:    "x",
			wantBare: strings.Repeat("k", registry.MaxLabelKeyLen),
			wantOK:   true,
		},
		{
			name:   "a key one byte over the Label key bound is rejected",
			key:    "node:" + strings.Repeat("k", registry.MaxLabelKeyLen+1),
			value:  "x",
			wantOK: false,
		},
		{
			name:     "a value of exactly the Label value bound is accepted",
			key:      "node:role",
			value:    strings.Repeat("v", registry.MaxLabelValueLen),
			wantBare: "role",
			wantOK:   true,
		},
		{
			name:   "a value one byte over the Label value bound is rejected",
			key:    "node:role",
			value:  strings.Repeat("v", registry.MaxLabelValueLen+1),
			wantOK: false,
		},
		{
			name:     "equals in the key-side split hazard is rejected",
			key:      "node:role=x",
			value:    "web",
			wantBare: "",
			wantOK:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bare, ok := protoconv.ParseNodeLabel(tc.key, tc.value)
			if ok != tc.wantOK {
				t.Errorf("ok: got %v, want %v", ok, tc.wantOK)
			}
			if bare != tc.wantBare {
				t.Errorf("bare: got %q, want %q", bare, tc.wantBare)
			}
		})
	}
}
