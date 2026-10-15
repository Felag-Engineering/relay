package protoconv_test

import (
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/protoconv"
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
		if len(got.IPAddresses) != 0 {
			t.Errorf("expected empty IPAddresses, got %v", got.IPAddresses)
		}
	})
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
