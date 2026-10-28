package main

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

func TestParseInitFlags_TTLDefaultsToTheHumanLifetime(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want capability.APITokenLifetime
	}{
		{"absent", []string{"--admin", "alice"}, capability.DefaultAPITokenLifetime()},
		{"zero", []string{"--admin", "alice", "--ttl", "0"}, capability.ExplicitAPITokenLifetime(0)},
		{"24h", []string{"--recover", "alice", "--ttl", "24h"}, capability.ExplicitAPITokenLifetime(24 * time.Hour)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			opts, code, done := parseInitFlags(tc.args, os.Stderr)
			if done {
				t.Fatalf("parse refused with exit %d", code)
			}
			if opts.lifetime != tc.want {
				t.Errorf("lifetime = %+v, want %+v", opts.lifetime, tc.want)
			}
		})
	}

	got, err := capability.ResolveAPITokenTTL(accounts.KindHuman, capability.DefaultAPITokenLifetime())
	if err != nil || got != 168*time.Hour {
		t.Errorf("the default resolves to %v, %v; want 168h", got, err)
	}
}

// The usage text states the default the constant decides, so the two cannot
// drift apart.
func TestInitUsage_NamesTheDefaultLifetime(t *testing.T) {
	if want := capability.HumanAPITokenDefaultTTL.String(); !strings.Contains(initUsage, "Default 168h") || want != "168h0m0s" {
		t.Errorf("initUsage does not name the %s default:\n%s", want, initUsage)
	}
	if !strings.Contains(initUsage, "--ttl 0 means no expiry") {
		t.Error("initUsage does not say --ttl 0 means no expiry")
	}
}
