package main

import (
	"strings"
	"testing"

	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
)

// The OAuth lane's refusals run before discovery, so each is reachable here
// without an IdP.

func TestOAuthAuthOption_NoIssuerBuildsNoLane(t *testing.T) {
	opt, ok, err := oauthAuthOption(Config{OAuthAudience: "relay", OAuthPublicURL: "https://relay.example"}, nil)
	if err != nil || ok || opt != nil {
		t.Fatalf("oauthAuthOption with no issuer = (%v, %v, %v), want (nil, false, nil)", opt != nil, ok, err)
	}
}

func TestOAuthAuthOption_RefusesMissingAudience(t *testing.T) {
	_, ok, err := oauthAuthOption(Config{OAuthIssuer: "https://idp.example", OAuthPublicURL: "https://relay.example"}, nil)
	if err == nil || ok {
		t.Fatalf("oauthAuthOption without an audience = (ok %v, err %v), want a refusal", ok, err)
	}
	if !strings.Contains(err.Error(), "-oauth-audience is required") {
		t.Errorf("refusal %q does not name the missing audience", err)
	}
}

func TestOAuthAuthOption_RefusesMissingPublicURL(t *testing.T) {
	_, ok, err := oauthAuthOption(Config{OAuthIssuer: "https://idp.example", OAuthAudience: "relay"}, nil)
	if err == nil || ok {
		t.Fatalf("oauthAuthOption without a public URL = (ok %v, err %v), want a refusal", ok, err)
	}
	if !strings.Contains(err.Error(), "-oauth-public-url is required") {
		t.Errorf("refusal %q does not name the missing public URL", err)
	}
}

// Enroll is the one RPC a daemon reaches before it holds a client certificate;
// anything added to this set is reachable without mTLS.
// Proves NC-2, NC-29.
func TestCertlessMethods_OnlyEnroll(t *testing.T) {
	got := certlessMethods()
	if len(got) != 1 {
		t.Fatalf("certlessMethods has %d entries, want exactly 1: %v", len(got), got)
	}
	if _, ok := got[relayv1.Enrollment_Enroll_FullMethodName]; !ok {
		t.Fatalf("certlessMethods = %v, want only %s", got, relayv1.Enrollment_Enroll_FullMethodName)
	}
}
