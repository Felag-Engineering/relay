// Package main: oauth_idp_e2e_test.go is #743's OAuth e2e fixture — a LOCAL
// test IdP, not a live OAuth provider (#351 stays open), so AP-86/AP-79's
// "OAuth session of a human Account" can be built end to end through the
// REAL composition root: real discovery (oidc.NewProvider against a loopback
// issuer, main.go's NewOIDCVerifier), the real oauthResolver
// (controlplane/oauth.go) copying the Account's Kind through unchecked, and
// the real audit lanes.
//
// go-oidc v3.20.0 is already a direct requirement (go.mod) and ships a test
// IdP at github.com/coreos/go-oidc/v3/oidc/oidctest: a Server serving
// /.well-known/openid-configuration and /keys, plus SignIDToken. Nothing here
// adds a new dependency; `go mod tidy` leaves go.mod and go.sum untouched.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// e2eOAuthAudience is this Relay's resource identifier for every token these
// tests mint — checked against the token's `aud`, per RFC 8707.
const e2eOAuthAudience = "https://relay.e2e.invalid/mcp"

// e2eIDP is a local OpenID Connect provider serving real discovery and JWKS
// documents over a loopback HTTP listener.
type e2eIDP struct {
	key    *rsa.PrivateKey
	issuer string
}

// startE2EIDP brings up the test IdP and returns a handle to mint tokens
// against it. The server is closed on test cleanup.
func startE2EIDP(t *testing.T) *e2eIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate IdP key: %v", err)
	}
	srv := &oidctest.Server{
		PublicKeys: []oidctest.PublicKey{
			{PublicKey: key.Public(), KeyID: "e2e", Algorithm: oidc.RS256},
		},
	}
	hs := httptest.NewServer(srv)
	t.Cleanup(hs.Close)
	srv.SetIssuer(hs.URL)
	return &e2eIDP{key: key, issuer: hs.URL}
}

// token mints a signed ID token for accountName, claiming it in the "email"
// claim — OAuthConfig.AccountClaim's default (controlplane/auth.go's
// WithOAuth) — with a subject distinct from the Account name, so a test
// cannot accidentally pass by matching on "sub" instead of the claim Relay
// actually reads.
func (i *e2eIDP) token(t *testing.T, accountName string) string {
	t.Helper()
	now := time.Now()
	claims, err := json.Marshal(map[string]any{
		"iss":   i.issuer,
		"aud":   e2eOAuthAudience,
		"sub":   "idp-" + accountName,
		"email": accountName,
		"iat":   now.Add(-time.Minute).Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return oidctest.SignIDToken(i.key, "e2e", oidc.RS256, string(claims))
}

// withE2EOAuth is the FixtureOption that points a relayFixture's Config at
// i's issuer and this file's fixed audience/public URL — the composition
// root's real discovery path (main.go), not a hand-built verifier.
func withE2EOAuth(i *e2eIDP) FixtureOption {
	return WithConfig(func(c *Config) {
		c.OAuthIssuer = i.issuer
		c.OAuthAudience = e2eOAuthAudience
		c.OAuthPublicURL = "https://relay.e2e.invalid"
	})
}

// createAccount creates an Account with no API Token — the OAuth session's
// only credential is the IdP-issued JWT — and returns its stored ID.
func createAccount(t *testing.T, f *relayFixture, name string, kind accounts.Kind, role accounts.Role) string {
	t.Helper()
	acct, err := f.Deps.store.Accounts().Create(context.Background(), accounts.Account{
		Name: name, Kind: kind, Role: role, Enabled: true,
	})
	if err != nil {
		t.Fatalf("create account %s: %v", name, err)
	}
	return acct.ID
}

// startOAuthElicitingRelay is startElicitingRelayWith with the local test IdP
// wired in, for a test that needs a real OAuth session on top of the
// elicitation fixture's usual gate/Node/machine-Account setup.
func startOAuthElicitingRelay(t *testing.T, rules string) (f *relayFixture, idp *e2eIDP) {
	t.Helper()
	idp = startE2EIDP(t)
	f, _, _ = startElicitingRelayWith(t, rules, withE2EOAuth(idp))
	return f, idp
}

// TestE2EOAuth_SessionResolvesToTheAccount is the fixture's own acceptance
// test: a read tool call authenticated with the IdP's JWT succeeds, and its
// audit entry's verified lane names the Account the token's email claim
// resolved to, with an empty TokenID (OAuth presents no API Token) — so a
// fixture failure (discovery refused, wrong claim, silently falling back to
// the API-token lane) is diagnosable apart from whatever claim a consuming
// test is actually exercising.
func TestE2EOAuth_SessionResolvesToTheAccount(t *testing.T) {
	f, idp := startOAuthElicitingRelay(t, gateAllMutatesInBandAskable)
	createAccount(t, f, "hana", accounts.KindHuman, accounts.RoleAdmin)
	token := idp.token(t, "hana")

	session := relaytest.Connect(t, f.ControlBase, f.ClientFor(token))
	res := relaytest.CallTool(t, session, "run_operation", map[string]any{"operation": "system.facts", "wait_seconds": 300})
	if res.IsError {
		t.Fatalf("run_operation over the OAuth session returned IsError=true: %+v", res.Content)
	}

	records, err := f.Deps.audit.List(context.Background())
	if err != nil {
		t.Fatalf("audit.List: %v", err)
	}
	var found bool
	for _, r := range records {
		if r.Attribution.Verified.AccountName != "hana" {
			continue
		}
		found = true
		if r.Attribution.Verified.TokenID != "" {
			t.Errorf("Verified.TokenID = %q, want empty — an OAuth session presents no API Token", r.Attribution.Verified.TokenID)
		}
	}
	if !found {
		t.Fatalf("no audit record names the Account hana: %+v", records)
	}
}
