// Package main: oauth_idp_e2e_test.go is #743's OAuth e2e fixture — a LOCAL
// test IdP, not a live OAuth provider (#351 stays open), so AP-78/AP-79's
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
//
// TestE2EOAuth_ApproveRequestOnAHumanSessionStillRecordsAnAssertion pins
// that approve_request is out of scope for #743's signed-in-identity change:
// it is always asserted, even on a qualifying OAuth human session.
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/coreos/go-oidc/v3/oidc/oidctest"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/mcp"
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

// TestE2EOAuth_ApproveRequestOnAHumanSessionStillRecordsAnAssertion pins
// that approve_request never takes AP-79's verified form, even on a
// qualifying OAuth human session: the tool is model-called, so treating its
// approver as verified would let a model approve its own request on a
// human's session. #743's signed-in-identity change touches only the
// answered-retry path (tools_approval.go's acceptElicitedAnswer).
func TestE2EOAuth_ApproveRequestOnAHumanSessionStillRecordsAnAssertion(t *testing.T) {
	f, idp := startOAuthElicitingRelay(t, gateAllMutatesInBandAskable)
	accountID := createAccount(t, f, "hana", accounts.KindHuman, accounts.RoleAdmin)
	token := idp.token(t, "hana")

	// relaytest.Connect uses the default, unrecognised client name, so this
	// call parks as pending_approval and asks nothing (AP-78) — this test
	// needs an ordinary in-band park on an OAuth human session, not a
	// question.
	session := relaytest.Connect(t, f.ControlBase, f.ClientFor(token))
	res := relaytest.CallTool(t, session, "run_operation", restartNginxArgs())
	var out mcp.RunOrPlanOutput
	relaytest.DecodeToolJSON(t, res, &out)
	if out.PendingApproval == nil {
		t.Fatalf("did not park: %+v", out)
	}
	requestID := out.PendingApproval.RequestID
	planHash := out.PendingApproval.PlanHash

	// Subtests run in order on the SAME parked request: (a) before (b),
	// because (b) decides it.
	// This would refuse on any session — the approver bound refuses a blank
	// value first — so it proves nothing about the human-OAuth case on its
	// own; the next subtest carries that proof.
	t.Run("approver \"\" is refused as a machine self-decision", func(t *testing.T) {
		approveRes := relaytest.CallTool(t, session, "approve_request", map[string]any{
			"request_id": requestID,
			"plan_hash":  planHash,
			"approve":    true,
			"approver":   "",
		})
		if !approveRes.IsError {
			t.Fatalf("IsError = false, want true — approve_request never takes the verified form on a human OAuth session")
		}
		text := relaytest.ToolErrorText(t, approveRes)
		if !strings.Contains(text, "must name the human") {
			t.Errorf("error text = %q, want it to contain %q", text, "must name the human")
		}
		if got := len(decisionRecordsFor(t, f, requestID)); got != 0 {
			t.Errorf("decision records = %d, want 0", got)
		}
	})

	t.Run("approver alice records an asserted decision", func(t *testing.T) {
		approveRes := relaytest.CallTool(t, session, "approve_request", map[string]any{
			"request_id": requestID,
			"plan_hash":  planHash,
			"approve":    true,
			"approver":   elicitResponderUsername,
		})
		if approveRes.IsError {
			t.Fatalf("approve_request: IsError, content=%+v", approveRes.Content)
		}
		var decision mcp.ApprovalDecisionOutput
		relaytest.DecodeToolJSON(t, approveRes, &decision)
		if decision.OnBehalfOf != elicitResponderUsername {
			t.Errorf("OnBehalfOf = %q, want %q", decision.OnBehalfOf, elicitResponderUsername)
		}

		decisions := decisionRecordsFor(t, f, requestID)
		if len(decisions) != 1 {
			t.Fatalf("decision records = %d, want exactly 1: %+v", len(decisions), decisions)
		}
		if decisions[0].Attribution.Asserted.OnBehalfOf != elicitResponderUsername {
			t.Errorf("Asserted.OnBehalfOf = %q, want %q", decisions[0].Attribution.Asserted.OnBehalfOf, elicitResponderUsername)
		}
		if decisions[0].Attribution.Verified.AccountID != accountID {
			t.Errorf("Verified.AccountID = %q, want %q", decisions[0].Attribution.Verified.AccountID, accountID)
		}
		if decisions[0].Attribution.Verified.TokenID != "" {
			t.Errorf("Verified.TokenID = %q, want empty — this session is OAuth, not an API Token", decisions[0].Attribution.Verified.TokenID)
		}
	})
}
