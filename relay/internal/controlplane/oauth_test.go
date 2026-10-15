package controlplane

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/relaytest"
)

// -----------------------------------------------------------------------
// Harness: a real oidc.IDTokenVerifier over a locally-generated key.
//
// No live IdP and no HTTP mock of one. The verifier under test is the real
// go-oidc verifier — signature checking, issuer, audience, and expiry all
// genuinely enforced — with a StaticKeySet holding a key this test generated.
// An auth path that can only be exercised against a real provider is one that
// goes untested, and this is the path a human's session comes in through.
// -----------------------------------------------------------------------

const (
	testIssuer   = "https://idp.example.internal"
	testAudience = "https://relay.example.internal:9443/mcp"
)

type idpFixture struct {
	key      *rsa.PrivateKey
	verifier OIDCVerifier
}

func newIDP(t *testing.T) *idpFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	verifier := oidc.NewVerifier(
		testIssuer,
		&oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}},
		&oidc.Config{ClientID: testAudience},
	)
	return &idpFixture{key: key, verifier: verifier}
}

// claimSet is the token body, with every field a test might want to bend.
type claimSet struct {
	Issuer   string
	Audience string
	Subject  string
	Email    string
	Scope    string
	Expiry   time.Time
}

func (f *idpFixture) mint(t *testing.T, c claimSet) string {
	t.Helper()
	if c.Issuer == "" {
		c.Issuer = testIssuer
	}
	if c.Audience == "" {
		c.Audience = testAudience
	}
	if c.Expiry.IsZero() {
		c.Expiry = time.Now().Add(time.Hour)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: f.key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	claims := map[string]any{
		"iss": c.Issuer,
		"aud": c.Audience,
		"sub": c.Subject,
		"exp": c.Expiry.Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	}
	if c.Email != "" {
		claims["email"] = c.Email
	}
	if c.Scope != "" {
		claims["scope"] = c.Scope
	}

	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return raw
}

// fakeLookup is the narrow read-only Account view OAuth resolution needs.
type fakeLookup struct {
	accts map[string]accounts.Account
	err   error
}

func (f *fakeLookup) GetByName(_ context.Context, name string) (accounts.Account, error) {
	if f.err != nil {
		return accounts.Account{}, f.err
	}
	a, ok := f.accts[accounts.NormalizeName(name)]
	if !ok {
		return accounts.Account{}, accounts.ErrNotFound
	}
	return a, nil
}

func humanAccount(name string, role accounts.Role, enabled bool) accounts.Account {
	return accounts.Account{
		ID: "acct-" + name, Name: name, Kind: accounts.KindHuman, Role: role, Enabled: enabled,
	}
}

// oauthAuthenticator wires a real verifier and a lookup into an Authenticator.
func oauthAuthenticator(t *testing.T, f *idpFixture, lookup *fakeLookup, scope string) *Authenticator {
	t.Helper()
	return NewAuthenticator(
		&fakeVerifier{acct: storedFoundingAdmin(), valid: testCredential},
		WithOAuth(
			OAuthConfig{Issuer: testIssuer, Audience: testAudience, RequiredScope: scope},
			f.verifier, lookup,
			"https://relay.example.internal:9443"+ProtectedResourceMetadataPath,
		),
	)
}

// -----------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------

// Acceptance: a human's token drives the control plane, attributed to their
// Account with their Account's role.
func TestOAuth_ValidTokenResolvesToItsAccount(t *testing.T) {
	f := newIDP(t)
	lookup := &fakeLookup{accts: map[string]accounts.Account{
		"mike": humanAccount("mike", accounts.RoleOperator, true),
	}}
	a := oauthAuthenticator(t, f, lookup, "")

	code, seen := authRequest(t, a, f.mint(t, claimSet{Subject: "idp-uid-1", Email: "mike"}))
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200", code)
	}
	if seen.Name != "mike" || seen.Role != string(accounts.RoleOperator) || seen.ID != "acct-mike" {
		t.Errorf("principal = %+v, want mike's Account with its stored role", seen)
	}
}

// Acceptance: "a machine-token session and an OAuth session are
// distinguishable in audit."
func TestOAuth_SessionKindIsDistinguishable(t *testing.T) {
	f := newIDP(t)
	lookup := &fakeLookup{accts: map[string]accounts.Account{
		"mike": humanAccount("mike", accounts.RoleAdmin, true),
	}}
	a := oauthAuthenticator(t, f, lookup, "")

	var oauthPrincipal, tokenPrincipal capability.Principal
	capture := func(dst *capability.Principal) http.Handler {
		return http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			*dst, _ = PrincipalFromContext(r.Context())
		})
	}

	for _, c := range []struct {
		credential string
		dst        *capability.Principal
	}{
		{f.mint(t, claimSet{Subject: "idp-uid-1", Email: "mike"}), &oauthPrincipal},
		{testCredential, &tokenPrincipal},
	} {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+c.credential)
		a.Middleware(capture(c.dst)).ServeHTTP(httptest.NewRecorder(), req)
	}

	if oauthPrincipal.AuthMethod != capability.AuthMethodOAuth {
		t.Errorf("OAuth session AuthMethod = %q, want %q", oauthPrincipal.AuthMethod, capability.AuthMethodOAuth)
	}
	if tokenPrincipal.AuthMethod != capability.AuthMethodAPIToken {
		t.Errorf("API Token session AuthMethod = %q, want %q", tokenPrincipal.AuthMethod, capability.AuthMethodAPIToken)
	}
	if oauthPrincipal.AuthMethod == tokenPrincipal.AuthMethod {
		t.Error("the two session kinds are indistinguishable")
	}
	// An OAuth session presents no API Token, so there is no token id to
	// record — and inventing one would imply a credential the Relay could
	// revoke, which it cannot.
	if oauthPrincipal.TokenID != "" {
		t.Errorf("OAuth session carries TokenID %q, want empty", oauthPrincipal.TokenID)
	}
}

// Every rejection is the same generic 401. The IdP already told the caller
// their token was good; telling them which of the Relay's checks then refused
// it only helps someone probing for a valid identity.
func TestOAuth_EveryRejectionIsIndistinguishable(t *testing.T) {
	f := newIDP(t)
	other := newIDP(t) // a different signing key entirely
	lookup := &fakeLookup{accts: map[string]accounts.Account{
		"mike":    humanAccount("mike", accounts.RoleOperator, true),
		"retired": humanAccount("retired", accounts.RoleOperator, false),
	}}

	cases := []struct{ label, credential string }{
		{"wrong signing key", other.mint(t, claimSet{Email: "mike"})},
		{"wrong issuer", f.mint(t, claimSet{Issuer: "https://evil.example", Email: "mike"})},
		{"wrong audience", f.mint(t, claimSet{Audience: "https://other-service.example", Email: "mike"})},
		{"expired", f.mint(t, claimSet{Email: "mike", Expiry: time.Now().Add(-time.Minute)})},
		{"no account claim", f.mint(t, claimSet{Subject: "idp-uid-1"})},
		{"unknown account", f.mint(t, claimSet{Email: "stranger"})},
		{"disabled account", f.mint(t, claimSet{Email: "retired"})},
		{"not a jwt", "this-is-not-a-token"},
		{"empty-ish", "..."},
	}

	a := oauthAuthenticator(t, f, lookup, "")
	bodies := map[string]bool{}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+c.credential)
		rec := httptest.NewRecorder()
		a.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			t.Errorf("[%s] handler reached", c.label)
		})).ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("[%s] status = %d, want 401", c.label, rec.Code)
		}
		bodies[rec.Body.String()] = true
	}
	if len(bodies) != 1 {
		t.Errorf("rejection bodies differ across cases (%v); every one must be byte-identical", bodies)
	}
}

// The audience check is the RFC 8707 binding, and it is what stops a token
// minted for a different service in the same IdP from driving the fleet.
// Called out separately because it is the failure with the worst consequence:
// without it, every application sharing the IdP becomes a confused deputy.
func TestOAuth_TokenForAnotherAudienceIsRefused(t *testing.T) {
	f := newIDP(t)
	lookup := &fakeLookup{accts: map[string]accounts.Account{
		"mike": humanAccount("mike", accounts.RoleAdmin, true),
	}}
	a := oauthAuthenticator(t, f, lookup, "")

	valid := f.mint(t, claimSet{Email: "mike"})
	if code, _ := authRequest(t, a, valid); code != http.StatusOK {
		t.Fatalf("the correctly-audienced token was refused (%d); the fixture proves nothing", code)
	}

	elsewhere := f.mint(t, claimSet{Email: "mike", Audience: "https://wiki.example.internal"})
	if code, seen := authRequest(t, a, elsewhere); code != http.StatusUnauthorized {
		t.Errorf("a token minted for another service authenticated: status %d, principal %+v", code, seen)
	}
}

// An unknown subject is refused, never provisioned: auto-creating an Account
// from a token claim would let whoever administers the IdP mint identities on
// the control plane and bypass the audited creation path (#297, ADR-0024).
func TestOAuth_UnknownSubjectIsNotProvisioned(t *testing.T) {
	f := newIDP(t)
	lookup := &fakeLookup{accts: map[string]accounts.Account{}}
	a := oauthAuthenticator(t, f, lookup, "")

	if code, _ := authRequest(t, a, f.mint(t, claimSet{Email: "stranger"})); code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", code)
	}
	if len(lookup.accts) != 0 {
		t.Errorf("an Account was created during authentication: %+v", lookup.accts)
	}
}

// An OAuth session's authority is the role of the Account it resolves to.
// Authenticating through an IdP does not grant anything extra — in particular
// it does not make a session admin.
func TestOAuth_AuthorityIsTheAccountsRole(t *testing.T) {
	f := newIDP(t)
	lookup := &fakeLookup{accts: map[string]accounts.Account{
		"viewer-human": humanAccount("viewer-human", accounts.RoleViewer, true),
	}}
	a := oauthAuthenticator(t, f, lookup, "")

	_, seen := authRequest(t, a, f.mint(t, claimSet{Email: "viewer-human"}))
	if seen.Role != string(accounts.RoleViewer) {
		t.Errorf("role = %q, want viewer — an OAuth session inherits its Account's role and nothing more", seen.Role)
	}
}

func TestOAuth_RequiredScopeIsEnforced(t *testing.T) {
	f := newIDP(t)
	lookup := &fakeLookup{accts: map[string]accounts.Account{
		"mike": humanAccount("mike", accounts.RoleOperator, true),
	}}
	a := oauthAuthenticator(t, f, lookup, "relay.fleet")

	if code, _ := authRequest(t, a, f.mint(t, claimSet{Email: "mike", Scope: "openid profile relay.fleet"})); code != http.StatusOK {
		t.Errorf("a token carrying the required scope was refused: %d", code)
	}
	if code, _ := authRequest(t, a, f.mint(t, claimSet{Email: "mike", Scope: "openid profile"})); code != http.StatusUnauthorized {
		t.Errorf("a token missing the required scope was accepted: %d", code)
	}
	// Element match, not substring: "relay.fleet.readonly" must not satisfy
	// a requirement for "relay.fleet".
	if code, _ := authRequest(t, a, f.mint(t, claimSet{Email: "mike", Scope: "relay.fleet.readonly"})); code != http.StatusUnauthorized {
		t.Errorf("a scope that merely contains the required one was accepted: %d", code)
	}
}

// Credential kinds are routed by prefix, never tried in turn — the ADR-0023
// rule, applied again now that there are two kinds.
func TestOAuth_CredentialKindsAreRoutedNotTried(t *testing.T) {
	f := newIDP(t)
	lookup := &fakeLookup{accts: map[string]accounts.Account{
		"mike": humanAccount("mike", accounts.RoleAdmin, true),
	}}
	tokenVerifier := &fakeVerifier{acct: storedFoundingAdmin(), valid: testCredential}
	a := NewAuthenticator(tokenVerifier, WithOAuth(
		OAuthConfig{Issuer: testIssuer, Audience: testAudience},
		f.verifier, lookup, "https://relay.example.internal:9443"+ProtectedResourceMetadataPath))

	// A JWT never reaches the API Token verifier...
	if code, _ := authRequest(t, a, f.mint(t, claimSet{Email: "mike"})); code != http.StatusOK {
		t.Fatalf("oauth status = %d, want 200", code)
	}
	if len(tokenVerifier.seen) != 0 {
		t.Errorf("the API Token verifier was consulted for a JWT: %v", tokenVerifier.seen)
	}

	// ...and a glp_ credential never reaches the OAuth resolver, which would
	// have refused it.
	if code, _ := authRequest(t, a, testCredential); code != http.StatusOK {
		t.Errorf("api token status = %d, want 200", code)
	}
}

// Without an IdP configured the Relay advertises no flow and refuses anything
// that is not an API Token — fail closed rather than 401-with-a-dead-pointer.
func TestOAuth_NotConfiguredRefusesAndAdvertisesNothing(t *testing.T) {
	a := NewAuthenticator(&fakeVerifier{acct: storedFoundingAdmin(), valid: testCredential})

	code, _ := authRequest(t, a, "eyJhbGciOiJSUzI1NiJ9.e30.sig")
	if code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", code)
	}

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	rec := httptest.NewRecorder()
	a.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)
	if got := rec.Header().Get("WWW-Authenticate"); got != "Bearer" {
		t.Errorf("WWW-Authenticate = %q, want a bare %q with no IdP configured", got, "Bearer")
	}

	rec = httptest.NewRecorder()
	a.MetadataHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ProtectedResourceMetadataPath, nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("metadata status = %d, want 404 with no IdP configured", rec.Code)
	}
}

// The discovery contract: a 401 points at the metadata document, and the
// document names the authorization server. Together they are what lets an
// off-the-shelf harness complete the flow with no Relay-specific setup.
func TestOAuth_DiscoveryContract(t *testing.T) {
	f := newIDP(t)
	a := oauthAuthenticator(t, f, &fakeLookup{accts: map[string]accounts.Account{}}, "relay.fleet")
	metadataURL := "https://relay.example.internal:9443" + ProtectedResourceMetadataPath

	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	rec := httptest.NewRecorder()
	a.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).ServeHTTP(rec, req)

	challenge := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(challenge, "Bearer ") || !strings.Contains(challenge, `resource_metadata="`+metadataURL+`"`) {
		t.Errorf("WWW-Authenticate = %q, want a Bearer challenge carrying resource_metadata=%q", challenge, metadataURL)
	}

	rec = httptest.NewRecorder()
	a.MetadataHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, ProtectedResourceMetadataPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("metadata status = %d, want 200", rec.Code)
	}

	var doc protectedResourceMetadata
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatalf("decode metadata %q: %v", rec.Body.String(), err)
	}
	if doc.Resource != testAudience {
		t.Errorf("resource = %q, want the audience tokens must be bound to (%q)", doc.Resource, testAudience)
	}
	if len(doc.AuthorizationServers) != 1 || doc.AuthorizationServers[0] != testIssuer {
		t.Errorf("authorization_servers = %v, want [%q]", doc.AuthorizationServers, testIssuer)
	}
	if len(doc.ScopesSupported) != 1 || doc.ScopesSupported[0] != "relay.fleet" {
		t.Errorf("scopes_supported = %v, want the required scope so a harness requests it", doc.ScopesSupported)
	}

	// The document is public discovery data and must be fetchable
	// cross-origin by a browser-based harness (RFC 9728 §3.1). It carries no
	// secret: an issuer URL and a resource identifier.
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("metadata is not CORS-readable; a browser-based harness cannot discover the flow")
	}
	if body := rec.Body.String(); strings.Contains(body, "glp_") {
		t.Errorf("the public metadata document contains credential-shaped material: %s", body)
	}
}

// The metadata document must be reachable WITHOUT a credential — it is what
// tells a harness how to obtain one. A metadata endpoint behind the auth it
// describes is a locked door with the key inside.
//
// Driven through the real Server (not the handler in isolation) because the
// property under test is exactly the routing: one public path, everything else
// authenticated.
func TestOAuth_MetadataIsReachableWithoutACredential(t *testing.T) {
	f := newIDP(t)
	authn := oauthAuthenticator(t, f, &fakeLookup{accts: map[string]accounts.Account{}}, "")

	srv := New(Config{Addr: "127.0.0.1:0", GetCertificate: staticCert(relaytest.SelfSignedServerCert(t, "controlplane-test"))}, authn)
	srv.Mux().HandleFunc("GET /api/v1/protected", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	ts := httptest.NewServer(srv.http.Handler)
	defer ts.Close()

	// Public: no Authorization header at all.
	resp, err := http.Get(ts.URL + ProtectedResourceMetadataPath)
	if err != nil {
		t.Fatalf("Get metadata: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metadata status = %d, want 200 without a credential", resp.StatusCode)
	}

	// ...and nothing else on the listener became public along with it.
	protected, err := http.Get(ts.URL + "/api/v1/protected")
	if err != nil {
		t.Fatalf("Get protected: %v", err)
	}
	defer protected.Body.Close()
	if protected.StatusCode != http.StatusUnauthorized {
		t.Errorf("an ordinary route returned %d without a credential, want 401 — the public exemption must be exactly one path", protected.StatusCode)
	}

	ping, err := http.Get(ts.URL + "/api/v1/ping")
	if err != nil {
		t.Fatalf("Get ping: %v", err)
	}
	defer ping.Body.Close()
	if ping.StatusCode != http.StatusUnauthorized {
		t.Errorf("/api/v1/ping returned %d without a credential, want 401", ping.StatusCode)
	}
}
