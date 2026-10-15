package mcp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/capability"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
)

// elicit_internal_test.go is S2b's SDK in-memory seam (package mcp, unlike
// elicit_test.go's mcp_test HTTP seam): it drives the SDK's real
// server-side multi-round-trip middleware (serverMultiRoundTripMiddleware,
// unconditionally installed by sdkmcp.NewServer) over a genuine in-memory
// transport, so the branch clientCanBeAsked's condition 2 exists to keep
// closed is actually live in these tests — the stateless HTTP seam
// (elicit_test.go) cannot reach it, because the transport itself already
// refuses a request whose `_meta` protocolVersion disagrees with the
// MCP-Protocol-Version header before the handler ever runs.

// elicitInternalCredential/elicitInternalVerifier are a minimal
// TokenVerifier, exactly like taskgolden_test.go's goldenVerifier, so
// authedContext below can inject a real Principal.
const elicitInternalCredential = accounts.TokenPrefix + "0123456789abcdef.elicit-internal-secret" // test fixture, not a real credential

type elicitInternalVerifier struct{}

func (elicitInternalVerifier) Verify(_ context.Context, credential string) (accounts.Account, accounts.APIToken, error) {
	if credential != elicitInternalCredential {
		return accounts.Account{}, accounts.APIToken{}, accounts.ErrTokenInvalid
	}
	return accounts.Account{
		ID: "acct-elicit-internal", Name: "elicit-internal", Role: accounts.RoleOperator,
		Kind: accounts.KindHuman, Enabled: true,
	}, accounts.APIToken{ID: "tok-elicit-internal"}, nil
}

// authedContext runs controlplane.NewAuthenticator(verifier).Middleware over
// a synthetic request carrying a valid bearer credential and captures the
// context it injects — the only way to get a Principal into a context from
// outside package controlplane. jsonrpc2's Connection keeps the base ctx's
// values for every request it dispatches, so passing this ctx to
// srv.Connect makes requirePrincipal succeed inside the handlers below,
// exactly as the real Authenticator.Middleware would over HTTP.
func authedContext(t *testing.T) context.Context {
	t.Helper()
	var captured context.Context
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		captured = r.Context()
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+elicitInternalCredential)
	controlplane.NewAuthenticator(elicitInternalVerifier{}).Middleware(next).ServeHTTP(httptest.NewRecorder(), req)
	if captured == nil {
		t.Fatal("authedContext: middleware refused the synthetic credential")
	}
	return captured
}

// elicitModernMeta is a `_meta` map shaped exactly like a real >= 2026-07-28
// client would send: protocolVersion at mrtrProtocolVersion, clientInfo
// declaring the recognised name "gleipnir" (AP-78), plus clientCapabilities
// carrying form elicitation. Built as a map (the wire shape decodeMetaValue's
// remarshal path expects), not the typed Go struct, so it exercises the same
// JSON round trip a real request would.
func elicitModernMeta() map[string]any {
	return map[string]any{
		sdkmcp.MetaKeyProtocolVersion:    mrtrProtocolVersion,
		sdkmcp.MetaKeyClientInfo:         map[string]any{"name": clientNameGleipnir, "version": "0.0.1"},
		sdkmcp.MetaKeyClientCapabilities: map[string]any{"elicitation": map[string]any{"form": map[string]any{}}},
	}
}

// TestElicit_LegacyHeaderWithModernMetaDoesNotAsk is predicate condition 2's
// tripwire: a client whose SESSION negotiated a legacy protocol version, but
// whose PER-REQUEST `_meta` looks modern (protocolVersion 2026-07-28,
// elicitation/form capability), must not be asked. If condition 2 were
// skipped and only condition 3 (the per-request `_meta`) were checked, the
// handler would return InputRequests to a session
// serverMultiRoundTripMiddleware considers non-MRTR, and the SDK would
// respond by sending a SERVER-INITIATED elicitation/create straight to the
// client — exactly the pattern ADR-0029 rejected, on a stateless handler
// that cannot serve it. This is what clientCanBeAsked's condition-2 doc
// comment is about, made concrete: the ElicitationHandler call count below
// is the proof that path was never taken.
func TestElicit_LegacyHeaderWithModernMetaDoesNotAsk(t *testing.T) {
	parked := &capability.ParkedError{
		RequestID: "req-predicate-1",
		PlanHash:  "hash-predicate-1",
		Summary:   `service.restart(unit="nginx") [mutate] on 1 node(s): node-a`,
		Progress:  "0 of 1",
		Rules:     []string{"all-mutates-need-a-human"},
		ExpiresAt: time.Now().Add(time.Hour),
		Askable:   true,
	}

	srv := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "relay-elicit-test", Version: "0.0.1"}, nil)
	registerExecutionTools(srv, parkingExecutor{parked: parked}, nil, stubOpsLister{}, newQuestioner(nil), nil, nil, time.Now)

	serverTransport, clientTransport := sdkmcp.NewInMemoryTransports()

	var elicitCalls int32
	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "legacy-client", Version: "0.0.1"}, &sdkmcp.ClientOptions{
		Capabilities: &sdkmcp.ClientCapabilities{
			Elicitation: &sdkmcp.ElicitationCapabilities{Form: &sdkmcp.FormElicitationCapabilities{}},
		},
		ElicitationHandler: func(context.Context, *sdkmcp.ElicitRequest) (*sdkmcp.ElicitResult, error) {
			atomic.AddInt32(&elicitCalls, 1)
			return &sdkmcp.ElicitResult{Action: "decline"}, nil
		},
	})

	ctx := authedContext(t)

	// Servers must be connected before clients (NewInMemoryTransports' doc).
	ss, err := srv.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server Connect: %v", err)
	}
	defer ss.Close()

	cs, err := client.Connect(ctx, clientTransport, &sdkmcp.ClientSessionOptions{ProtocolVersion: "2025-11-25"})
	if err != nil {
		t.Fatalf("client Connect: %v", err)
	}
	defer cs.Close()

	// Precondition: the SESSION really did negotiate a legacy version — the
	// scenario this test exists to exercise.
	if ip := ss.InitializeParams(); ip == nil || ip.ProtocolVersion >= mrtrProtocolVersion {
		t.Fatalf("precondition failed: server session InitializeParams = %+v, want a real ProtocolVersion below %s", ip, mrtrProtocolVersion)
	}

	params := &sdkmcp.CallToolParams{
		Name:      toolRunOperation,
		Arguments: map[string]any{"operation": "service.restart", "args": map[string]string{"unit": "nginx"}},
	}
	params.SetMeta(elicitModernMeta())

	res, err := cs.CallTool(ctx, params)
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}

	if res.InputRequests != nil {
		t.Errorf("InputRequests = %+v, want nil — condition 2 must refuse a legacy SESSION even with a modern _meta", res.InputRequests)
	}
	if res.RequestState != "" {
		t.Errorf("RequestState = %q, want empty", res.RequestState)
	}
	if res.NeedsInput() {
		t.Error("NeedsInput() = true, want false")
	}
	if res.StructuredContent == nil {
		t.Fatal("StructuredContent is nil, want the ordinary pending_approval result")
	}
	if calls := atomic.LoadInt32(&elicitCalls); calls != 0 {
		t.Errorf("ElicitationHandler was called %d times, want 0 — the server must never send a "+
			"server-initiated elicitation/create over a stateless handler that cannot serve it", calls)
	}
}

// probeToolInput/probeToolOutput are the minimal shapes a no-op probe tool
// needs.
type probeToolInput struct{}
type probeToolOutput struct{}

// registerProbeTool adds a tool that unconditionally asks ONE bare question
// on its first call (ignoring Askable/the questioner entirely — this probes
// the SDK's OWN clientSupportsMultiRoundTrip judgment, not elicit.go's
// predicate) and returns an ordinary complete result once it has been
// answered, so a retried call — whether driven by the client's own
// multi-round-trip middleware or by the server's — terminates rather than
// looping.
func registerProbeTool(srv *sdkmcp.Server) {
	sdkmcp.AddTool(srv, &sdkmcp.Tool{Name: "probe"}, func(_ context.Context, req *sdkmcp.CallToolRequest, _ probeToolInput) (*sdkmcp.CallToolResult, probeToolOutput, error) {
		if len(req.Params.InputResponses) > 0 {
			return &sdkmcp.CallToolResult{}, probeToolOutput{}, nil
		}
		return &sdkmcp.CallToolResult{
			InputRequests: sdkmcp.InputRequestMap{"probe-1": &sdkmcp.ElicitParams{Mode: "form", Message: "probe"}},
		}, probeToolOutput{}, nil
	})
}

// TestElicit_PredicateMirrorsTheSDK strengthens the predicate proof beyond a
// hand-written truth table: it drives the SDK's OWN clientSupportsMultiRoundTrip
// judgment on a real *sdkmcp.ServerSession (via the probe tool above,
// independent of elicit.go) and asserts clientCanBeAsked's condition-2 half
// AGREES with whichever real branch the SDK took — resultType input_required
// (the SDK considers the session MRTR-capable) versus a server-initiated
// elicitation/create reaching the client's ElicitationHandler (the SDK
// considers it not).
//
// Only two of the three legs a full truth table would need are exercised
// here as REAL negotiated sessions (legacy and modern): the third, a session
// with a truly nil InitializeParams, only arises on the stateless-HTTP
// ephemeral path for a >= 2026-07-28 request (ephemeralConnectOpts
// synthesizes fake params only for OLD-protocol requests) — every test in
// elicit_test.go's mcp_test HTTP seam already IS that leg, since Relay's
// real handler runs stateless. Reproducing that exact ephemeral-session
// construction over a raw in-memory transport, without going through
// streamable.go's HTTP machinery, was judged not worth the fragility it
// would add here; TestElicit_LegacyHeaderWithModernMetaDoesNotAsk remains
// the named tripwire for an SDK behaviour change on the mismatched leg, and
// the HTTP seam's own tests are the tripwire for the nil-session leg.
func TestElicit_PredicateMirrorsTheSDK(t *testing.T) {
	cases := []struct {
		name            string
		protocolVersion string
	}{
		{"legacy session", "2025-11-25"},
		{"modern session", mrtrProtocolVersion},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "relay-predicate-probe", Version: "0.0.1"}, nil)
			registerProbeTool(srv)

			serverTransport, clientTransport := sdkmcp.NewInMemoryTransports()

			var elicitCalls int32
			client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "probe-client", Version: "0.0.1"}, &sdkmcp.ClientOptions{
				Capabilities: &sdkmcp.ClientCapabilities{
					Elicitation: &sdkmcp.ElicitationCapabilities{Form: &sdkmcp.FormElicitationCapabilities{}},
				},
				// Disabled so a modern session's raw input-required result
				// reaches this test unconsumed, isolating "did the SDK MARK
				// it input_required" from "did the client's OWN automatic
				// retry middleware also fire".
				MultiRoundTrip: &sdkmcp.MultiRoundTripOptions{Disabled: true},
				ElicitationHandler: func(context.Context, *sdkmcp.ElicitRequest) (*sdkmcp.ElicitResult, error) {
					atomic.AddInt32(&elicitCalls, 1)
					return &sdkmcp.ElicitResult{Action: "decline"}, nil
				},
			})

			ctx := authedContext(t)

			ss, err := srv.Connect(ctx, serverTransport, nil)
			if err != nil {
				t.Fatalf("server Connect: %v", err)
			}
			defer ss.Close()

			cs, err := client.Connect(ctx, clientTransport, &sdkmcp.ClientSessionOptions{ProtocolVersion: tc.protocolVersion})
			if err != nil {
				t.Fatalf("client Connect: %v", err)
			}
			defer cs.Close()

			// Our own condition-2 judgment, computed from the SAME real
			// session clientCanBeAsked would see — condition 3 is held
			// always-true by construction (elicitModernMeta), so this
			// return value IS condition 2 alone. The Principal is an
			// arbitrary API Token human: elicitModernMeta declares gleipnir,
			// which is asked on any session, so it plays no part here.
			gotCondition2 := clientCanBeAsked(&sdkmcp.CallToolRequest{
				Session: ss,
				Params:  probeAlwaysAskableParams(),
			}, capability.Principal{AuthMethod: capability.AuthMethodAPIToken, Kind: capability.PrincipalKindHuman})

			res, err := cs.CallTool(ctx, &sdkmcp.CallToolParams{Name: "probe"})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}

			sdkConsidersMRTRCapable := res.NeedsInput()
			calls := atomic.LoadInt32(&elicitCalls)

			switch {
			case sdkConsidersMRTRCapable && calls != 0:
				t.Fatalf("SDK reported input_required AND called ElicitationHandler (%d times) — test harness contradiction", calls)
			case !sdkConsidersMRTRCapable && calls == 0:
				t.Fatalf("SDK neither reported input_required nor called ElicitationHandler — the probe tool's InputRequests were dropped")
			}

			if gotCondition2 != sdkConsidersMRTRCapable {
				t.Errorf("clientCanBeAsked's condition 2 = %v, but the SDK's OWN clientSupportsMultiRoundTrip judgment = %v "+
					"(observed via %s) — the two must always agree", gotCondition2, sdkConsidersMRTRCapable,
					map[bool]string{true: "resultType input_required", false: "a server-initiated elicitation/create"}[sdkConsidersMRTRCapable])
			}
		})
	}
}

// probeAlwaysAskableParams is a *sdkmcp.CallToolParamsRaw whose `_meta`
// always satisfies clientCanBeAsked's condition 3, so calling
// clientCanBeAsked against it isolates condition 2 alone.
func probeAlwaysAskableParams() *sdkmcp.CallToolParamsRaw {
	p := &sdkmcp.CallToolParamsRaw{Name: "probe"}
	p.SetMeta(elicitModernMeta())
	return p
}

// oauthHumanInternalPrincipal is the session shape AP-78 admits for a
// claude-code ask: an OAuth session of a human Account.
func oauthHumanInternalPrincipal() capability.Principal {
	return capability.Principal{AuthMethod: capability.AuthMethodOAuth, Kind: capability.PrincipalKindHuman}
}

// TestElicit_WhoIsAskedByNameAndSession is AP-78's clientCanBeAsked unit
// seam: a real MODERN session holds condition 2 always true, and every row's
// `_meta` carries a modern protocolVersion and form elicitation (so
// condition 3 always holds too), leaving the declared client name — read from
// the raw io.modelcontextprotocol/clientInfo entry, condition 5 — and, for
// claude-code, the calling Principal's own session shape, as the only things
// that vary.
func TestElicit_WhoIsAskedByNameAndSession(t *testing.T) {
	srv := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "relay-name-probe", Version: "0.0.1"}, nil)
	registerProbeTool(srv)
	serverTransport, clientTransport := sdkmcp.NewInMemoryTransports()

	client := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "probe-client", Version: "0.0.1"}, &sdkmcp.ClientOptions{
		Capabilities: &sdkmcp.ClientCapabilities{
			Elicitation: &sdkmcp.ElicitationCapabilities{Form: &sdkmcp.FormElicitationCapabilities{}},
		},
	})

	ctx := authedContext(t)
	ss, err := srv.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server Connect: %v", err)
	}
	defer ss.Close()
	cs, err := client.Connect(ctx, clientTransport, &sdkmcp.ClientSessionOptions{ProtocolVersion: mrtrProtocolVersion})
	if err != nil {
		t.Fatalf("client Connect: %v", err)
	}
	defer cs.Close()

	// metaWith builds a `_meta` map that always satisfies conditions 2/3
	// (protocolVersion and form elicitation present), varying only clientInfo
	// — nil omits the key entirely.
	metaWith := func(clientInfo any) map[string]any {
		m := map[string]any{
			sdkmcp.MetaKeyProtocolVersion:    mrtrProtocolVersion,
			sdkmcp.MetaKeyClientCapabilities: map[string]any{"elicitation": map[string]any{"form": map[string]any{}}},
		}
		if clientInfo != nil {
			m[sdkmcp.MetaKeyClientInfo] = clientInfo
		}
		return m
	}

	cases := []struct {
		name       string
		clientInfo any
		wantAsked  bool
	}{
		{"gleipnir", map[string]any{"name": "gleipnir", "version": "1"}, true},
		{"claude-code", map[string]any{"name": "claude-code", "version": "1"}, true},
		{"typed Implementation pointer named gleipnir", &sdkmcp.Implementation{Name: "gleipnir"}, true},
		{"Gleipnir (wrong case)", map[string]any{"name": "Gleipnir", "version": "1"}, false},
		{"leading space", map[string]any{"name": " gleipnir", "version": "1"}, false},
		{"trailing space", map[string]any{"name": "claude-code ", "version": "1"}, false},
		{"some-other-client", map[string]any{"name": "some-other-client", "version": "1"}, false},
		{"empty name", map[string]any{"name": "", "version": "1"}, false},
		{"name not a string", map[string]any{"name": 42, "version": "1"}, false},
		{"clientInfo not an object", "gleipnir", false},
		{"key Name only (case-variant)", map[string]any{"Name": "gleipnir"}, false},
		{"clientInfo absent", nil, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			params := &sdkmcp.CallToolParamsRaw{Name: "probe"}
			params.SetMeta(metaWith(tc.clientInfo))
			got := clientCanBeAsked(&sdkmcp.CallToolRequest{Session: ss, Params: params}, oauthHumanInternalPrincipal())
			if got != tc.wantAsked {
				t.Errorf("clientCanBeAsked = %v, want %v", got, tc.wantAsked)
			}
		})
	}

	// claude-code's OWN name row above is asked only because the Principal
	// there is an OAuth human session (AP-78) — this table pins that the
	// session shape, not just the name, decides it: every other shape is not
	// asked, decided by oauthHumanSession (tools_approval.go), the same
	// function the acceptor uses for the verified form, and never inferred
	// from AuthMethod alone. The assertions do not change, because asking
	// does not change.
	claudeCodeMeta := metaWith(map[string]any{"name": "claude-code", "version": "1"})
	sessionCases := []struct {
		name      string
		principal capability.Principal
		wantAsked bool
	}{
		{"OAuth + human", capability.Principal{AuthMethod: capability.AuthMethodOAuth, Kind: capability.PrincipalKindHuman}, true},
		{"API Token + human", capability.Principal{AuthMethod: capability.AuthMethodAPIToken, Kind: capability.PrincipalKindHuman}, false},
		{"API Token + machine", capability.Principal{AuthMethod: capability.AuthMethodAPIToken, Kind: "machine"}, false},
		{"OAuth + machine", capability.Principal{AuthMethod: capability.AuthMethodOAuth, Kind: "machine"}, false},
		{"OAuth + unset kind", capability.Principal{AuthMethod: capability.AuthMethodOAuth}, false},
		{"Console session + human", capability.Principal{AuthMethod: capability.AuthMethodConsoleSession, Kind: capability.PrincipalKindHuman}, false},
		{"Unspecified + human", capability.Principal{Kind: capability.PrincipalKindHuman}, false},
	}
	for _, tc := range sessionCases {
		t.Run("claude-code, "+tc.name, func(t *testing.T) {
			params := &sdkmcp.CallToolParamsRaw{Name: "probe"}
			params.SetMeta(claudeCodeMeta)
			got := clientCanBeAsked(&sdkmcp.CallToolRequest{Session: ss, Params: params}, tc.principal)
			if got != tc.wantAsked {
				t.Errorf("clientCanBeAsked = %v, want %v", got, tc.wantAsked)
			}
		})
	}

	// gleipnir's path is unaffected by the session: it is asked whatever the
	// Principal, including a machine Account on either auth method.
	gleipnirMeta := metaWith(map[string]any{"name": "gleipnir", "version": "1"})
	gleipnirCases := []struct {
		name      string
		principal capability.Principal
	}{
		{"API Token + machine", capability.Principal{AuthMethod: capability.AuthMethodAPIToken, Kind: "machine"}},
		{"OAuth + machine", capability.Principal{AuthMethod: capability.AuthMethodOAuth, Kind: "machine"}},
	}
	for _, tc := range gleipnirCases {
		t.Run("gleipnir, "+tc.name, func(t *testing.T) {
			params := &sdkmcp.CallToolParamsRaw{Name: "probe"}
			params.SetMeta(gleipnirMeta)
			if got := clientCanBeAsked(&sdkmcp.CallToolRequest{Session: ss, Params: params}, tc.principal); !got {
				t.Errorf("clientCanBeAsked = %v, want true (gleipnir is asked on any session)", got)
			}
		})
	}
}
