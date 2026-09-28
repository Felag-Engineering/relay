package relaytest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestElicitingClientOptions_AdvertisesElicitationAndDisablesAutoFulfil is a
// pure data assertion — no network. The wire behaviour (an input-required
// result reaching a client built this way unchanged) is proved by the
// cmd/relay smoke test (#721).
func TestElicitingClientOptions_AdvertisesElicitationAndDisablesAutoFulfil(t *testing.T) {
	opts := ElicitingClientOptions()

	if opts.Capabilities == nil || opts.Capabilities.Elicitation == nil || opts.Capabilities.Elicitation.Form == nil {
		t.Fatalf("ElicitingClientOptions().Capabilities = %+v, want a form elicitation capability advertised", opts.Capabilities)
	}
	if opts.MultiRoundTrip == nil || !opts.MultiRoundTrip.Disabled {
		t.Fatalf("ElicitingClientOptions().MultiRoundTrip = %+v, want Disabled=true so an input-required "+
			"result reaches the caller instead of being auto-fulfilled", opts.MultiRoundTrip)
	}

	// Two calls must return distinct pointers, so a caller mutating one (to
	// add URL elicitation or an ElicitationHandler) cannot affect another
	// test's client.
	other := ElicitingClientOptions()
	if opts == other {
		t.Fatal("ElicitingClientOptions() returned the same pointer twice, want a fresh value per call")
	}
	if opts.Capabilities == other.Capabilities {
		t.Fatal("ElicitingClientOptions() returned the same Capabilities pointer twice, want a fresh value per call")
	}
}

// echoNameInput/echoNameOutput are the minimal shapes echoNameServer's tool
// needs.
type echoNameInput struct{}
type echoNameOutput struct {
	Name string `json:"name"`
}

// echoNameServer is a bare go-sdk HTTP server (no Relay auth or composition
// root) whose one tool reports the declared client name it observed in the
// per-request `_meta` clientInfo — the exact reading AP-78
// (internal/controlplane/mcp) uses, so this test proves ConnectOptions is the
// wire-level source of that value rather than trusting mcpclient.go's own
// reading of it.
func echoNameServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := sdkmcp.NewServer(&sdkmcp.Implementation{Name: "relaytest-echo-server", Version: "0.0.1"}, nil)
	sdkmcp.AddTool(srv, &sdkmcp.Tool{Name: "echo_client_name"}, func(_ context.Context, req *sdkmcp.CallToolRequest, _ echoNameInput) (*sdkmcp.CallToolResult, echoNameOutput, error) {
		info, _ := req.Params.GetMeta()[sdkmcp.MetaKeyClientInfo].(map[string]any)
		name, _ := info["name"].(string)
		return nil, echoNameOutput{Name: name}, nil
	})

	// Stateless: true mirrors mcp.go's own composition root — without it the
	// SDK server does not answer SEP-2575's server/discover, the client falls
	// back to the legacy initialize handshake, and clientInfo is never
	// injected into any per-request `_meta` at all (client.go's
	// usesNewProtocol gate).
	mux := http.NewServeMux()
	mux.Handle("/mcp", sdkmcp.NewStreamableHTTPHandler(func(*http.Request) *sdkmcp.Server { return srv },
		&sdkmcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
	httpSrv := httptest.NewServer(mux)
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

// TestConnectOptions_ClientNameTravelsInClientInfo proves ConnectOptions.ClientName
// is what lands in every request's `_meta` clientInfo.name, and that its zero
// value is defaultClientName — a name AP-78 deliberately does not recognise.
func TestConnectOptions_ClientNameTravelsInClientInfo(t *testing.T) {
	srv := echoNameServer(t)

	cases := []struct {
		name       string
		clientName string
		want       string
	}{
		{name: "zero value defaults to relaytest-client", clientName: "", want: defaultClientName},
		{name: "GleipnirClientName", clientName: GleipnirClientName, want: GleipnirClientName},
		{name: "ClaudeCodeClientName", clientName: ClaudeCodeClientName, want: ClaudeCodeClientName},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			session := ConnectWithOptions(t, srv.URL, http.DefaultClient, ConnectOptions{ClientName: tc.clientName})
			res := CallTool(t, session, "echo_client_name", nil)
			var out echoNameOutput
			DecodeToolJSON(t, res, &out)
			if out.Name != tc.want {
				t.Errorf("observed clientInfo.name = %q, want %q", out.Name, tc.want)
			}
		})
	}
}
