package relaytest

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// callToolTimeout covers a real daemon's live Task execution (run_operation
// blocks on the Tunnel round trip), longer than a purely read-only tool call
// needs.
const callToolTimeout = 30 * time.Second

// defaultClientName is what ConnectOptions.ClientName defaults to: a name
// AP-78 does not recognise, so a test that wants the emission predicate to
// ask a question must opt in with GleipnirClientName (asked on any session)
// or ClaudeCodeClientName (asked only on an OAuth session of a human
// Account).
const defaultClientName = "relaytest-client"

// GleipnirClientName and ClaudeCodeClientName are the declared client names
// AP-78 recognises (elicit.go's clientNameGleipnir/clientNameClaudeCode),
// exported so a test can set ConnectOptions.ClientName without repeating the
// literal. Gleipnir is asked wherever AP-61 otherwise allows, whatever the
// session; Claude Code is asked only where the calling Principal also
// authenticated by OAuth with a human Account (AP-78) — declaring
// ClaudeCodeClientName alone is not enough.
const (
	GleipnirClientName   = "gleipnir"
	ClaudeCodeClientName = "claude-code"
)

// Connect opens an authenticated MCP client session against base+"/mcp",
// using client for the transport (carry any required auth on client, e.g. a
// BearerRoundTripper). session.Close is registered as a t.Cleanup.
func Connect(t *testing.T, base string, client *http.Client) *sdkmcp.ClientSession {
	t.Helper()
	session, err := TryConnect(t, base, client)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	return session
}

// TryConnect is Connect without the fatal: it returns the connection error
// instead, for tests asserting that a credential is *refused* at the MCP
// endpoint (a revoked token, a disabled Account, a non-credential).
func TryConnect(t *testing.T, base string, client *http.Client) (*sdkmcp.ClientSession, error) {
	t.Helper()
	return tryConnect(t, base, client, ConnectOptions{})
}

// ConnectOptions configures ConnectWithOptions. Every field is optional; the
// zero value is exactly Connect.
type ConnectOptions struct {
	// Client is passed to sdkmcp.NewClient. This is the only way to reach
	// options the SDK reads INSIDE NewClient itself — most notably
	// MultiRoundTrip, which installs the client's automatic input-fulfilment
	// middleware in NewClient's body, before any post-construction hook could
	// switch it off.
	Client *sdkmcp.ClientOptions
	// ClientName is the MCP client's declared name: it travels in every
	// 2026-07-28 request's `_meta` clientInfo, and Relay's emission predicate
	// asks a question only when it declares a recognised name (AP-78,
	// GleipnirClientName or ClaudeCodeClientName). Empty means
	// "relaytest-client", which is deliberately unrecognised.
	ClientName string
	// Session is passed to the Connect call. ProtocolVersion lets a test build
	// a client that negotiates an older protocol than 2026-07-28 (SEP-2322),
	// which does not support multi-round-trip on the wire at all — useful for
	// an AP-85 "cannot be asked" client. An empty value negotiates the latest.
	//
	// Such a client is NOT the same as one with MultiRoundTrip.Disabled: on an
	// old protocol version the SDK server transparently fulfills an
	// input-required result itself (serverMultiRoundTripMiddleware), sending
	// elicitation/create straight to the client regardless of the client's own
	// MultiRoundTrip setting — a client built this way must still be prepared
	// to answer it (e.g. via ElicitationHandler) or the call will hang.
	Session *sdkmcp.ClientSessionOptions
}

// ConnectWithOptions is Connect generalized to every ClientOptions and
// ClientSessionOptions a test may need — for example ElicitingClientOptions
// with a declared ClientName.
func ConnectWithOptions(t *testing.T, base string, client *http.Client, o ConnectOptions) *sdkmcp.ClientSession {
	t.Helper()
	session, err := tryConnect(t, base, client, o)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}
	return session
}

// TryConnectWithOptions is ConnectWithOptions without the fatal: it returns
// the connection error instead.
func TryConnectWithOptions(t *testing.T, base string, client *http.Client, o ConnectOptions) (*sdkmcp.ClientSession, error) {
	t.Helper()
	return tryConnect(t, base, client, o)
}

// ElicitingClientOptions returns ClientOptions for a client that CAN be asked
// (advertises form elicitation) but answers nothing by itself (the SDK's
// automatic multi-round-trip middleware is off), so an input-required result
// reaches the test verbatim instead of being consumed by the client. Returns a
// fresh value per call, so callers may mutate it freely (for example to add
// URL elicitation or an ElicitationHandler) without affecting another test.
//
// A non-nil Capabilities also drops the SDK's default "roots" capability
// advertisement — harmless here, since Relay never reads roots.
func ElicitingClientOptions() *sdkmcp.ClientOptions {
	return &sdkmcp.ClientOptions{
		Capabilities: &sdkmcp.ClientCapabilities{
			Elicitation: &sdkmcp.ElicitationCapabilities{Form: &sdkmcp.FormElicitationCapabilities{}},
		},
		MultiRoundTrip: &sdkmcp.MultiRoundTripOptions{Disabled: true},
	}
}

func tryConnect(t *testing.T, base string, client *http.Client, o ConnectOptions) (*sdkmcp.ClientSession, error) {
	t.Helper()

	name := o.ClientName
	if name == "" {
		name = defaultClientName
	}
	c := sdkmcp.NewClient(&sdkmcp.Implementation{Name: name, Version: "0.0.1"}, o.Client)
	transport := &sdkmcp.StreamableClientTransport{Endpoint: base + "/mcp", HTTPClient: client}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := c.Connect(ctx, transport, o.Session)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, nil
}

// CallTool calls name with args, failing the test on a protocol-level error
// (not a tool error — callers assert IsError explicitly).
func CallTool(t *testing.T, session *sdkmcp.ClientSession, name string, args map[string]any) *sdkmcp.CallToolResult {
	t.Helper()
	return CallToolWith(t, session, &sdkmcp.CallToolParams{Name: name, Arguments: args})
}

// CallToolWith is TryCallToolWith that fails the test on a protocol-level
// error only. Use it for the MRTR happy path, where a well-formed retry is
// expected to succeed at the protocol level even if it (today) reports the
// same result as before.
func CallToolWith(t *testing.T, session *sdkmcp.ClientSession, params *sdkmcp.CallToolParams) *sdkmcp.CallToolResult {
	t.Helper()
	res, err := TryCallToolWith(t, session, params)
	if err != nil {
		t.Fatalf("CallTool(%s): protocol error: %v", params.Name, err)
	}
	return res
}

// TryCallToolWith sends params as-is and returns the raw result and error. An
// input-required result (res.NeedsInput()) is a normal return, never an
// error — this is how a caller drives the MRTR happy path and its refusals
// alike, without this package interpreting IsError or NeedsInput itself.
//
// The SDK fills a nil Arguments with an empty map and may copy params to
// inject _meta (client.go's injectRequestMeta), so callers must not rely on
// params being left untouched after the call.
func TryCallToolWith(t *testing.T, session *sdkmcp.ClientSession, params *sdkmcp.CallToolParams) (*sdkmcp.CallToolResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), callToolTimeout)
	defer cancel()
	return session.CallTool(ctx, params)
}

// RetryTool is the MRTR retry (SEP-2322): the same call, echoing requestState
// and carrying responses to the input requests the previous result asked for.
// It fails the test on a protocol-level error only — see CallToolWith.
func RetryTool(t *testing.T, session *sdkmcp.ClientSession, name string, args map[string]any, requestState string, responses sdkmcp.InputResponseMap) *sdkmcp.CallToolResult {
	t.Helper()
	return CallToolWith(t, session, &sdkmcp.CallToolParams{
		Name:           name,
		Arguments:      args,
		RequestState:   requestState,
		InputResponses: responses,
	})
}

// DecodeToolJSON unmarshals a successful CallToolResult's text content into
// out, failing the test on a tool error or malformed content.
func DecodeToolJSON(t *testing.T, res *sdkmcp.CallToolResult, out any) {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool call returned IsError=true unexpectedly; content = %+v", res.Content)
	}
	if len(res.Content) == 0 {
		t.Fatal("CallToolResult.Content is empty")
	}
	tc, ok := res.Content[0].(*sdkmcp.TextContent)
	if !ok {
		t.Fatalf("CallToolResult.Content[0] = %T, want *sdkmcp.TextContent", res.Content[0])
	}
	if err := json.Unmarshal([]byte(tc.Text), out); err != nil {
		t.Fatalf("json.Unmarshal(%q): %v", tc.Text, err)
	}
}

// ToolErrorText extracts a tool error's message text, failing the test if
// res is not actually an error result.
func ToolErrorText(t *testing.T, res *sdkmcp.CallToolResult) string {
	t.Helper()
	if !res.IsError {
		t.Fatal("ToolErrorText: result is not an error")
	}
	if len(res.Content) == 0 {
		t.Fatal("ToolErrorText: Content is empty")
	}
	tc, ok := res.Content[0].(*sdkmcp.TextContent)
	if !ok {
		t.Fatalf("ToolErrorText: Content[0] = %T, want *sdkmcp.TextContent", res.Content[0])
	}
	return tc.Text
}

// FactHostname extracts the "hostname=" value from a system.facts stdout
// blob — the daemon's key=value stdout encoding (relay-daemon/src/dispatch.rs
// format_facts_as_kv), NOT JSON — one line per fact, "hostname=..." first.
func FactHostname(stdout string) string {
	for _, line := range strings.Split(stdout, "\n") {
		if v, ok := strings.CutPrefix(line, "hostname="); ok {
			return v
		}
	}
	return ""
}
