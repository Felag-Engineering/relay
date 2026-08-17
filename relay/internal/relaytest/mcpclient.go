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

// ConnectWith is Connect with a hook to configure the underlying client
// before it dials — the seam a test needs to register custom JSON-RPC methods
// via sdkmcp.AddSendingCustomMethod, since the extension methods Relay serves
// (tasks/get, tasks/cancel; #374, SEP-2663) are not on the SDK's standard
// dispatch table on either side.
func ConnectWith(t *testing.T, base string, client *http.Client, setup func(*sdkmcp.Client)) *sdkmcp.ClientSession {
	t.Helper()
	session, err := tryConnect(t, base, client, setup)
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
	return tryConnect(t, base, client, nil)
}

func tryConnect(t *testing.T, base string, client *http.Client, setup func(*sdkmcp.Client)) (*sdkmcp.ClientSession, error) {
	t.Helper()

	c := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "relaytest-client", Version: "0.0.1"}, nil)
	if setup != nil {
		setup(c)
	}
	transport := &sdkmcp.StreamableClientTransport{Endpoint: base + "/mcp", HTTPClient: client}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := c.Connect(ctx, transport, nil)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, nil
}

// CallTool calls name with args, failing the test on a protocol-level error
// (not a tool error — callers assert IsError explicitly). The 30s timeout
// covers a real daemon's live Task execution (run_operation blocks on the
// Tunnel round trip), longer than a purely read-only tool call needs.
func CallTool(t *testing.T, session *sdkmcp.ClientSession, name string, args map[string]any) *sdkmcp.CallToolResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := session.CallTool(ctx, &sdkmcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool(%s): protocol error: %v", name, err)
	}
	return res
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
