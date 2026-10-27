// Package harnesssetup renders, at API Token mint, what a Harness needs to reach
// this Relay's MCP endpoint: the URL, the CA certificate, a client block per
// supported Harness and a one-command check. It is ADR-0032's mint-and-render
// rule applied to API Tokens.
package harnesssetup

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

const (
	// MCPPath is the path the MCP surface is mounted at. The end-to-end test that
	// replays the rendered check proves it matches the mount.
	MCPPath = "/mcp"
	// CAFileName is the file name every rendered block expects the CA certificate
	// to be saved under.
	CAFileName = "relay-ca.pem"
	// CheckBody is the MCP initialize request the rendered check sends. It holds
	// no single quote, so it sits safely inside single quotes in a shell line.
	CheckBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"relay-check","version":"1"}}}`

	serverName = "relay"
)

// CheckHeaders are the request headers, besides Authorization, the rendered
// check sends. They are exported so tests replay exactly what the check does.
var CheckHeaders = []string{
	"Content-Type: application/json",
	"Accept: application/json, text/event-stream",
}

var (
	// ErrNoTarget is returned by Render on a zero Target.
	ErrNoTarget = errors.New("harnesssetup: no target")
	// ErrTarget is returned by NewTarget for an address or certificate it cannot
	// render safely.
	ErrTarget = errors.New("harnesssetup: invalid target")
	// ErrCredential is returned by Render for a credential outside the alphabet an
	// API Token is minted in.
	ErrCredential = errors.New("harnesssetup: credential is not an API Token")
)

// Target is where this Relay's MCP endpoint is and the CA certificate that
// signs it. It holds public data only, as strings nothing can write through.
type Target struct {
	mcpURL string
	caPEM  string
}

// NewTarget builds the Target from the node-plane advertised address (whose host
// is a SAN of the server certificate), the control-plane listen address (whose
// port serves /mcp) and the CA certificate PEM. A host or port outside the DNS
// and IP alphabet is refused, which is what keeps the rendered URL safe inside
// single quotes. So is a PEM holding anything but CERTIFICATE blocks, which
// keeps key material out of what every minter is shown.
func NewTarget(advertisedAddress, controlListenAddress string, caPEM []byte) (Target, error) {
	host, _, err := net.SplitHostPort(advertisedAddress)
	if err != nil || !validHost(host) {
		return Target{}, ErrTarget
	}
	_, port, err := net.SplitHostPort(controlListenAddress)
	if err != nil || !allDigits(port) {
		return Target{}, ErrTarget
	}
	if !onlyCertificates(caPEM) {
		return Target{}, ErrTarget
	}
	u := url.URL{Scheme: "https", Host: net.JoinHostPort(host, port), Path: MCPPath}
	return Target{mcpURL: u.String(), caPEM: string(caPEM)}, nil
}

// onlyCertificates reports whether data is one or more PEM CERTIFICATE blocks
// and nothing else: no text before or between blocks, no block that fails to
// decode, no trailing bytes. pem.Decode alone skips all three.
func onlyCertificates(data []byte) bool {
	const begin = "-----BEGIN CERTIFICATE-----"
	blocks := 0
	for {
		data = bytes.TrimLeft(data, " \t\r\n")
		if len(data) == 0 {
			return blocks > 0
		}
		if !bytes.HasPrefix(data, []byte(begin)) {
			return false
		}
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return false
		}
		blocks++
	}
}

func validHost(host string) bool {
	if host == "" {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	return onlyBytes(host, func(c byte) bool {
		return isAlnum(c) || c == '.' || c == '-'
	})
}

func allDigits(s string) bool {
	return s != "" && onlyBytes(s, func(c byte) bool { return c >= '0' && c <= '9' })
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func onlyBytes(s string, ok func(byte) bool) bool {
	for i := 0; i < len(s); i++ {
		if !ok(s[i]) {
			return false
		}
	}
	return true
}

// validCredential reports whether credential has the shape a minted API Token
// has: the prefix, then a hex id, a dot and base64url. Nothing in that alphabet
// can end a double-quoted shell word or a JSON string.
func validCredential(credential string) bool {
	return strings.HasPrefix(credential, accounts.TokenPrefix) && onlyBytes(credential, func(c byte) bool {
		return isAlnum(c) || c == '.' || c == '-' || c == '_'
	})
}

// Render builds the Harness setup for credential, an API Token plaintext. The
// Gleipnir block is rendered only for a machine Account.
func (t Target) Render(credential string, kind accounts.Kind) (Rendering, error) {
	if t.mcpURL == "" {
		return Rendering{}, ErrNoTarget
	}
	if !validCredential(credential) {
		return Rendering{}, ErrCredential
	}
	bearer := "Bearer " + credential

	mcpJSON, err := encodeJSON(mcpJSONFile{map[string]mcpJSONServer{
		serverName: {Type: "http", URL: t.mcpURL, Headers: map[string]string{"Authorization": bearer}},
	}})
	if err != nil {
		return Rendering{}, err
	}
	claudeCode := fmt.Sprintf("claude mcp add --transport http %s '%s' --header \"Authorization: %s\"\n", serverName, t.mcpURL, bearer) +
		"# Claude Code has no CA setting: NODE_EXTRA_CA_CERTS makes this one process trust the Relay CA.\n" +
		fmt.Sprintf("# Run it from the directory that holds %s.\n", CAFileName) +
		fmt.Sprintf("NODE_EXTRA_CA_CERTS=\"$PWD/%s\" claude\n", CAFileName)

	var checkLine strings.Builder
	fmt.Fprintf(&checkLine, "curl -sS --cacert %s -H \"Authorization: %s\"", CAFileName, bearer)
	for _, h := range CheckHeaders {
		fmt.Fprintf(&checkLine, " -H \"%s\"", h)
	}
	fmt.Fprintf(&checkLine, " --data '%s' '%s'", CheckBody, t.mcpURL)
	check := checkLine.String()

	r := Rendering{
		mcpURL:     t.mcpURL,
		caPEM:      t.caPEM,
		claudeCode: &claudeCode,
		mcpJSON:    &mcpJSON,
		check:      &check,
	}
	if kind == accounts.KindMachine {
		gleipnir := fmt.Sprintf("MCP URL: %s\nAuthorization: %s\nCA certificate: %s\nClient name: gleipnir\n", t.mcpURL, bearer, CAFileName)
		r.gleipnir = &gleipnir
	}
	return r, nil
}

type mcpJSONFile struct {
	MCPServers map[string]mcpJSONServer `json:"mcpServers"`
}

type mcpJSONServer struct {
	Type    string            `json:"type"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
}

// encodeJSON indents by two spaces and leaves < > & unescaped so the
// URL reads as written.
func encodeJSON(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// Rendering is the Harness setup for one minted API Token. The blocks that embed
// the credential are held behind pointers and the type owns every fmt verb, so
// neither fmt, slog nor encoding/json can reach them, including when a Rendering
// sits in an unexported field.
type Rendering struct {
	mcpURL     string
	caPEM      string
	claudeCode *string
	mcpJSON    *string
	gleipnir   *string
	check      *string
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// MCPURL is the Relay's MCP endpoint.
func (r Rendering) MCPURL() string { return r.mcpURL }

// CACertificate is the PEM a client saves as relay-ca.pem. It is public.
func (r Rendering) CACertificate() string { return r.caPEM }

// ClaudeCode is the `claude mcp add` line and the line that trusts the CA. It
// embeds the credential.
func (r Rendering) ClaudeCode() string { return deref(r.claudeCode) }

// ClaudeCodeMCPJSON is the equivalent .mcp.json file. It embeds the credential.
func (r Rendering) ClaudeCodeMCPJSON() string { return deref(r.mcpJSON) }

// Gleipnir is the registration values for Gleipnir, or "" when the Account is not
// a machine Account. It embeds the credential.
func (r Rendering) Gleipnir() string { return deref(r.gleipnir) }

// Check is the one command that proves the connection works. It embeds the
// credential.
func (r Rendering) Check() string { return deref(r.check) }

// String renders only the MCP URL.
func (r Rendering) String() string {
	return "Rendering{mcp_url=" + r.mcpURL + " blocks=[REDACTED]}"
}

// GoString renders the same redacted text for %#v.
func (r Rendering) GoString() string { return r.String() }

// Format owns every verb, as enroll.Minted does.
func (r Rendering) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(r.String())) }

// LogValue implements slog.LogValuer. The group carries only the MCP URL.
func (r Rendering) LogValue() slog.Value {
	return slog.GroupValue(slog.String("mcp_url", r.mcpURL))
}

// MarshalJSON renders only the MCP URL.
func (r Rendering) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		MCPURL string `json:"mcp_url"`
	}{r.mcpURL})
}
