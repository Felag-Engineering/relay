package harnesssetup_test

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/harnesssetup"
)

const (
	testPEM   = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
	testToken = "glp_" + "0123456789abcdef" + "." + "AbC-_xyz0123456789"

	// otherBlockType is a PEM type that is not CERTIFICATE. The block is built
	// from it, not written out, so no key-shaped literal sits in the source.
	otherBlockType = "OTHER DATA"
)

var otherBlock = string(pem.EncodeToMemory(&pem.Block{Type: otherBlockType, Bytes: []byte("not a certificate")}))

func mustTarget(t *testing.T, advertised, listen string) harnesssetup.Target {
	t.Helper()
	target, err := harnesssetup.NewTarget(advertised, listen, []byte(testPEM))
	if err != nil {
		t.Fatalf("NewTarget(%q, %q): %v", advertised, listen, err)
	}
	return target
}

func mustRender(t *testing.T, target harnesssetup.Target, kind accounts.Kind) harnesssetup.Rendering {
	t.Helper()
	r, err := target.Render(testToken, kind)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return r
}

func TestNewTarget_URLIsTheAdvertisedHostOnTheControlPort(t *testing.T) {
	tests := []struct {
		name, advertised, listen, want string
	}{
		{"dns name", "relay.example:7654", "0.0.0.0:9443", "https://relay.example:9443/mcp"},
		{"ipv4", "192.0.2.7:7654", "0.0.0.0:9443", "https://192.0.2.7:9443/mcp"},
		{"ipv6", "[2001:db8::1]:7654", "[::]:9443", "https://[2001:db8::1]:9443/mcp"},
		{"port zero", "relay.example:7654", "127.0.0.1:0", "https://relay.example:0/mcp"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := mustRender(t, mustTarget(t, tc.advertised, tc.listen), accounts.KindHuman).MCPURL()
			if got != tc.want {
				t.Errorf("MCPURL() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNewTarget_RefusesAMalformedTarget(t *testing.T) {
	tests := []struct {
		name, advertised, listen, pem string
	}{
		{"no port in the advertised address", "relay.example", "0.0.0.0:9443", testPEM},
		{"empty host", ":7654", "0.0.0.0:9443", testPEM},
		{"host with a quote", "re'lay.example:7654", "0.0.0.0:9443", testPEM},
		{"host with a space", "re lay.example:7654", "0.0.0.0:9443", testPEM},
		{"ipv6 zone", "[fe80::1%eth0]:7654", "[::]:9443", testPEM},
		{"no control port", "relay.example:7654", "0.0.0.0", testPEM},
		{"empty control port", "relay.example:7654", "0.0.0.0:", testPEM},
		{"non-digit control port", "relay.example:7654", "0.0.0.0:http", testPEM},
		{"empty CA", "relay.example:7654", "0.0.0.0:9443", ""},
		{"non-PEM CA", "relay.example:7654", "0.0.0.0:9443", "not a certificate"},
		{"certificate then another block type", "relay.example:7654", "0.0.0.0:9443", testPEM + otherBlock},
		{"certificate then trailing bytes", "relay.example:7654", "0.0.0.0:9443", testPEM + "trailing"},
		{"another block type alone", "relay.example:7654", "0.0.0.0:9443", otherBlock},
		{"text before the certificate", "relay.example:7654", "0.0.0.0:9443", "note\n" + testPEM},
		{"text between two certificates", "relay.example:7654", "0.0.0.0:9443", testPEM + "note\n" + testPEM},
		{"undecodable block then a certificate", "relay.example:7654", "0.0.0.0:9443",
			"-----BEGIN " + otherBlockType + "-----\n!!!not base64!!!\n-----END " + otherBlockType + "-----\n" + testPEM},
		{"undecodable certificate block", "relay.example:7654", "0.0.0.0:9443",
			"-----BEGIN CERTIFICATE-----\n!!!not base64!!!\n-----END CERTIFICATE-----\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := harnesssetup.NewTarget(tc.advertised, tc.listen, []byte(tc.pem))
			if !errors.Is(err, harnesssetup.ErrTarget) {
				t.Errorf("err = %v, want ErrTarget", err)
			}
		})
	}
}

func TestRender_ZeroTargetRendersNothing(t *testing.T) {
	_, err := harnesssetup.Target{}.Render(testToken, accounts.KindMachine)
	if !errors.Is(err, harnesssetup.ErrNoTarget) {
		t.Errorf("err = %v, want ErrNoTarget", err)
	}
}

func TestRender_GleipnirOnlyForAMachineAccount(t *testing.T) {
	target := mustTarget(t, "relay.example:7654", "0.0.0.0:9443")
	if got := mustRender(t, target, accounts.KindMachine).Gleipnir(); !strings.Contains(got, testToken) {
		t.Errorf("machine Gleipnir() = %q, want it to carry the token", got)
	}
	for _, kind := range []accounts.Kind{accounts.KindHuman, ""} {
		if got := mustRender(t, target, kind).Gleipnir(); got != "" {
			t.Errorf("Gleipnir() for kind %q = %q, want empty", kind, got)
		}
	}
}

func TestRender_ClaudeCodeCarriesTheHeaderAndTheTrustLine(t *testing.T) {
	r := mustRender(t, mustTarget(t, "relay.example:7654", "0.0.0.0:9443"), accounts.KindHuman)
	want := `claude mcp add --transport http relay 'https://relay.example:9443/mcp' --header "Authorization: Bearer ` + testToken + `"` + "\n" +
		"# Claude Code has no CA setting: NODE_EXTRA_CA_CERTS makes this one process trust the Relay CA.\n" +
		"# Run it from the directory that holds relay-ca.pem.\n" +
		`NODE_EXTRA_CA_CERTS="$PWD/relay-ca.pem" claude` + "\n"
	if got := r.ClaudeCode(); got != want {
		t.Errorf("ClaudeCode() =\n%s\nwant\n%s", got, want)
	}
	if got := r.CACertificate(); got != testPEM {
		t.Errorf("CACertificate() = %q, want the PEM as given", got)
	}
}

func TestRender_JSONBlocksParseAndCarryTheBearerHeader(t *testing.T) {
	r := mustRender(t, mustTarget(t, "relay.example:7654", "0.0.0.0:9443"), accounts.KindHuman)
	bearer := "Bearer " + testToken

	var code struct {
		MCPServers map[string]struct {
			Type    string            `json:"type"`
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(r.ClaudeCodeMCPJSON()), &code); err != nil {
		t.Fatalf(".mcp.json does not parse: %v", err)
	}
	srv := code.MCPServers["relay"]
	if srv.Type != "http" || srv.URL != r.MCPURL() || srv.Headers["Authorization"] != bearer {
		t.Errorf(".mcp.json server = %+v, want http, %q and the bearer header", srv, r.MCPURL())
	}
}

func TestRender_CheckIsTheCurlOverCheckBody(t *testing.T) {
	r := mustRender(t, mustTarget(t, "relay.example:7654", "0.0.0.0:9443"), accounts.KindHuman)
	want := `curl -sS --cacert relay-ca.pem -H "Authorization: Bearer ` + testToken + `"` +
		` -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream"` +
		` --data '` + harnesssetup.CheckBody + `' 'https://relay.example:9443/mcp'`
	if got := r.Check(); got != want {
		t.Errorf("Check() =\n%s\nwant\n%s", got, want)
	}
	for _, h := range harnesssetup.CheckHeaders {
		if !strings.Contains(r.Check(), h) {
			t.Errorf("Check() lacks header %q", h)
		}
	}
}

func TestRender_ShellLinesSingleQuoteAnIPv6URL(t *testing.T) {
	r := mustRender(t, mustTarget(t, "[2001:db8::1]:7654", "[::]:9443"), accounts.KindHuman)
	const url = "https://[2001:db8::1]:9443/mcp"
	if !strings.Contains(r.ClaudeCode(), "relay '"+url+"' --header") {
		t.Errorf("ClaudeCode() does not single-quote the URL:\n%s", r.ClaudeCode())
	}
	if !strings.HasSuffix(r.Check(), "'"+url+"'") {
		t.Errorf("Check() does not end with the single-quoted URL:\n%s", r.Check())
	}
	for name, line := range map[string]string{"ClaudeCode": r.ClaudeCode(), "Check": r.Check()} {
		if strings.Count(line, url) != strings.Count(line, "'"+url+"'") {
			t.Errorf("%s has the URL unquoted:\n%s", name, line)
		}
	}
}

func TestRender_RefusesACredentialOutsideTheTokenAlphabet(t *testing.T) {
	target := mustTarget(t, "relay.example:7654", "0.0.0.0:9443")
	for name, credential := range map[string]string{
		"double quote":   `glp_ab"cd.efgh`,
		"single quote":   `glp_ab'cd.efgh`,
		"space":          "glp_ab cd.efgh",
		"command subst":  "glp_ab$(id).efgh",
		"newline":        "glp_abcd.ef\ngh",
		"missing prefix": "abcd.efgh",
		"empty":          "",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := target.Render(credential, accounts.KindMachine)
			if !errors.Is(err, harnesssetup.ErrCredential) {
				t.Fatalf("err = %v, want ErrCredential", err)
			}
			if credential != "" && strings.Contains(err.Error(), credential) {
				t.Errorf("error text %q contains the credential", err.Error())
			}
		})
	}
}

func TestRendering_RedactsUnderEveryVerbLogAndJSON(t *testing.T) {
	r := mustRender(t, mustTarget(t, "relay.example:7654", "0.0.0.0:9443"), accounts.KindMachine)
	holder := struct{ r harnesssetup.Rendering }{r}

	var rendered []string
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%d"} {
		rendered = append(rendered, fmt.Sprintf(verb, r), fmt.Sprintf(verb, holder), fmt.Sprintf(verb, &r))
	}

	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("minted", "setup", r, "holder", holder)
	rendered = append(rendered, logs.String())

	marshaled, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	rendered = append(rendered, string(marshaled))
	if marshaled, err = json.Marshal(struct{ R harnesssetup.Rendering }{r}); err != nil {
		t.Fatal(err)
	}
	rendered = append(rendered, string(marshaled))

	for _, out := range rendered {
		if strings.Contains(out, testToken) || strings.Contains(out, "glp_") {
			t.Errorf("output leaks the token: %s", out)
		}
	}
	if !strings.Contains(fmt.Sprint(r), r.MCPURL()) || !strings.Contains(logs.String(), r.MCPURL()) {
		t.Error("the redaction does not carry the MCP URL")
	}
}
