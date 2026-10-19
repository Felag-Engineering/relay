package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/hostfile"
	"github.com/Felag-Engineering/relay/relay/internal/relayconfig"
)

func writeConfigFile(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "relay.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// readSecretPlain reads a secret file without hostfile's check, which refuses every temporary
// directory a test can make; the check is approvalnotify.ReadSecretFile's, proven there and on
// the separate-uid harness.
func readSecretPlain(path string) ([]byte, error) { return os.ReadFile(path) }

// webhookURLSecret builds a relayconfig.Secret holding rawURL, the only way
// outside relayconfig to get one.
func webhookURLSecret(t *testing.T, rawURL string) relayconfig.Secret {
	t.Helper()
	sc, err := parseConfig([]byte(requiredTOML+"[approval]\nwebhook_url = \""+rawURL+"\"\n"), readSecretPlain)
	if err != nil {
		t.Fatal(err)
	}
	return sc.Config.ApprovalWebhookURL
}

const requiredTOML = `
[node_plane]
listen_address = "127.0.0.1:7654"
[ca]
dir = "/var/lib/relay/ca"
[store]
path = "/var/lib/relay/relay.db"
[tls]
hostname = "relay.example.test"
`

func TestFromFile_CarriesEverySetting(t *testing.T) {
	sc, err := parseConfig([]byte(`
[node_plane]
listen_address = "127.0.0.1:7001"
advertised_address = "relay.example.test:7002"
[control_plane]
enabled = true
listen_address = "127.0.0.1:9001"
[console]
enabled = true
session_max_age = "10h"
session_idle = "20m"
step_up_window = "3m"
[ca]
dir = "/srv/ca"
[store]
path = "/srv/relay.db"
[tls]
hostname = "relay.example.test"
[oauth]
issuer = "https://idp.example.test"
audience = "https://relay.example.test/mcp"
account_claim = "sub"
required_scope = "relay"
public_url = "https://relay.example.test"
[approval]
gate_rules_path = "/srv/gates.json"
webhook_url = "https://hooks.example.test/x"
webhook_secret = "signing-value"
webhook_timeout = "7s"
[reach]
read_blast_cap = 11
mutate_blast_cap = 3
dispatch_concurrency = 9
min_daemon_version = "1.2.3"
[enrollment]
ip_rate_per_minute = 21
ip_burst = 22
global_rate_per_minute = 23
global_burst = 24
max_tracked_ips = 25
max_nodes = 26
cert_expiring_fraction = 0.3
`), readSecretPlain)
	if err != nil {
		t.Fatal(err)
	}
	c := sc.Config
	if v := reflect.ValueOf(c); true {
		for i := range v.NumField() {
			if v.Field(i).IsZero() {
				t.Errorf("Config.%s is zero: fromFile does not carry a setting", v.Type().Field(i).Name)
			}
		}
	}

	want := Config{
		Addr: "127.0.0.1:7001", AdvertisedAddress: "relay.example.test:7002",
		ControlEnabled: true, ControlAddr: "127.0.0.1:9001",
		ConsoleEnabled: true, ConsoleSessionMaxAge: 10 * time.Hour, ConsoleSessionIdle: 20 * time.Minute, ConsoleStepUpWindow: 3 * time.Minute,
		CADir: "/srv/ca", StorePath: "/srv/relay.db", Hostname: "relay.example.test",
		OAuthIssuer: "https://idp.example.test", OAuthAudience: "https://relay.example.test/mcp",
		OAuthAccountClaim: "sub", OAuthRequiredScope: "relay", OAuthPublicURL: "https://relay.example.test",
		ApprovalGatePath:       "/srv/gates.json",
		ApprovalWebhookTimeout: 7 * time.Second,
		ReadBlastCap:           11, MutateBlastCap: 3, DispatchConcurrency: 9, MinDaemonVersion: "1.2.3",
		EnrollIPRate: 21, EnrollIPBurst: 22, EnrollGlobalRate: 23, EnrollGlobalBurst: 24,
		EnrollMaxTrackedIPs: 25, MaxNodes: 26, CertExpiringFraction: 0.3,
	}
	if got, ok := c.ApprovalWebhookSecret.Reveal(); !ok || got != "signing-value" {
		t.Errorf("webhook secret = %q, %v", got, ok)
	}
	if got, ok := c.ApprovalWebhookURL.Reveal(); !ok || got != "https://hooks.example.test/x" {
		t.Errorf("webhook URL = %q, %v", got, ok)
	}
	c.ApprovalWebhookSecret = relayconfig.Secret{}
	c.ApprovalWebhookURL = relayconfig.Secret{}
	if !reflect.DeepEqual(c, want) {
		t.Errorf("Config = %+v\nwant     %+v", c, want)
	}
}

func TestLoadConfig_MissingFileRefusedNamingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.toml")
	_, err := loadConfig(path)
	if err == nil || !strings.Contains(err.Error(), path) || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("err = %v, want one naming %s that satisfies fs.ErrNotExist", err, path)
	}
}

func TestLoadConfig_DirectoryRefused(t *testing.T) {
	dir := t.TempDir()
	_, err := loadConfig(dir)
	if err == nil || !strings.Contains(err.Error(), dir) {
		t.Errorf("err = %v, want a refusal naming %s", err, dir)
	}
}

func TestLoadConfig_UnreadableFileRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-0000 file")
	}
	path := writeConfigFile(t, requiredTOML)
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	_, err := loadConfig(path)
	if err == nil || !errors.Is(err, fs.ErrPermission) || !strings.Contains(err.Error(), path) {
		t.Errorf("err = %v, want a permission refusal naming %s", err, path)
	}
}

func TestLoadConfig_InvalidValueNamesKeyAndLineNotValue(t *testing.T) {
	_, err := parseConfig([]byte(requiredTOML+"[reach]\nread_blast_cap = 0\n"), readSecretPlain)
	if err == nil {
		t.Fatal("a zero blast cap was accepted")
	}
	if !strings.Contains(err.Error(), "reach.read_blast_cap") || !strings.Contains(err.Error(), "line") {
		t.Errorf("err = %v, want the key and a line", err)
	}
}

func TestLoadConfig_FileSecretsResolved(t *testing.T) {
	dir := t.TempDir()
	urlFile, secretFile := filepath.Join(dir, "url"), filepath.Join(dir, "secret")
	if err := os.WriteFile(urlFile, []byte("https://hooks.example.test/x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secretFile, []byte("signing-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sc, err := parseConfig([]byte(requiredTOML+"[approval]\nwebhook_url_file = \""+urlFile+"\"\nwebhook_secret_file = \""+secretFile+"\"\n"), readSecretPlain)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := sc.Config.ApprovalWebhookURL.Reveal(); !ok || got != "https://hooks.example.test/x" {
		t.Errorf("webhook URL = %q, %v", got, ok)
	}
	if got, ok := sc.Config.ApprovalWebhookSecret.Reveal(); !ok || got != "signing-value" {
		t.Errorf("webhook secret = %q, %v", got, ok)
	}
}

// A secret file the file check refuses refuses start, naming the key and the check's reason
// and never the file's content.
func TestLoadConfig_SecretFileRefusalNamesKey(t *testing.T) {
	secretFile := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secretFile, []byte("signing-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	refuse := func(p string) ([]byte, error) {
		if _, err := os.ReadFile(p); err != nil {
			return nil, err
		}
		return nil, &hostfile.Refusal{Path: p, Component: "secret", Clause: hostfile.ClauseReadableByOther}
	}
	_, err := parseConfig([]byte(requiredTOML+"[approval]\nwebhook_url = \"https://hooks.example.test/x\"\nwebhook_secret_file = \""+secretFile+"\"\n"), refuse)
	if err == nil {
		t.Fatal("a secret file the check refused was accepted")
	}
	for _, want := range []string{"approval.webhook_secret_file", "an account other than the Relay and root could read it"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "signing-value") || strings.Contains(err.Error(), "hooks.example.test") {
		t.Errorf("err carries a secret: %v", err)
	}
}

func TestLoadConfig_MissingSecretFileReasonIsPrecise(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	_, err := parseConfig([]byte(requiredTOML+"[approval]\nwebhook_url = \"https://hooks.example.test/x\"\nwebhook_secret_file = \""+missing+"\"\n"), readSecretPlain)
	if err == nil {
		t.Fatal("a missing secret file was accepted")
	}
	for _, want := range []string{"the file does not exist", "approval.webhook_secret_file"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want it to contain %q", err, want)
		}
	}
}

func TestParseArgs(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
		err  bool
	}{
		{name: "default", want: relayconfig.DefaultPath},
		{name: "--config x", args: []string{"--config", "x"}, want: "x"},
		{name: "-config=x", args: []string{"-config=x"}, want: "x"},
		{name: "unknown flag", args: []string{"--addr", "S3CR3T"}, err: true},
		{name: "positional", args: []string{"S3CR3T"}, err: true},
		{name: "empty config", args: []string{"--config", ""}, err: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			got, err := parseArgs(tc.args, &out)
			if (err != nil) != tc.err {
				t.Fatalf("err = %v, want error: %v", err, tc.err)
			}
			if got != tc.want {
				t.Errorf("path = %q, want %q", got, tc.want)
			}
			if strings.Contains(out.String(), "S3CR3T") {
				t.Errorf("output echoes an argument value: %s", out.String())
			}
		})
	}

	t.Run("--help", func(t *testing.T) {
		var out bytes.Buffer
		if _, err := parseArgs([]string{"--help"}, &out); !errors.Is(err, flag.ErrHelp) {
			t.Errorf("err = %v, want flag.ErrHelp", err)
		}
		if !strings.Contains(out.String(), "--config") {
			t.Errorf("help = %q", out.String())
		}
	})
}

func TestNewLogHandler_FormatAndLevel(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(newLogHandler(&buf, relayconfig.Log{Level: slog.LevelWarn, Format: relayconfig.LogJSON}))
	log.Info("quiet")
	log.Warn("loud")
	out := buf.String()
	if strings.Contains(out, "quiet") || !strings.Contains(out, `"msg":"loud"`) {
		t.Errorf("json/warn output = %q", out)
	}

	buf.Reset()
	log = slog.New(newLogHandler(io.Writer(&buf), relayconfig.Log{Level: slog.LevelInfo, Format: relayconfig.LogText}))
	log.Info("shown")
	if !strings.Contains(buf.String(), "msg=shown") {
		t.Errorf("text output = %q", buf.String())
	}
}
