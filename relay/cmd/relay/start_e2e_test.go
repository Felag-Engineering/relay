//go:build integration

package main

// The shippable binary's start, on the separate-uid harness (relaytest.RelayLayout): every
// test here starts the real Relay as relaytest over root-owned fixtures, because the
// start-time file check (ADR-0043, RC-15 to RC-17) refuses any file the Relay's own uid could
// write — which every file a test writes as itself is. Runs under make test-integration
// (RELAY_SHIPPABLE_BIN); without the separate uid each test records a skip in make verify's
// skip ledger and skips, and under RELAY_E2E_SUDO_REQUIRED=1 it fails.

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

const integrationGate = "test-integration"

// shippableLayout returns the shippable binary's root-owned installed path and a fresh layout.
func shippableLayout(t *testing.T) (string, *relaytest.RelayLayout) {
	t.Helper()
	bin := os.Getenv("RELAY_SHIPPABLE_BIN")
	if bin == "" {
		relaytest.SkipMissingBin(t, "RELAY_SHIPPABLE_BIN not set; skipping a shippable-binary start test (run via make test-integration)")
	}
	layout := relaytest.NewRelayLayout(t, integrationGate)
	return layout.InstallBinary(t, bin), layout
}

// layoutTOML is the smallest configuration the Relay starts from, its CA directory and store
// in the layout's state directory, followed by extra.
func layoutTOML(layout *relaytest.RelayLayout, addr, extra string) string {
	return fmt.Sprintf("[node_plane]\nlisten_address = %q\n\n[ca]\ndir = %q\n\n[store]\npath = %q\n\n[tls]\nhostname = \"localhost\"\n%s",
		addr, filepath.Join(layout.StateDir(), "ca"), filepath.Join(layout.StateDir(), "relay.db"), extra)
}

// freeLoopbackAddr binds 127.0.0.1:0, reads the OS-assigned port, and closes
// the listener, returning the address string for a subprocess to bind next.
// The window between close and the subprocess's bind is inherent and small;
// startRelaySubprocess retries on a fresh port to absorb it.
func freeLoopbackAddr() (string, error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer lis.Close()
	return lis.Addr().String(), nil
}

func freeAddr(t *testing.T) string {
	t.Helper()
	addr, err := freeLoopbackAddr()
	if err != nil {
		t.Fatal(err)
	}
	return addr
}

// startShippable starts bin through layout with args.
func startShippable(t *testing.T, layout *relaytest.RelayLayout, bin string, args ...string) *relaytest.RelayProcess {
	t.Helper()
	proc, err := layout.Start(t, bin, relaySubprocessEnv(), args...)
	if err != nil {
		t.Fatal(err)
	}
	return proc
}

// refusedStart starts bin on cfg and returns its output once it has exited non-zero without
// ever listening.
func refusedStart(t *testing.T, layout *relaytest.RelayLayout, bin, cfg string) string {
	t.Helper()
	proc, err := layout.Start(t, bin, relaySubprocessEnv(), "--config", cfg)
	if err != nil {
		// A refusal can end the Relay before the harness finds its pid; the error carries the
		// log, and the caller's wanted refusal text is what tells it from a failed drop.
		out := err.Error()
		if strings.Contains(out, "relay listening") {
			t.Fatalf("relay listened before refusing\n%s", out)
		}
		return out
	}
	select {
	case <-proc.Done():
	case <-time.After(10 * time.Second):
		t.Fatalf("relay did not exit within 10s; the start-time check did not refuse\n%s", proc.Log())
	}
	out := proc.Log()
	if proc.Err() == nil {
		t.Fatalf("relay exited 0\n%s", out)
	}
	if strings.Contains(out, "relay listening") {
		t.Fatalf("relay listened before refusing\n%s", out)
	}
	return out
}

func wantInOutput(t *testing.T, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
}

// Proves RC-12.
func TestMain_ConfigFlagHonoured(t *testing.T) {
	for _, form := range []string{"--config", "-config="} {
		t.Run(form, func(t *testing.T) {
			bin, layout := shippableLayout(t)
			cfg := layout.WriteConfig(t, layoutTOML(layout, freeAddr(t), ""))
			args := []string{"--config", cfg}
			if strings.HasSuffix(form, "=") {
				args = []string{form + cfg}
			}
			proc := startShippable(t, layout, bin, args...)
			waitForRelayLog(t, proc, "relay listening")

			// Stat fails the test if either is absent.
			layout.Stat(t, filepath.Join(layout.StateDir(), "ca", "ca-cert.pem"))
			layout.Stat(t, filepath.Join(layout.StateDir(), "relay.db"))
		})
	}
}

// Proves RC-20.
func TestMain_CoherentButSuspectConfigStartsWithWarning(t *testing.T) {
	bin, layout := shippableLayout(t)
	cfg := layout.WriteConfig(t, layoutTOML(layout, freeAddr(t), "\n[reach]\nread_blast_cap = 2\nmutate_blast_cap = 5\n"))
	proc := startShippable(t, layout, bin, "--config", cfg)
	waitForRelayLog(t, proc, "relay listening")

	out := proc.Log()
	warnAt := -1
	offset := 0
	for _, line := range strings.SplitAfter(out, "\n") {
		if warnAt < 0 && strings.Contains(line, `"level":"WARN"`) && strings.Contains(line, "mutate_blast_cap") {
			warnAt = offset
		}
		offset += len(line)
	}
	if warnAt < 0 {
		t.Fatalf("no warning line naming mutate_blast_cap:\n%s", out)
	}
	if warnAt > strings.Index(out, "relay listening") {
		t.Errorf("the warning does not precede 'relay listening':\n%s", out)
	}
}

const (
	webhookURLValue    = "https://hooks.example.test/T0K3N-path"
	webhookSecretValue = "s3cr3t-signing-value"
)

// bannedSecrets is every fragment of the webhook URL and secret RC-18 keeps off every output.
var bannedSecrets = []string{"hooks.example.test", "T0K3N-path", webhookSecretValue}

func wantNoSecret(t *testing.T, out string) {
	t.Helper()
	for _, b := range bannedSecrets {
		if strings.Contains(out, b) {
			t.Errorf("output carries %q:\n%s", b, out)
		}
	}
}

// Proves RC-14.
func TestStartupLog_CarriesNoWebhookURLOrSecret(t *testing.T) {
	run := func(t *testing.T, approval func(layout *relaytest.RelayLayout) string) string {
		t.Helper()
		bin, layout := shippableLayout(t)
		cfg := layout.WriteConfig(t, layoutTOML(layout, freeAddr(t), "\n[approval]\n"+approval(layout)))
		proc := startShippable(t, layout, bin, "--config", cfg)
		waitForRelayLog(t, proc, "relay listening")
		return proc.Log()
	}
	checkClean := func(t *testing.T, out string) {
		t.Helper()
		wantInOutput(t, out, "approval webhook enabled", `"signed":true`)
		wantNoSecret(t, out)
	}

	t.Run("file", func(t *testing.T) {
		checkClean(t, run(t, func(layout *relaytest.RelayLayout) string {
			urlFile := layout.WriteFile(t, "webhook-url", webhookURLValue+"\n", "root", relaytest.TestUser, "0640")
			secretFile := layout.WriteFile(t, "webhook-secret", webhookSecretValue+"\n", "root", relaytest.TestUser, "0640")
			return "webhook_url_file = \"" + urlFile + "\"\nwebhook_secret_file = \"" + secretFile + "\"\n"
		}))
	})

	t.Run("refusal", func(t *testing.T) {
		bin, layout := shippableLayout(t)
		urlFile := layout.WriteFile(t, "webhook-url", "http://hooks.example.test/T0K3N-path\n", "root", relaytest.TestUser, "0640")
		cfg := layout.WriteConfig(t, layoutTOML(layout, freeAddr(t), "\n[approval]\nwebhook_url_file = \""+urlFile+"\"\n"))
		wantNoSecret(t, refusedStart(t, layout, bin, cfg))
	})
}

// TestStart_RefusesConfigWritableByRelay is RC-15's could-write clauses on the configuration
// file: owned by the Relay on a writable filesystem, or group-writable by the Relay's group.
func TestStart_RefusesConfigWritableByRelay(t *testing.T) {
	for _, tc := range []struct {
		name, owner, group, mode, want string
	}{
		{"owned by the Relay", relaytest.TestUser, relaytest.TestUser, "0640", "the Relay owns it on a filesystem mounted writable"},
		{"group-writable by the Relay's group", "root", relaytest.TestUser, "0660", "grants the Relay, or one of its groups, write"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin, layout := shippableLayout(t)
			cfg := layout.WriteFile(t, "relay.toml", layoutTOML(layout, freeAddr(t), ""), tc.owner, tc.group, tc.mode)
			wantInOutput(t, refusedStart(t, layout, bin, cfg), cfg, tc.want)
		})
	}
}

// TestStart_RefusesConfigOwnedByTestUser: a configuration file the test's own uid owns, as a
// file a developer writes and a test writes always is, refuses the shippable binary.
func TestStart_RefusesConfigOwnedByTestUser(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("as root the test's own files are root's, which the Relay may read")
	}
	bin, layout := shippableLayout(t)
	me := strconv.Itoa(os.Getuid())
	cfg := layout.WriteFile(t, "relay.toml", layoutTOML(layout, freeAddr(t), ""), me, relaytest.TestUser, "0640")
	wantInOutput(t, refusedStart(t, layout, bin, cfg), cfg, "an account other than the Relay and root could read it")
}

// TestStart_RefusesSecretReadableByOthers is RC-15's could-read clause on a secret file the
// configuration names, and on the configuration file itself: readable by an account other
// than the Relay and root refuses start, and the refusal carries no secret.
func TestStart_RefusesSecretReadableByOthers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(t *testing.T, layout *relaytest.RelayLayout) (cfg, refused string)
	}{
		{"world-readable secret file", func(t *testing.T, layout *relaytest.RelayLayout) (string, string) {
			urlFile := layout.WriteFile(t, "webhook-url", webhookURLValue+"\n", "root", relaytest.TestUser, "0640")
			secret := layout.WriteFile(t, "webhook-secret", webhookSecretValue+"\n", "root", relaytest.TestUser, "0644")
			return layout.WriteConfig(t, layoutTOML(layout, freeAddr(t),
				"\n[approval]\nwebhook_url_file = \""+urlFile+"\"\nwebhook_secret_file = \""+secret+"\"\n")), secret
		}},
		{"secret file readable by a group other accounts share", func(t *testing.T, layout *relaytest.RelayLayout) (string, string) {
			urlFile := layout.WriteFile(t, "webhook-url", webhookURLValue+"\n", "root", relaytest.TestUser, "0640")
			secret := layout.WriteFile(t, "webhook-secret", webhookSecretValue+"\n", "root", relaytest.TestIOGroup, "0640")
			return layout.WriteConfig(t, layoutTOML(layout, freeAddr(t),
				"\n[approval]\nwebhook_url_file = \""+urlFile+"\"\nwebhook_secret_file = \""+secret+"\"\n")), secret
		}},
		{"world-readable configuration file", func(t *testing.T, layout *relaytest.RelayLayout) (string, string) {
			cfg := layout.WriteFile(t, "relay.toml", layoutTOML(layout, freeAddr(t), ""), "root", relaytest.TestUser, "0644")
			return cfg, cfg
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin, layout := shippableLayout(t)
			cfg, refused := tc.write(t, layout)
			out := refusedStart(t, layout, bin, cfg)
			wantInOutput(t, out, refused)
			wantNoSecret(t, out)
		})
	}
}

// TestStart_RefusesSymlinkedConfig is RC-16: a path that is a symbolic link is refused, for
// the configuration file and for a file it names, even when the link's target would pass.
func TestStart_RefusesSymlinkedConfig(t *testing.T) {
	t.Run("configuration file", func(t *testing.T) {
		bin, layout := shippableLayout(t)
		real := layout.WriteConfig(t, layoutTOML(layout, freeAddr(t), ""))
		link := layout.Symlink(t, real, "relay-link.toml")
		wantInOutput(t, refusedStart(t, layout, bin, link), "a symbolic link is on the path")
	})
}

// TestStart_RefusesGateRulesPath is RC-37 on the shippable binary: a configuration naming
// approval.gate_rules_path is refused at start, naming the key, and never the path.
func TestStart_RefusesGateRulesPath(t *testing.T) {
	bin, layout := shippableLayout(t)
	cfg := layout.WriteConfig(t, layoutTOML(layout, freeAddr(t), "\n[approval]\ngate_rules_path = \"/etc/relay/CANARY.json\"\n"))
	out := refusedStart(t, layout, bin, cfg)
	wantInOutput(t, out, "approval.gate_rules_path")
	if strings.Contains(out, "CANARY") {
		t.Errorf("the refusal echoes the path:\n%s", out)
	}
}

// TestStart_RefusesMalformedGateRule is AP-8 and AP-81 on the shippable binary: a gate rule
// naming a field a rule no longer has refuses start, naming the field; the Relay never runs
// ungated because its rules did not load.
func TestStart_RefusesMalformedGateRule(t *testing.T) {
	bin, layout := shippableLayout(t)
	cfg := layout.WriteConfig(t, layoutTOML(layout, freeAddr(t), "\n[[approval.rules]]\nname = \"CANARY\"\ncount = 1\n"))
	out := refusedStart(t, layout, bin, cfg)
	wantInOutput(t, out, "approval.rules.count")
	if strings.Contains(out, "CANARY") {
		t.Errorf("the refusal echoes a rule name:\n%s", out)
	}
}

// TestStart_RefusesGroupReadableStateOrKey is RC-17 on the shippable binary: the CA directory,
// the CA private key and the store's directory are the Relay's alone, or start is refused.
func TestStart_RefusesGroupReadableStateOrKey(t *testing.T) {
	const refusal = "generated material grants access to an account other than the Relay"

	t.Run("CA directory", func(t *testing.T) {
		bin, layout := shippableLayout(t)
		layout.MakeStateDir(t, "ca", "0750")
		cfg := layout.WriteConfig(t, layoutTOML(layout, freeAddr(t), ""))
		wantInOutput(t, refusedStart(t, layout, bin, cfg), "CA directory", refusal)
	})

	t.Run("CA private key", func(t *testing.T) {
		bin, layout := shippableLayout(t)
		cfg := layout.WriteConfig(t, layoutTOML(layout, freeAddr(t), ""))
		proc := startShippable(t, layout, bin, "--config", cfg)
		waitForRelayLog(t, proc, "relay listening")
		if err := proc.Kill(); err != nil {
			t.Fatal(err)
		}
		<-proc.Done()
		layout.ChmodState(t, filepath.Join(layout.StateDir(), "ca", "ca-key.pem"), "0640")
		wantInOutput(t, refusedStart(t, layout, bin, cfg), "ca-key.pem", refusal)
	})

	t.Run("store directory", func(t *testing.T) {
		bin, layout := shippableLayout(t)
		store := layout.MakeStateDir(t, "store", "0750")
		cfg := layout.WriteConfig(t, fmt.Sprintf(
			"[node_plane]\nlisten_address = %q\n\n[ca]\ndir = %q\n\n[store]\npath = %q\n\n[tls]\nhostname = \"localhost\"\n",
			freeAddr(t), filepath.Join(layout.StateDir(), "ca"), filepath.Join(store, "relay.db")))
		wantInOutput(t, refusedStart(t, layout, bin, cfg), "store directory", refusal)
	})
}

// TestRefusals_CarryNoSecretOrWebhookURL is RC-18 on refusal messages: whichever check refuses
// start, with the webhook URL and secret present in files, no refusal carries either.
func TestRefusals_CarryNoSecretOrWebhookURL(t *testing.T) {
	// files places the webhook URL and secret in files the check accepts and returns the
	// [approval] section naming them.
	files := func(t *testing.T, layout *relaytest.RelayLayout) string {
		urlFile := layout.WriteFile(t, "webhook-url", webhookURLValue+"\n", "root", relaytest.TestUser, "0640")
		secretFile := layout.WriteFile(t, "webhook-secret", webhookSecretValue+"\n", "root", relaytest.TestUser, "0640")
		return "\n[approval]\nwebhook_url_file = \"" + urlFile + "\"\nwebhook_secret_file = \"" + secretFile + "\"\n"
	}
	for _, tc := range []struct {
		name  string
		want  string // the refusal, so no case passes on some earlier one
		write func(t *testing.T, layout *relaytest.RelayLayout) string
	}{
		{"an invalid value beside webhook files", "reach.read_blast_cap", func(t *testing.T, layout *relaytest.RelayLayout) string {
			return layout.WriteConfig(t, layoutTOML(layout, freeAddr(t), files(t, layout)+"\n[reach]\nread_blast_cap = 0\n"))
		}},
		{"a malformed line beside webhook files", "line 1", func(t *testing.T, layout *relaytest.RelayLayout) string {
			return layout.WriteConfig(t, layoutTOML(layout, freeAddr(t), files(t, layout)+"\n[log]\nlevel = \""+webhookSecretValue+"\n"))
		}},
		{"an inline webhook URL is refused naming the key, never the value", "approval.webhook_url", func(t *testing.T, layout *relaytest.RelayLayout) string {
			return layout.WriteConfig(t, layoutTOML(layout, freeAddr(t), "\n[approval]\nwebhook_url = \""+webhookURLValue+"\"\n"))
		}},
		{"a plaintext off-host webhook URL", "plaintext http to a non-loopback host", func(t *testing.T, layout *relaytest.RelayLayout) string {
			urlFile := layout.WriteFile(t, "webhook-url", "http://hooks.example.test/T0K3N-path\n", "root", relaytest.TestUser, "0640")
			secretFile := layout.WriteFile(t, "webhook-secret", webhookSecretValue+"\n", "root", relaytest.TestUser, "0640")
			return layout.WriteConfig(t, layoutTOML(layout, freeAddr(t),
				"\n[approval]\nwebhook_url_file = \""+urlFile+"\"\nwebhook_secret_file = \""+secretFile+"\"\n"))
		}},
		{"a webhook URL file holding no URL", "approval.webhook_url_file", func(t *testing.T, layout *relaytest.RelayLayout) string {
			f := layout.WriteFile(t, "webhook-url", webhookSecretValue+"\n", "root", relaytest.TestUser, "0640")
			return layout.WriteConfig(t, layoutTOML(layout, freeAddr(t), "\n[approval]\nwebhook_url_file = \""+f+"\"\n"))
		}},
		{"a configuration file the check refuses", "the Relay owns it on a filesystem mounted writable", func(t *testing.T, layout *relaytest.RelayLayout) string {
			return layout.WriteFile(t, "relay.toml", layoutTOML(layout, freeAddr(t), files(t, layout)), relaytest.TestUser, relaytest.TestUser, "0600")
		}},
		{"a secret file the check refuses", "the Relay owns it on a filesystem mounted writable", func(t *testing.T, layout *relaytest.RelayLayout) string {
			f := layout.WriteFile(t, "webhook-url", webhookURLValue+"\n", relaytest.TestUser, relaytest.TestUser, "0600")
			g := layout.WriteFile(t, "webhook-secret", webhookSecretValue+"\n", "root", relaytest.TestUser, "0640")
			return layout.WriteConfig(t, layoutTOML(layout, freeAddr(t),
				"\n[approval]\nwebhook_url_file = \""+f+"\"\nwebhook_secret_file = \""+g+"\"\n"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin, layout := shippableLayout(t)
			out := refusedStart(t, layout, bin, tc.write(t, layout))
			wantInOutput(t, out, tc.want)
			wantNoSecret(t, out)
		})
	}
}
