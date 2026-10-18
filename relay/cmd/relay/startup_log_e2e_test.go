package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStartupLog_CarriesNoWebhookURLOrSecret(t *testing.T) {
	const (
		urlValue    = "https://hooks.example.test/T0K3N-path"
		secretValue = "s3cr3t-signing-value"
	)
	banned := []string{"hooks.example.test", "T0K3N-path", secretValue}

	run := func(t *testing.T, approval string) string {
		t.Helper()
		addr, err := freeLoopbackAddr()
		if err != nil {
			t.Fatal(err)
		}
		path := writeRelayTOML(t, minimalTOML(t, addr)+"\n[approval]\n"+approval)
		cmd, buf := runRelayMain(t, nil, "--config", path)
		waitListening(t, cmd, buf)
		return buf.String()
	}
	checkClean := func(t *testing.T, out string) {
		t.Helper()
		if !strings.Contains(out, "approval webhook enabled") || !strings.Contains(out, "signed=true") {
			t.Errorf("startup log lacks the enabled/signed line:\n%s", out)
		}
		for _, b := range banned {
			if strings.Contains(out, b) {
				t.Errorf("startup log carries %q:\n%s", b, out)
			}
		}
	}

	t.Run("inline", func(t *testing.T) {
		checkClean(t, run(t, "webhook_url = \""+urlValue+"\"\nwebhook_secret = \""+secretValue+"\"\n"))
	})

	t.Run("file", func(t *testing.T) {
		dir := t.TempDir()
		urlFile, secretFile := filepath.Join(dir, "url"), filepath.Join(dir, "secret")
		if err := os.WriteFile(urlFile, []byte(urlValue+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(secretFile, []byte(secretValue+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		checkClean(t, run(t, "webhook_url_file = \""+urlFile+"\"\nwebhook_secret_file = \""+secretFile+"\"\n"))
	})

	t.Run("refusal", func(t *testing.T) {
		path := writeRelayTOML(t, minimalTOML(t, "127.0.0.1:0")+
			"\n[approval]\nwebhook_url = \"http://hooks.example.test/T0K3N-path\"\n")
		cmd, buf := runRelayMain(t, nil, "--config", path)
		if code := exitCode(t, cmd); code == 0 {
			t.Fatalf("a plaintext off-host webhook URL started the Relay:\n%s", buf.String())
		}
		for _, b := range banned {
			if strings.Contains(buf.String(), b) {
				t.Errorf("refusal carries %q:\n%s", b, buf.String())
			}
		}
	})
}
