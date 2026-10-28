package relayconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"slices"
	"strings"
	"testing"
)

const secretValueText = "s3cr3t-VALUE-9f2"

const webhookSecretFile = minimal + "[approval]\nwebhook_url_file = \"/etc/relay/hook.url\"\nwebhook_secret_file = \"/etc/relay/hook.secret\"\n"

// readWebhookFiles reads the secret file as value and the URL file as a URL
// carrying it.
func readWebhookFiles(value string) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) {
		if strings.HasSuffix(path, ".url") {
			return []byte("https://hooks.example.internal/" + value + "\n"), nil
		}
		return []byte("  " + value + "\n"), nil
	}
}

// resolvedFileSecret loads the webhook files configuration and resolves both
// through an in-memory reader: the secret file holds value, the URL file a URL
// carrying it.
func resolvedFileSecret(t *testing.T, value string) Config {
	t.Helper()
	cfg := mustLoad(t, webhookSecretFile)
	if err := cfg.ResolveSecrets(readWebhookFiles(value)); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Proves RC-14.
func TestSecret_FileLoad(t *testing.T) {
	cfg := mustLoad(t, webhookSecretFile)
	s := cfg.Approval.WebhookSecret
	if s.Path() != "/etc/relay/hook.secret" {
		t.Fatalf("Path = %q", s.Path())
	}
	if _, ok := s.Reveal(); ok {
		t.Fatal("a file-backed secret reveals before it is resolved")
	}
	var asked []string
	read := readWebhookFiles(secretValueText)
	err := cfg.ResolveSecrets(func(path string) ([]byte, error) {
		asked = append(asked, path)
		return read(path)
	})
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := cfg.Approval.WebhookSecret.Reveal(); !ok || v != secretValueText {
		t.Fatalf("resolved Reveal = %q, %v", v, ok)
	}
	if want := []string{"/etc/relay/hook.url", "/etc/relay/hook.secret"}; !slices.Equal(asked, want) {
		t.Fatalf("read called for %v", asked)
	}

	t.Run("an empty file is refused naming the key", func(t *testing.T) {
		cfg := mustLoad(t, webhookSecretFile)
		err := cfg.ResolveSecrets(func(string) ([]byte, error) { return []byte(" \n"), nil })
		if err == nil || !strings.Contains(err.Error(), "approval.webhook_secret_file (line 9)") {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("a webhook URL file that fails the shape check is refused without echoing it", func(t *testing.T) {
		cfg := mustLoad(t, minimal+"[approval]\nwebhook_url_file = \"/etc/relay/hook.url\"\n")
		err := cfg.ResolveSecrets(func(string) ([]byte, error) { return []byte(secretValueText), nil })
		if err == nil || !strings.Contains(err.Error(), "approval.webhook_url_file (line 8)") {
			t.Fatalf("err = %v", err)
		}
		if strings.Contains(err.Error(), secretValueText) {
			t.Fatalf("error echoes the file content: %v", err)
		}
	})

	t.Run("a webhook URL file holding a URL resolves", func(t *testing.T) {
		cfg := mustLoad(t, minimal+"[approval]\nwebhook_url_file = \"/etc/relay/hook.url\"\n")
		err := cfg.ResolveSecrets(func(string) ([]byte, error) { return []byte("https://hooks.example.internal/x\n"), nil })
		if err != nil {
			t.Fatal(err)
		}
		if v, ok := cfg.Approval.WebhookURL.Reveal(); !ok || v != "https://hooks.example.internal/x" {
			t.Fatalf("Reveal = %q, %v", v, ok)
		}
	})
}

func TestResolveSecrets_ReaderErrorTextIsNeverPrinted(t *testing.T) {
	const leak = "LEAK-from-the-reader"
	cases := []struct {
		name   string
		err    error
		reason string
	}{
		{"missing", fmt.Errorf("%s: %w", leak, fs.ErrNotExist), "does not exist"},
		{"permission", fmt.Errorf("%s: %w", leak, fs.ErrPermission), "permission denied"},
		{"refused by the file check", errors.New(leak), "file check"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustLoad(t, webhookSecretFile)
			err := cfg.ResolveSecrets(func(string) ([]byte, error) { return nil, tc.err })
			if err == nil {
				t.Fatal("ResolveSecrets accepted a read error")
			}
			for _, rendered := range []string{err.Error(), fmt.Sprintf("%+v", err)} {
				if strings.Contains(rendered, leak) {
					t.Errorf("error prints the reader's text: %q", rendered)
				}
			}
			if !strings.Contains(err.Error(), tc.reason) || !strings.Contains(err.Error(), "approval.webhook_secret_file (line 9)") {
				t.Errorf("error = %q", err)
			}
			if errors.Is(err, tc.err) {
				t.Error("the reader's error is reachable through errors.Is")
			}
			var e *Error
			if errors.As(err, &e) && errors.Unwrap(e) != nil {
				t.Error("the Error unwraps to a cause")
			}
			for _, kind := range []error{fs.ErrNotExist, fs.ErrPermission} {
				if want := errors.Is(tc.err, kind); errors.Is(err, kind) != want {
					t.Errorf("errors.Is(err, %v) = %v, want %v", kind, !want, want)
				}
			}
		})
	}
}

// Proves RC-41.
func TestValidate_WebhookURLAndSecretOnlyFromFiles(t *testing.T) {
	cases := []struct{ name, body, key, fileKey string }{
		{"webhook url", "webhook_url = \"https://x.example/CANARY-v\"\n", "approval.webhook_url", "approval.webhook_url_file"},
		{"webhook secret", "webhook_url_file = \"/etc/relay/u\"\nwebhook_secret = \"CANARY-v\"\n", "approval.webhook_secret", "approval.webhook_secret_file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := loadErr(t, minimal+"[approval]\n"+tc.body)
			if !strings.Contains(got, tc.key+" (line") || !strings.Contains(got, tc.fileKey) {
				t.Fatalf("error does not name the key and point at the file form: %q", got)
			}
			if strings.Contains(got, "CANARY") {
				t.Fatalf("error echoes the value: %q", got)
			}
		})
	}

	cfg := resolvedFileSecret(t, secretValueText)
	if v, ok := cfg.Approval.WebhookSecret.Reveal(); !ok || v != secretValueText {
		t.Fatalf("secret Reveal = %q, %v", v, ok)
	}
	if v, ok := cfg.Approval.WebhookURL.Reveal(); !ok || v != "https://hooks.example.internal/"+secretValueText {
		t.Fatalf("url Reveal = %q, %v", v, ok)
	}
}

func TestSecret_NeverPrints(t *testing.T) {
	cfg := resolvedFileSecret(t, secretValueText)
	s := cfg.Approval.WebhookSecret
	if v, _ := s.Reveal(); v != secretValueText {
		t.Fatal("test setup: secret not revealed")
	}

	check := func(name, out string) {
		t.Helper()
		if strings.Contains(out, secretValueText) {
			t.Errorf("%s prints the secret: %q", name, out)
		}
		if !strings.Contains(out, "[redacted]") {
			t.Errorf("%s does not say [redacted]: %q", name, out)
		}
	}

	for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x", "%X", "%d"} {
		check("Sprintf("+verb+") of Secret", fmt.Sprintf(verb, s))
		check("Sprintf("+verb+") of Config", fmt.Sprintf(verb, cfg))
		check("Sprintf("+verb+") of *Config", fmt.Sprintf(verb, &cfg))
	}
	check("Sprint", fmt.Sprint(s))
	check("Sprintln", fmt.Sprintln(s, cfg))
	check("String", s.String())
	check("GoString", s.GoString())

	for name, mk := range map[string]func(*bytes.Buffer) slog.Handler{
		"text": func(b *bytes.Buffer) slog.Handler { return slog.NewTextHandler(b, nil) },
		"json": func(b *bytes.Buffer) slog.Handler { return slog.NewJSONHandler(b, nil) },
	} {
		var b bytes.Buffer
		l := slog.New(mk(&b))
		l.Info("loaded", "secret", s)
		check("slog "+name+" Secret", b.String())
		b.Reset()
		l.Info("loaded", "config", cfg)
		check("slog "+name+" Config", b.String())
		b.Reset()
		l.Info("loaded", slog.Any("config", &cfg))
		check("slog "+name+" *Config", b.String())
	}

	for name, v := range map[string]any{"Secret": s, "Config": cfg, "*Config": &cfg} {
		out, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		check("json "+name, string(out))
	}
	text, err := s.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	check("MarshalText", string(text))

	var unset Secret
	check("unset Secret", fmt.Sprintf("%v", unset))
}

func TestSecret_FileContentIsTrimmedAndEmptyRefused(t *testing.T) {
	cfg := resolvedFileSecret(t, secretValueText)
	if v, _ := cfg.Approval.WebhookSecret.Reveal(); v != secretValueText {
		t.Fatalf("Reveal = %q", v)
	}
	for _, blank := range []string{"", "   ", "\n"} {
		cfg := mustLoad(t, webhookSecretFile)
		err := cfg.ResolveSecrets(func(string) ([]byte, error) { return []byte(blank), nil })
		if err == nil || !strings.Contains(err.Error(), "approval.webhook_url_file (line 8)") || !strings.Contains(err.Error(), "the file is empty") {
			t.Errorf("blank %q: error = %v", blank, err)
		}
	}
}

func TestResolveSecrets_DoesNotChangeEarlierCopies(t *testing.T) {
	cfg := mustLoad(t, webhookSecretFile)
	before := cfg
	if err := cfg.ResolveSecrets(readWebhookFiles(secretValueText)); err != nil {
		t.Fatal(err)
	}
	if _, ok := before.Approval.WebhookSecret.Reveal(); ok {
		t.Fatal("a copy taken before ResolveSecrets reveals the value")
	}
	if v, ok := cfg.Approval.WebhookSecret.Reveal(); !ok || v != secretValueText {
		t.Fatalf("resolved Reveal = %q, %v", v, ok)
	}
}
