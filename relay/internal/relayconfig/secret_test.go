package relayconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"
	"testing"
)

const secretValueText = "s3cr3t-VALUE-9f2"

const webhookSecretFile = minimal + "[approval]\nwebhook_url = \"https://hooks.example.internal/x\"\nwebhook_secret_file = \"/etc/relay/hook.secret\"\n"

func TestSecret_InlineAndFileLoad(t *testing.T) {
	inline := mustLoad(t, minimal+"[approval]\nwebhook_url = \"https://hooks.example.internal/x\"\nwebhook_secret = \""+secretValueText+"\"\n")
	if v, ok := inline.Approval.WebhookSecret.Reveal(); !ok || v != secretValueText {
		t.Fatalf("inline Reveal = %q, %v", v, ok)
	}
	if inline.Approval.WebhookSecret.Path() != "" {
		t.Fatal("inline secret has a path")
	}

	cfg := mustLoad(t, webhookSecretFile)
	s := cfg.Approval.WebhookSecret
	if s.Path() != "/etc/relay/hook.secret" {
		t.Fatalf("Path = %q", s.Path())
	}
	if _, ok := s.Reveal(); ok {
		t.Fatal("a file-backed secret reveals before it is resolved")
	}
	var asked []string
	err := cfg.ResolveSecrets(func(path string) ([]byte, error) {
		asked = append(asked, path)
		return []byte("  " + secretValueText + "\n"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := cfg.Approval.WebhookSecret.Reveal(); !ok || v != secretValueText {
		t.Fatalf("resolved Reveal = %q, %v", v, ok)
	}
	if len(asked) != 1 || asked[0] != "/etc/relay/hook.secret" {
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

func TestSecret_BothInlineAndFileRefused(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"webhook url", "webhook_url = \"https://x.example/h\"\nwebhook_url_file = \"/etc/relay/u\"\n", "approval.webhook_url_file (line 9)"},
		{"webhook secret", "webhook_url = \"https://x.example/h\"\nwebhook_secret = \"v\"\nwebhook_secret_file = \"/etc/relay/s\"\n", "approval.webhook_secret_file (line 10)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := loadErr(t, minimal+"[approval]\n"+tc.body)
			if !strings.Contains(got, tc.want) || !strings.Contains(got, "not both") {
				t.Fatalf("error = %q", got)
			}
		})
	}
}

func TestSecret_NeverPrints(t *testing.T) {
	cfg := mustLoad(t, minimal+"[approval]\nwebhook_url = \"https://hooks.example.internal/"+secretValueText+"\"\nwebhook_secret = \""+secretValueText+"\"\n")
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

func TestSecret_InlineIsTrimmedAndBlankRefused(t *testing.T) {
	cfg := mustLoad(t, minimal+"[approval]\nwebhook_url = \"https://hooks.example.internal/x\"\nwebhook_secret = \"  "+secretValueText+"\\n\"\n")
	if v, _ := cfg.Approval.WebhookSecret.Reveal(); v != secretValueText {
		t.Fatalf("Reveal = %q", v)
	}
	for _, blank := range []string{"", "   ", "\\n"} {
		got := loadErr(t, minimal+"[approval]\nwebhook_url = \"https://hooks.example.internal/x\"\nwebhook_secret = \""+blank+"\"\n")
		if !strings.Contains(got, "approval.webhook_secret (line 9)") || !strings.Contains(got, "must not be empty") {
			t.Errorf("blank %q: error = %q", blank, got)
		}
	}
	got := loadErr(t, minimal+"[approval]\nwebhook_url = \"  \"\n")
	if !strings.Contains(got, "approval.webhook_url (line 8)") {
		t.Errorf("blank URL: error = %q", got)
	}
}

func TestResolveSecrets_DoesNotChangeEarlierCopies(t *testing.T) {
	cfg := mustLoad(t, webhookSecretFile)
	before := cfg
	err := cfg.ResolveSecrets(func(string) ([]byte, error) { return []byte(secretValueText), nil })
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := before.Approval.WebhookSecret.Reveal(); ok {
		t.Fatal("a copy taken before ResolveSecrets reveals the value")
	}
	if v, ok := cfg.Approval.WebhookSecret.Reveal(); !ok || v != secretValueText {
		t.Fatalf("resolved Reveal = %q, %v", v, ok)
	}
}
