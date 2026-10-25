package relayconfig

import (
	"fmt"
	"strings"
	"testing"
)

// minimal holds the three keys that have no default. Text appended to it
// starts on line 7.
const minimal = `[ca]
dir = "/var/lib/relay/ca"
[store]
path = "/var/lib/relay/relay.db"
[tls]
hostname = "relay.example.internal"
`

func mustLoad(t *testing.T, src string) Config {
	t.Helper()
	cfg, _, err := Load([]byte(src))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

func loadErr(t *testing.T, src string) string {
	t.Helper()
	_, _, err := Load([]byte(src))
	if err == nil {
		t.Fatalf("Load accepted:\n%s", src)
	}
	return err.Error()
}

func TestLoad_UnknownKeyRefused(t *testing.T) {
	cases := []struct {
		name, src, want string
	}{
		{"unknown key in a known section", minimal + "[reach]\nread_cap = 5\n", "line 8: an unrecognised key in [reach]"},
		{"unknown section", minimal + "[listen]\naddr = 1\n", "line 7: an unrecognised key is"},
		{"root key named like a retired one", "addr = \":7654\"\n" + minimal, "line 1: an unrecognised key"},
		{"no Console execution key", minimal + "[console]\nexecution = true\n", "line 8: an unrecognised key in [console]"},
		{"no root console_execution key", "console_execution = true\n" + minimal, "line 1: an unrecognised key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := loadErr(t, tc.src); !strings.Contains(got, tc.want) {
				t.Fatalf("error %q does not contain %q", got, tc.want)
			}
		})
	}
}

func TestLoad_UnknownKeyWithUnsafeNameIsNotEchoed(t *testing.T) {
	// A quoted key can hold anything, including a token pasted on the wrong
	// line; it is source text, so it is reported as an unrecognised key.
	src := minimal + "[reach]\n\"tok\\u001b[31mSENTINEL-9\" = 5\n"
	got := loadErr(t, src)
	if strings.Contains(got, "SENTINEL") || strings.ContainsRune(got, '\x1b') {
		t.Fatalf("error echoes the key text: %q", got)
	}
	if !strings.Contains(got, "line 8") || !strings.Contains(got, "unrecognised key") {
		t.Fatalf("error does not locate the unrecognised key: %q", got)
	}
}

func TestLoad_TokenShapedKeyIsNotEchoed(t *testing.T) {
	// `openssl rand -hex 32` pasted where a key belongs.
	token := strings.Repeat("9f2c4e6a", 8) // built at runtime: no secret-shaped literal in source
	for _, src := range []string{
		minimal + "[reach]\n" + token + " = 5\n",
		minimal + "[" + token + "]\nx = 5\n",
		minimal + "[reach." + token + "]\nx = 5\n",
	} {
		got := loadErr(t, src)
		if strings.Contains(got, token[:16]) {
			t.Errorf("error echoes the key: %q", got)
		}
		if !strings.Contains(got, "unrecognised key") {
			t.Errorf("error does not say unrecognised key: %q", got)
		}
	}
}

func TestLoad_DuplicateKeyNamesFullKeyAndSaysSetTwice(t *testing.T) {
	got := loadErr(t, minimal+"[reach]\nread_blast_cap = 1\nread_blast_cap = 2\n")
	if !strings.Contains(got, "reach.read_blast_cap (line 9)") || !strings.Contains(got, "is set twice") {
		t.Fatalf("error = %q", got)
	}
}

func TestLoad_ErrorNamesKeyAndLineNotValue(t *testing.T) {
	const sentinel = "hunter2-SENTINEL"
	cases := []struct {
		name    string
		src     string
		key     string // empty when the error names no key
		line    int
		sources []string // text that must never appear
	}{
		{"type error", minimal + "[approval]\nwebhook_secret = 123456789012\n", "approval.webhook_secret", 8, []string{"123456789012"}},
		{"misspelled key", minimal + "[approval]\nwebhok_secret = \"" + sentinel + "\"\n", "", 8, []string{sentinel, "webhok"}},
		{"syntax error", minimal + "[approval]\nwebhook_secret = \"" + sentinel + "\" junk\n", "", 8, []string{sentinel, "junk"}},
		{"shape error", minimal + "[control_plane]\nenabled = true\n[approval]\nwebhook_url = \"" + sentinel + "\"\n", "approval.webhook_url", 10, []string{sentinel}},
		{"both forms", minimal + "[approval]\nwebhook_url = \"https://x.example/" + sentinel + "\"\nwebhook_url_file = \"/etc/relay/u\"\n", "approval.webhook_url_file", 9, []string{sentinel}},
		{"integer overflow", minimal + "[reach]\nread_blast_cap = 99999999999999999999\n", "reach.read_blast_cap", 8, []string{"99999999999999999999"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Load([]byte(tc.src))
			if err == nil {
				t.Fatal("Load accepted the file")
			}
			for _, rendered := range []string{err.Error(), fmt.Sprintf("%+v", err)} {
				if tc.key != "" && !strings.Contains(rendered, tc.key) {
					t.Errorf("error does not name %s: %q", tc.key, rendered)
				}
				if want := fmt.Sprintf("line %d", tc.line); !strings.Contains(rendered, want) {
					t.Errorf("error does not say %q: %q", want, rendered)
				}
				for _, bad := range tc.sources {
					if strings.Contains(rendered, bad) {
						t.Errorf("error echoes %q: %q", bad, rendered)
					}
				}
				for _, line := range strings.Split(tc.src, "\n") {
					if strings.Contains(line, sentinel) && strings.Contains(rendered, line) {
						t.Errorf("error echoes the source line %q", line)
					}
				}
			}
		})
	}
}

func TestLoad_ReportsEveryProblem(t *testing.T) {
	src := minimal + "[reach]\nread_blast_cap = 0\ndispatch_concurrency = 0\n"
	got := loadErr(t, src)
	i := strings.Index(got, "reach.read_blast_cap (line 8)")
	j := strings.Index(got, "reach.dispatch_concurrency (line 9)")
	if i < 0 || j < 0 || i > j {
		t.Fatalf("both problems should appear in line order: %q", got)
	}
}

func TestLoad_UnknownKeySegmentsAreNeverRendered(t *testing.T) {
	// base32-like and base64url-like text, built at runtime so no secret-shaped
	// literal sits in source.
	tokens := []string{
		strings.ToLower("JBSWY3DPEBLW64TMMQQQ"),
		strings.ToLower("QUJDREVGR0hJSktMTU5PUA") + "_x9" + "k3j",
	}
	for _, tok := range tokens {
		for name, src := range map[string]string{
			"bare key":   minimal + "[approval]\n" + tok + " = \"x\"\n",
			"dotted key": minimal + "[approval]\n" + tok + ".y = 1\n",
			"sub-table":  minimal + "[approval." + tok + "]\nx = 1\n",
			"top table":  minimal + "[" + tok + "]\nx = 1\n",
			"root key":   tok + " = 1\n" + minimal,
			"quoted key": minimal + "[approval]\n\"" + tok + "\" = 1\n",
		} {
			got := loadErr(t, src)
			for _, part := range []string{tok, tok[:8], tok[len(tok)-6:]} {
				if strings.Contains(got, part) {
					t.Errorf("%s: error renders %q: %q", name, part, got)
				}
			}
			if !strings.Contains(got, "unrecognised key") {
				t.Errorf("%s: error does not say unrecognised key: %q", name, got)
			}
		}
	}
}
