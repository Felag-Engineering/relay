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
		{"type error", minimal + "[approval]\nwebhook_secret_file = 123456789012\n", "approval.webhook_secret_file", 8, []string{"123456789012"}},
		{"misspelled key", minimal + "[approval]\nwebhok_secret = \"" + sentinel + "\"\n", "", 8, []string{sentinel, "webhok"}},
		{"syntax error", minimal + "[approval]\nwebhook_secret_file = \"" + sentinel + "\" junk\n", "", 8, []string{sentinel, "junk"}},
		{"shape error", minimal + "[approval]\nwebhook_url_file = \"" + sentinel + "\"\n", "approval.webhook_url_file", 8, []string{sentinel}},
		{"removed inline key", minimal + "[approval]\nwebhook_url = \"https://x.example/" + sentinel + "\"\n", "approval.webhook_url", 8, []string{sentinel}},
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
	src := minimal + "[reach]\nread_blast_cap = 0\nmutate_blast_cap = 0\n"
	got := loadErr(t, src)
	i := strings.Index(got, "reach.read_blast_cap (line 8)")
	j := strings.Index(got, "reach.mutate_blast_cap (line 9)")
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

// removedCases are the thirteen keys RC-44 lists, each with a value that must
// never be echoed.
var removedCases = []struct{ section, key, value string }{
	{"enrollment", "ip_rate_per_minute", "5"},
	{"enrollment", "ip_burst", "3"},
	{"enrollment", "global_rate_per_minute", "50"},
	{"enrollment", "global_burst", "10"},
	{"enrollment", "max_tracked_ips", "100000"},
	{"enrollment", "cert_expiring_fraction", "0.25"},
	{"reach", "dispatch_concurrency", "16"},
	{"approval", "webhook_timeout", `"5s"`},
	{"approval", "webhook_url", `"https://hooks.example/CANARY-url"`},
	{"approval", "webhook_secret", `"CANARY-secret"`},
	{"log", "format", `"json"`},
	{"console", "session_max_age", `"12h"`},
	{"console", "step_up_window", `"5m"`},
}

// Proves RC-44.
func TestLoad_RemovedKeyRefusedNamingKey(t *testing.T) {
	if len(removedCases) != 13 || len(removedKeys) != 13 {
		t.Fatalf("RC-44 lists 13 keys; the test has %d and the loader %d", len(removedCases), len(removedKeys))
	}
	for _, tc := range removedCases {
		key := tc.section + "." + tc.key
		if schemaKeySet[key] {
			t.Errorf("%s is a removed key and must not be a schema key", key)
		}
		t.Run(key, func(t *testing.T) {
			got := loadErr(t, minimal+"["+tc.section+"]\n"+tc.key+" = "+tc.value+"\n")
			if !strings.Contains(got, key+" (line 8)") {
				t.Fatalf("error does not name the key and line: %q", got)
			}
			if strings.Contains(got, "CANARY") || strings.Contains(got, "unrecognised") {
				t.Fatalf("error echoes the value or reads as an unknown key: %q", got)
			}
		})
	}

	t.Run("written as a table or a dotted key", func(t *testing.T) {
		for name, src := range map[string]string{
			"table":  minimal + "[log.format]\nx = 1\n",
			"dotted": minimal + "[log]\nformat.x = \"CANARY\"\n",
		} {
			got := loadErr(t, src)
			if !strings.Contains(got, "log.format") || strings.Contains(got, "CANARY") {
				t.Errorf("%s: error = %q", name, got)
			}
		}
	})

	t.Run("written twice", func(t *testing.T) {
		got := loadErr(t, minimal+"[log]\nformat = \"json\"\nformat = \"CANARY\"\n")
		if !strings.Contains(got, "log.format (line 9)") || strings.Contains(got, "CANARY") {
			t.Errorf("error = %q", got)
		}
	})

	// A decode error elsewhere in the file is reported first: the removed key is
	// still refused, and is named once that error is fixed.
	t.Run("a separate decode error reports first", func(t *testing.T) {
		src := minimal + "[log]\nformat = \"json\"\n[reach]\nread_blast_cap = \"many\"\n"
		got := loadErr(t, src)
		if !strings.Contains(got, "reach.read_blast_cap") {
			t.Fatalf("error = %q", got)
		}
		fixed := strings.Replace(src, "\"many\"", "5", 1)
		if got := loadErr(t, fixed); !strings.Contains(got, "log.format (line 8)") {
			t.Fatalf("after the fix, error = %q", got)
		}
	})
}
