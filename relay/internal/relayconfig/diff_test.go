package relayconfig

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func loadForDiff(t *testing.T, body string) Config {
	t.Helper()
	cfg, _, err := Load([]byte(body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return cfg
}

const diffBase = `
[ca]
dir = "/var/lib/relay/ca"
[store]
path = "/var/lib/relay/relay.db"
[tls]
hostname = "relay.example.net"
`

func TestDiff_EverySchemaKeyClassified(t *testing.T) {
	logical := map[string]bool{}
	for _, s := range settings {
		logical[s.key] = true
	}
	for _, k := range schemaKeys() {
		if strings.HasSuffix(k, "_file") {
			base := strings.TrimSuffix(k, "_file")
			if !logical[base] {
				t.Errorf("%s is a _file key whose inline partner %s is not diffed", k, base)
			}
			continue
		}
		if !logical[k] {
			t.Errorf("schema key %s is not diffed", k)
		}
	}
	for k := range logical {
		if !IsSettingKey(k) {
			t.Errorf("diffed key %s is not a schema key", k)
		}
	}
}

func TestDiff_RestartRequiredIsRC21sListPlusConsoleWindows(t *testing.T) {
	want := []string{
		"node_plane.listen_address", "node_plane.advertised_address",
		"control_plane.enabled", "control_plane.listen_address", "console.enabled",
		"ca.dir", "store.path", "tls.hostname",
		"oauth.issuer", "oauth.audience", "oauth.account_claim", "oauth.required_scope", "oauth.public_url",
		"console.session_max_age", "console.session_idle", "console.step_up_window",
	}
	var got []string
	for k := range restartRequired {
		got = append(got, k)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("restart-required set = %v, want %v", got, want)
	}
	for _, k := range got {
		if !IsSettingKey(k) {
			t.Errorf("restart-required key %s is not a schema key", k)
		}
	}
}

func TestDiff_IdenticalConfigsNoChanges(t *testing.T) {
	a := loadForDiff(t, diffBase)
	b := loadForDiff(t, diffBase)
	if cs := Diff(a, b); len(cs) != 0 {
		t.Errorf("Diff of identical configs = %v", cs)
	}
}

func TestDiff_ChangedValuesAreNamedAndClassified(t *testing.T) {
	a := loadForDiff(t, diffBase)
	b := loadForDiff(t, diffBase+"[reach]\nmutate_blast_cap = 7\n[log]\nformat = \"json\"\n")
	b.Console.SessionIdle = time.Hour
	got := Diff(a, b)
	want := []Change{
		{Key: "console.session_idle", RestartRequired: true},
		{Key: "log.format"},
		{Key: "reach.mutate_blast_cap"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("Diff = %+v, want %+v", got, want)
	}
}

func TestDiff_SecretChangeNamedNeverValued(t *testing.T) {
	inline := loadForDiff(t, diffBase+"[approval]\nwebhook_url = \"http://127.0.0.1:1/hook-token-A\"\nwebhook_secret = \"s3cr3t-A\"\n")
	other := loadForDiff(t, diffBase+"[approval]\nwebhook_url = \"http://127.0.0.1:1/hook-token-B\"\nwebhook_secret = \"s3cr3t-A\"\n")
	byFile := loadForDiff(t, diffBase+"[approval]\nwebhook_url_file = \"/run/x/url\"\nwebhook_secret = \"s3cr3t-A\"\n")
	read := func(string) ([]byte, error) { return []byte("http://127.0.0.1:1/hook-token-A"), nil }
	if err := byFile.ResolveSecrets(read); err != nil {
		t.Fatal(err)
	}

	for name, next := range map[string]Config{"value change": other, "inline to file": byFile} {
		cs := Diff(inline, next)
		if len(cs) != 1 || cs[0].Key != "approval.webhook_url" || !cs[0].Secret || cs[0].RestartRequired {
			t.Errorf("%s: Diff = %+v, want one secret approval.webhook_url change", name, cs)
		}
	}

	// Same file path, different value read: a changed value behind a stable path.
	a := loadForDiff(t, diffBase+"[approval]\nwebhook_url = \"http://127.0.0.1:1/h\"\nwebhook_secret_file = \"/run/x/sec\"\n")
	b := loadForDiff(t, diffBase+"[approval]\nwebhook_url = \"http://127.0.0.1:1/h\"\nwebhook_secret_file = \"/run/x/sec\"\n")
	if err := a.ResolveSecrets(func(string) ([]byte, error) { return []byte("one"), nil }); err != nil {
		t.Fatal(err)
	}
	if err := b.ResolveSecrets(func(string) ([]byte, error) { return []byte("two"), nil }); err != nil {
		t.Fatal(err)
	}
	cs := Diff(a, b)
	if len(cs) != 1 || cs[0].Key != "approval.webhook_secret" || !cs[0].Secret {
		t.Errorf("same-path value change: Diff = %+v", cs)
	}
}

func TestIsSettingKey_ClosedSet(t *testing.T) {
	for _, k := range schemaKeys() {
		if !IsSettingKey(k) {
			t.Errorf("schema key %q is not a member", k)
		}
	}
	for _, k := range []string{"relay.example", "relay.toml", "foo.bar", "", "http://127.0.0.1:1/hook-token", "reach"} {
		if IsSettingKey(k) {
			t.Errorf("%q is a member", k)
		}
	}
}
