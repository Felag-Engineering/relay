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
		if logical[s.key] {
			t.Errorf("setting %s is listed twice", s.key)
		}
		logical[s.key] = true
		if s.class != restartRequired && s.class != appliedByReload {
			t.Errorf("setting %s has no reload class: classify it restartRequired or appliedByReload", s.key)
		}
	}
	for _, k := range schemaKeys() {
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

func TestDiff_RestartRequiredIsRC21sListPlusConsoleIdle(t *testing.T) {
	want := []string{
		"node_plane.listen_address", "node_plane.advertised_address",
		"control_plane.enabled", "control_plane.listen_address", "console.enabled",
		"ca.dir", "store.path", "tls.hostname",
		// RC-47 makes tls.extra_names bind-time, extending RC-21's list by reference.
		"tls.extra_names",
		"oauth.issuer", "oauth.audience", "oauth.account_claim", "oauth.required_scope", "oauth.public_url",
		"console.session_idle",
	}
	var got []string
	for _, s := range settings {
		if s.class == restartRequired {
			got = append(got, s.key)
		}
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

func TestDiff_UnclassifiedSettingIsRestartRequired(t *testing.T) {
	saved := settings
	t.Cleanup(func() { settings = saved })
	settings = []setting{{key: "log.level", class: unclassified, differs: differ(func(c Config) int { return int(c.Log.Level) })}}
	a := loadForDiff(t, diffBase)
	b := loadForDiff(t, diffBase+"[log]\nlevel = \"debug\"\n")
	cs := Diff(a, b)
	if len(cs) != 1 || !cs[0].RestartRequired {
		t.Errorf("Diff = %+v, want one restart-required change", cs)
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
	b := loadForDiff(t, diffBase+"[reach]\nmutate_blast_cap = 7\n[log]\nlevel = \"debug\"\n")
	b.Console.SessionIdle = time.Hour
	got := Diff(a, b)
	want := []Change{
		{Key: "console.session_idle", RestartRequired: true},
		{Key: "log.level"},
		{Key: "reach.mutate_blast_cap"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("Diff = %+v, want %+v", got, want)
	}
}

// A tls.extra_names change of any kind, a reorder included, is restart-required.
// Proves RC-47.
func TestDiff_ExtraNamesChangeIsRestartRequired(t *testing.T) {
	list := func(names string) Config {
		return loadForDiff(t, diffBase+"extra_names = ["+names+"]\n")
	}
	base := list(`"a.example.net", "b.example.net"`)
	for name, next := range map[string]Config{
		"removed":   loadForDiff(t, diffBase),
		"changed":   list(`"a.example.net", "c.example.net"`),
		"reordered": list(`"b.example.net", "a.example.net"`),
	} {
		cs := Diff(base, next)
		want := []Change{{Key: "tls.extra_names", RestartRequired: true}}
		if !slices.Equal(cs, want) {
			t.Errorf("%s: Diff = %+v, want %+v", name, cs, want)
		}
	}
	if cs := Diff(loadForDiff(t, diffBase), base); !slices.Equal(cs, []Change{{Key: "tls.extra_names", RestartRequired: true}}) {
		t.Errorf("added: Diff = %+v", cs)
	}
	if cs := Diff(base, list(`"a.example.net", "b.example.net"`)); len(cs) != 0 {
		t.Errorf("an unchanged list differs: %+v", cs)
	}
}

func TestDiff_SecretChangeNamedNeverValued(t *testing.T) {
	const urlA, urlB = "http://127.0.0.1:1/hook-token-A", "http://127.0.0.1:1/hook-token-B"
	load := func(body string, url, secret string) Config {
		cfg := loadForDiff(t, diffBase+"[approval]\n"+body)
		err := cfg.ResolveSecrets(func(path string) ([]byte, error) {
			if strings.Contains(path, "url") {
				return []byte(url), nil
			}
			return []byte(secret), nil
		})
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	const files = "webhook_url_file = \"/run/x/url\"\nwebhook_secret_file = \"/run/x/sec\"\n"
	base := load(files, urlA, "s3cr3t-A")

	// The same paths with new content: a secrets agent rewriting a file in place.
	for name, tc := range map[string]struct {
		next Config
		key  string
	}{
		"url rewritten in place":    {load(files, urlB, "s3cr3t-A"), "approval.webhook_url_file"},
		"secret rewritten in place": {load(files, urlA, "s3cr3t-B"), "approval.webhook_secret_file"},
		"url moved to a new path":   {load("webhook_url_file = \"/run/x/url2\"\nwebhook_secret_file = \"/run/x/sec\"\n", urlA, "s3cr3t-A"), "approval.webhook_url_file"},
	} {
		cs := Diff(base, tc.next)
		if len(cs) != 1 || cs[0].Key != tc.key || !cs[0].Secret || cs[0].RestartRequired {
			t.Errorf("%s: Diff = %+v, want one secret %s change", name, cs, tc.key)
		}
	}
	if cs := Diff(base, load(files, urlA, "s3cr3t-A")); len(cs) != 0 {
		t.Errorf("unchanged files differ: %+v", cs)
	}
}

func TestIsSettingKey_ClosedSet(t *testing.T) {
	for _, k := range schemaKeys() {
		if !IsSettingKey(k) {
			t.Errorf("schema key %q is not a member", k)
		}
	}
	for _, k := range []string{"relay.example", "relay.toml", "foo.bar", "", "http://127.0.0.1:1/hook-token", "reach",
		"approval.webhook_url", "approval.webhook_secret", "log.format", "console.session_max_age"} {
		if IsSettingKey(k) {
			t.Errorf("%q is a member", k)
		}
	}
}
