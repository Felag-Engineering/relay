package relayconfig

import (
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
)

// Proves RC-22.
func TestDefaults_EachReachValueWhenAbsent(t *testing.T) {
	cfg := mustLoad(t, minimal)

	// The RC-22 values.
	if cfg.Reach.ReadBlastCap != capability.DefaultReadCap || cfg.Reach.MutateBlastCap != capability.DefaultMutateCap {
		t.Errorf("blast caps = %d/%d", cfg.Reach.ReadBlastCap, cfg.Reach.MutateBlastCap)
	}
	if cfg.Reach.MinDaemonVersion != "" {
		t.Errorf("min_daemon_version = %q, want the gate off", cfg.Reach.MinDaemonVersion)
	}
	if cfg.Enrollment != (Enrollment{MaxNodes: 110000}) {
		t.Errorf("enrollment = %+v", cfg.Enrollment)
	}
	if cfg.Log.Level != slog.LevelInfo {
		t.Errorf("log = %+v", cfg.Log)
	}

	// The defaults outside RC-22.
	if cfg.NodePlane.ListenAddress != ":7654" || cfg.ControlPlane.ListenAddress != ":9443" {
		t.Errorf("listeners = %q, %q", cfg.NodePlane.ListenAddress, cfg.ControlPlane.ListenAddress)
	}
	if cfg.ControlPlane.Enabled || cfg.Console.Enabled {
		t.Error("the control plane and Console are on by default")
	}
	if cfg.Console.SessionIdle != consoleauth.DefaultIdleTimeout {
		t.Errorf("console durations = %+v", cfg.Console)
	}
	if cfg.Approval.WebhookURL.IsSet() || cfg.Approval.WebhookSecret.IsSet() {
		t.Errorf("approval = %+v", cfg.Approval)
	}
	if cfg.OAuth != (OAuth{}) {
		t.Errorf("OAuth is on by default: %+v", cfg.OAuth)
	}
}

func TestDefaults_ReadAndMutateCapsAreThePinnedValues(t *testing.T) {
	// The example and the operator docs state these numbers.
	if capability.DefaultReadCap != 10000 || capability.DefaultMutateCap != 100 {
		t.Fatalf("the blast cap defaults moved to %d/%d; update relay.toml.example",
			capability.DefaultReadCap, capability.DefaultMutateCap)
	}
}

// variantOAuth builds a control plane with OAuth; an empty argument leaves
// that key out.
func variantOAuth(issuer, audience, claim, scope, publicURL string) string {
	var b strings.Builder
	b.WriteString(minimal + "[control_plane]\nenabled = true\n[oauth]\n")
	for _, kv := range [][2]string{{"issuer", issuer}, {"audience", audience}, {"account_claim", claim},
		{"required_scope", scope}, {"public_url", publicURL}} {
		if kv[1] != "" {
			b.WriteString(kv[0] + " = \"" + kv[1] + "\"\n")
		}
	}
	return b.String()
}

const (
	webhookBase = minimal + "[approval]\nwebhook_url_file = \"/etc/relay/hook.url\"\n"
	oauthIssuer = "https://idp.example.com"
	oauthPublic = "https://relay.example.internal:9443"
)

// TestEveryKeyReachesConfig proves build copies every schema key: setting any
// one to a non-default value changes the Config, so a key the schema carries
// and Config drops cannot hide.
// Proves RC-22.
func TestEveryKeyReachesConfig(t *testing.T) {
	type variant struct{ base, doc string }
	m := func(doc string) variant { return variant{minimal, minimal + doc} }
	oauth := func(issuer, aud, claim, scope, pub string) variant {
		return variant{variantOAuth(oauthIssuer, "relay", "", "", oauthPublic), variantOAuth(issuer, aud, claim, scope, pub)}
	}
	webhook := func(doc string) variant { return variant{webhookBase, webhookBase + doc} }
	swap := func(old, new string) variant { return variant{minimal, strings.Replace(minimal, old, new, 1)} }

	cases := map[string]variant{
		"node_plane.listen_address":     m("[node_plane]\nlisten_address = \"127.0.0.1:8000\"\n"),
		"node_plane.advertised_address": m("[node_plane]\nadvertised_address = \"relay.example.internal:8000\"\n"),
		"control_plane.enabled":         m("[control_plane]\nenabled = true\n"),
		"control_plane.listen_address":  m("[control_plane]\nlisten_address = \":9444\"\n"),
		"console.enabled":               m("[control_plane]\nenabled = true\n[console]\nenabled = true\n"),
		"console.session_idle":          m("[console]\nsession_idle = \"1m\"\n"),
		"ca.dir":                        swap("/var/lib/relay/ca", "/srv/ca"),
		"store.path":                    swap("/var/lib/relay/relay.db", "/srv/relay.db"),
		"tls.hostname":                  swap("relay.example.internal", "relay2.example.internal"),
		"tls.extra_names":               m("extra_names = [\"lb.example.internal\"]\n"),
		"oauth.issuer":                  oauth("https://other.example.com", "relay", "", "", oauthPublic),
		"oauth.audience":                oauth(oauthIssuer, "other", "", "", oauthPublic),
		"oauth.account_claim":           oauth(oauthIssuer, "relay", "sub", "", oauthPublic),
		"oauth.required_scope":          oauth(oauthIssuer, "relay", "", "relay.operate", oauthPublic),
		"oauth.public_url":              oauth(oauthIssuer, "relay", "", "", "https://other.example.internal"),
		"approval.rules":                m("[[approval.rules]]\nname = \"r\"\n"),
		"approval.webhook_url_file":     m("[approval]\nwebhook_url_file = \"/etc/relay/hook.url\"\n"),
		"approval.webhook_secret_file":  webhook("webhook_secret_file = \"/etc/relay/hook.secret\"\n"),
		"log.level":                     m("[log]\nlevel = \"debug\"\n"),
		"reach.read_blast_cap":          m("[reach]\nread_blast_cap = 7\n"),
		"reach.mutate_blast_cap":        m("[reach]\nmutate_blast_cap = 7\n"),
		"reach.min_daemon_version":      m("[reach]\nmin_daemon_version = \"1.2.3\"\n"),
		"enrollment.max_nodes":          m("[enrollment]\nmax_nodes = 9\n"),
	}

	// The Config field each key must land in.
	fields := map[string]func(Config) any{
		"node_plane.listen_address":     func(c Config) any { return c.NodePlane.ListenAddress },
		"node_plane.advertised_address": func(c Config) any { return c.NodePlane.AdvertisedAddress },
		"control_plane.enabled":         func(c Config) any { return c.ControlPlane.Enabled },
		"control_plane.listen_address":  func(c Config) any { return c.ControlPlane.ListenAddress },
		"console.enabled":               func(c Config) any { return c.Console.Enabled },
		"console.session_idle":          func(c Config) any { return c.Console.SessionIdle },
		"ca.dir":                        func(c Config) any { return c.CA.Dir },
		"store.path":                    func(c Config) any { return c.Store.Path },
		"tls.hostname":                  func(c Config) any { return c.TLS.Hostname },
		"tls.extra_names":               func(c Config) any { return c.TLS.ExtraNames },
		"oauth.issuer":                  func(c Config) any { return c.OAuth.Issuer },
		"oauth.audience":                func(c Config) any { return c.OAuth.Audience },
		"oauth.account_claim":           func(c Config) any { return c.OAuth.AccountClaim },
		"oauth.required_scope":          func(c Config) any { return c.OAuth.RequiredScope },
		"oauth.public_url":              func(c Config) any { return c.OAuth.PublicURL },
		"approval.rules":                func(c Config) any { return c.Approval.Rules },
		"approval.webhook_url_file":     func(c Config) any { return c.Approval.WebhookURL },
		"approval.webhook_secret_file":  func(c Config) any { return c.Approval.WebhookSecret },
		"log.level":                     func(c Config) any { return c.Log.Level },
		"reach.read_blast_cap":          func(c Config) any { return c.Reach.ReadBlastCap },
		"reach.mutate_blast_cap":        func(c Config) any { return c.Reach.MutateBlastCap },
		"reach.min_daemon_version":      func(c Config) any { return c.Reach.MinDaemonVersion },
		"enrollment.max_nodes":          func(c Config) any { return c.Enrollment.MaxNodes },
	}
	if len(fields) != len(cases) {
		t.Fatalf("fields has %d entries, cases has %d", len(fields), len(cases))
	}

	var covered []string
	for k := range cases {
		covered = append(covered, k)
	}
	want := schemaKeys()
	slices.Sort(covered)
	slices.Sort(want)
	if !slices.Equal(covered, want) {
		t.Fatalf("the table covers %v, the schema has %v", covered, want)
	}

	for key, v := range cases {
		t.Run(key, func(t *testing.T) {
			base, changed := mustLoad(t, v.base), mustLoad(t, v.doc)
			field, ok := fields[key]
			if !ok {
				t.Fatalf("no expected field for %s", key)
			}
			if reflect.DeepEqual(field(base), field(changed)) {
				t.Fatalf("setting %s did not change its Config field", key)
			}
		})
	}
}
