package relayconfig

import (
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/approvalnotify"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/nodestate"
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
	if cfg.Enrollment.CertExpiringFraction != nodestate.DefaultCertExpiringFraction {
		t.Errorf("cert_expiring_fraction = %v", cfg.Enrollment.CertExpiringFraction)
	}
	wantEnroll := Enrollment{
		IPRatePerMinute: 5, IPBurst: 3, GlobalRatePerMinute: 50, GlobalBurst: 10,
		MaxTrackedIPs: 100000, MaxNodes: 110000,
		CertExpiringFraction: nodestate.DefaultCertExpiringFraction,
	}
	if cfg.Enrollment != wantEnroll {
		t.Errorf("enrollment = %+v, want %+v", cfg.Enrollment, wantEnroll)
	}
	if cfg.Log.Level != slog.LevelInfo || cfg.Log.Format != LogText {
		t.Errorf("log = %+v", cfg.Log)
	}

	// The defaults outside RC-22.
	if cfg.Reach.DispatchConcurrency != capability.DefaultDispatchConcurrency {
		t.Errorf("dispatch_concurrency = %d", cfg.Reach.DispatchConcurrency)
	}
	if cfg.NodePlane.ListenAddress != ":7654" || cfg.ControlPlane.ListenAddress != ":9443" {
		t.Errorf("listeners = %q, %q", cfg.NodePlane.ListenAddress, cfg.ControlPlane.ListenAddress)
	}
	if cfg.ControlPlane.Enabled || cfg.Console.Enabled {
		t.Error("the control plane and Console are on by default")
	}
	if cfg.Console.SessionMaxAge != consoleauth.DefaultAbsoluteLifetime ||
		cfg.Console.SessionIdle != consoleauth.DefaultIdleTimeout ||
		cfg.Console.StepUpWindow != consoleauth.DefaultStepUpWindow {
		t.Errorf("console durations = %+v", cfg.Console)
	}
	if cfg.Approval.WebhookTimeout != approvalnotify.DefaultTimeout || cfg.Approval.WebhookURL.IsSet() || cfg.Approval.WebhookSecret.IsSet() {
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

// Proves RC-22.
func TestApprovalGatePathAbsentMeansNoGate(t *testing.T) {
	if got := mustLoad(t, minimal).Approval.GateRulesPath; got != "" {
		t.Fatalf("GateRulesPath = %q, want none", got)
	}
	cfg := mustLoad(t, minimal+"[approval]\ngate_rules_path = \"/etc/relay/approval-gates.json\"\n")
	if cfg.Approval.GateRulesPath != "/etc/relay/approval-gates.json" {
		t.Fatalf("GateRulesPath = %q", cfg.Approval.GateRulesPath)
	}
	if got := loadErr(t, minimal+"[approval]\ngate_rules_path = \"\"\n"); !strings.Contains(got, "approval.gate_rules_path (line 8)") {
		t.Fatalf("an empty path must be refused, not read as no gate: %q", got)
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
	webhookBase = minimal + "[approval]\nwebhook_url = \"https://hooks.example.internal/x\"\n"
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
		"node_plane.listen_address":         m("[node_plane]\nlisten_address = \"127.0.0.1:8000\"\n"),
		"node_plane.advertised_address":     m("[node_plane]\nadvertised_address = \"relay.example.internal:8000\"\n"),
		"control_plane.enabled":             m("[control_plane]\nenabled = true\n"),
		"control_plane.listen_address":      m("[control_plane]\nlisten_address = \":9444\"\n"),
		"console.enabled":                   m("[control_plane]\nenabled = true\n[console]\nenabled = true\n"),
		"console.session_max_age":           m("[console]\nsession_max_age = \"1h\"\n"),
		"console.session_idle":              m("[console]\nsession_idle = \"1m\"\n"),
		"console.step_up_window":            m("[console]\nstep_up_window = \"1m\"\n"),
		"ca.dir":                            swap("/var/lib/relay/ca", "/srv/ca"),
		"store.path":                        swap("/var/lib/relay/relay.db", "/srv/relay.db"),
		"tls.hostname":                      swap("relay.example.internal", "relay2.example.internal"),
		"tls.extra_names":                   m("extra_names = [\"lb.example.internal\"]\n"),
		"oauth.issuer":                      oauth("https://other.example.com", "relay", "", "", oauthPublic),
		"oauth.audience":                    oauth(oauthIssuer, "other", "", "", oauthPublic),
		"oauth.account_claim":               oauth(oauthIssuer, "relay", "sub", "", oauthPublic),
		"oauth.required_scope":              oauth(oauthIssuer, "relay", "", "relay.operate", oauthPublic),
		"oauth.public_url":                  oauth(oauthIssuer, "relay", "", "", "https://other.example.internal"),
		"approval.gate_rules_path":          m("[approval]\ngate_rules_path = \"/etc/relay/gates.json\"\n"),
		"approval.webhook_url":              m("[approval]\nwebhook_url = \"https://hooks.example.internal/x\"\n"),
		"approval.webhook_url_file":         m("[approval]\nwebhook_url_file = \"/etc/relay/hook.url\"\n"),
		"approval.webhook_secret":           webhook("webhook_secret = \"v\"\n"),
		"approval.webhook_secret_file":      webhook("webhook_secret_file = \"/etc/relay/hook.secret\"\n"),
		"approval.webhook_timeout":          webhook("webhook_timeout = \"9s\"\n"),
		"log.level":                         m("[log]\nlevel = \"debug\"\n"),
		"log.format":                        m("[log]\nformat = \"json\"\n"),
		"reach.read_blast_cap":              m("[reach]\nread_blast_cap = 7\n"),
		"reach.mutate_blast_cap":            m("[reach]\nmutate_blast_cap = 7\n"),
		"reach.dispatch_concurrency":        m("[reach]\ndispatch_concurrency = 3\n"),
		"reach.min_daemon_version":          m("[reach]\nmin_daemon_version = \"1.2.3\"\n"),
		"enrollment.ip_rate_per_minute":     m("[enrollment]\nip_rate_per_minute = 9\n"),
		"enrollment.ip_burst":               m("[enrollment]\nip_burst = 9\n"),
		"enrollment.global_rate_per_minute": m("[enrollment]\nglobal_rate_per_minute = 9\n"),
		"enrollment.global_burst":           m("[enrollment]\nglobal_burst = 9\n"),
		"enrollment.max_tracked_ips":        m("[enrollment]\nmax_tracked_ips = 9\n"),
		"enrollment.max_nodes":              m("[enrollment]\nmax_nodes = 9\n"),
		"enrollment.cert_expiring_fraction": m("[enrollment]\ncert_expiring_fraction = 0.5\n"),
	}

	// The Config field each key must land in.
	fields := map[string]func(Config) any{
		"node_plane.listen_address":         func(c Config) any { return c.NodePlane.ListenAddress },
		"node_plane.advertised_address":     func(c Config) any { return c.NodePlane.AdvertisedAddress },
		"control_plane.enabled":             func(c Config) any { return c.ControlPlane.Enabled },
		"control_plane.listen_address":      func(c Config) any { return c.ControlPlane.ListenAddress },
		"console.enabled":                   func(c Config) any { return c.Console.Enabled },
		"console.session_max_age":           func(c Config) any { return c.Console.SessionMaxAge },
		"console.session_idle":              func(c Config) any { return c.Console.SessionIdle },
		"console.step_up_window":            func(c Config) any { return c.Console.StepUpWindow },
		"ca.dir":                            func(c Config) any { return c.CA.Dir },
		"store.path":                        func(c Config) any { return c.Store.Path },
		"tls.hostname":                      func(c Config) any { return c.TLS.Hostname },
		"tls.extra_names":                   func(c Config) any { return c.TLS.ExtraNames },
		"oauth.issuer":                      func(c Config) any { return c.OAuth.Issuer },
		"oauth.audience":                    func(c Config) any { return c.OAuth.Audience },
		"oauth.account_claim":               func(c Config) any { return c.OAuth.AccountClaim },
		"oauth.required_scope":              func(c Config) any { return c.OAuth.RequiredScope },
		"oauth.public_url":                  func(c Config) any { return c.OAuth.PublicURL },
		"approval.gate_rules_path":          func(c Config) any { return c.Approval.GateRulesPath },
		"approval.webhook_url":              func(c Config) any { return c.Approval.WebhookURL },
		"approval.webhook_url_file":         func(c Config) any { return c.Approval.WebhookURL },
		"approval.webhook_secret":           func(c Config) any { return c.Approval.WebhookSecret },
		"approval.webhook_secret_file":      func(c Config) any { return c.Approval.WebhookSecret },
		"approval.webhook_timeout":          func(c Config) any { return c.Approval.WebhookTimeout },
		"log.level":                         func(c Config) any { return c.Log.Level },
		"log.format":                        func(c Config) any { return c.Log.Format },
		"reach.read_blast_cap":              func(c Config) any { return c.Reach.ReadBlastCap },
		"reach.mutate_blast_cap":            func(c Config) any { return c.Reach.MutateBlastCap },
		"reach.dispatch_concurrency":        func(c Config) any { return c.Reach.DispatchConcurrency },
		"reach.min_daemon_version":          func(c Config) any { return c.Reach.MinDaemonVersion },
		"enrollment.ip_rate_per_minute":     func(c Config) any { return c.Enrollment.IPRatePerMinute },
		"enrollment.ip_burst":               func(c Config) any { return c.Enrollment.IPBurst },
		"enrollment.global_rate_per_minute": func(c Config) any { return c.Enrollment.GlobalRatePerMinute },
		"enrollment.global_burst":           func(c Config) any { return c.Enrollment.GlobalBurst },
		"enrollment.max_tracked_ips":        func(c Config) any { return c.Enrollment.MaxTrackedIPs },
		"enrollment.max_nodes":              func(c Config) any { return c.Enrollment.MaxNodes },
		"enrollment.cert_expiring_fraction": func(c Config) any { return c.Enrollment.CertExpiringFraction },
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
