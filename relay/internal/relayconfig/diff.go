package relayconfig

// Change is one setting whose value differs between two configurations. It
// carries the setting's key and never a value, so a list of Changes is safe to
// log and to audit (RC-18).
type Change struct {
	// Key is "section.key" as the schema spells it. A secret given either
	// inline or by a `_file` key is one logical setting, named by the inline
	// key (approval.webhook_url, approval.webhook_secret).
	Key string
	// Secret is true when the setting holds a secret.
	Secret bool
	// RestartRequired is true when only a restart applies the setting: its
	// consumer is built once at start (RC-21).
	RestartRequired bool
}

// IsSettingKey reports whether key is one of the closed set of "section.key"
// names the schema declares. A value can never be a member, so a caller that
// admits only members carries names, never values (RC-18).
func IsSettingKey(key string) bool { return schemaKeySet[key] }

// restartRequired is RC-21's bind-time list: each key is applied by a consumer
// built once at start that no reload reaches. The OAuth identity provider is
// the whole [oauth] section. The three Console session and step-up windows are
// beyond RC-21's enumeration and await the owner's ratification: the Console's
// authentication is constructed with them once, and a reload that silently did
// not apply them would leave the file and the running Relay disagreeing.
var restartRequired = map[string]bool{
	"node_plane.listen_address":     true,
	"node_plane.advertised_address": true,
	"control_plane.enabled":         true,
	"control_plane.listen_address":  true,
	"console.enabled":               true,
	"ca.dir":                        true,
	"store.path":                    true,
	"tls.hostname":                  true,
	"oauth.issuer":                  true,
	"oauth.audience":                true,
	"oauth.account_claim":           true,
	"oauth.required_scope":          true,
	"oauth.public_url":              true,
	"console.session_max_age":       true,
	"console.session_idle":          true,
	"console.step_up_window":        true,
}

// setting is one logical setting: how to tell whether two configurations
// differ in it.
type setting struct {
	key     string
	secret  bool
	differs func(a, b Config) bool
}

func differ[T comparable](get func(Config) T) func(a, b Config) bool {
	return func(a, b Config) bool { return get(a) != get(b) }
}

func secretDiffers(get func(Config) Secret) func(a, b Config) bool {
	return func(a, b Config) bool {
		x, y := get(a), get(b)
		if x.IsSet() != y.IsSet() || x.Path() != y.Path() {
			return true
		}
		xv, xok := x.Reveal()
		yv, yok := y.Reveal()
		return xok != yok || xv != yv
	}
}

// settings lists every logical setting in schema order. The `_file` keys are
// folded into their inline partner; TestDiff_EverySchemaKeyClassified pins that
// no schema key is left out.
var settings = []setting{
	{key: "node_plane.listen_address", differs: differ(func(c Config) string { return c.NodePlane.ListenAddress })},
	{key: "node_plane.advertised_address", differs: differ(func(c Config) string { return c.NodePlane.AdvertisedAddress })},
	{key: "control_plane.enabled", differs: differ(func(c Config) bool { return c.ControlPlane.Enabled })},
	{key: "control_plane.listen_address", differs: differ(func(c Config) string { return c.ControlPlane.ListenAddress })},
	{key: "console.enabled", differs: differ(func(c Config) bool { return c.Console.Enabled })},
	{key: "console.session_max_age", differs: differ(func(c Config) int64 { return int64(c.Console.SessionMaxAge) })},
	{key: "console.session_idle", differs: differ(func(c Config) int64 { return int64(c.Console.SessionIdle) })},
	{key: "console.step_up_window", differs: differ(func(c Config) int64 { return int64(c.Console.StepUpWindow) })},
	{key: "ca.dir", differs: differ(func(c Config) string { return c.CA.Dir })},
	{key: "store.path", differs: differ(func(c Config) string { return c.Store.Path })},
	{key: "tls.hostname", differs: differ(func(c Config) string { return c.TLS.Hostname })},
	{key: "oauth.issuer", differs: differ(func(c Config) string { return c.OAuth.Issuer })},
	{key: "oauth.audience", differs: differ(func(c Config) string { return c.OAuth.Audience })},
	{key: "oauth.account_claim", differs: differ(func(c Config) string { return c.OAuth.AccountClaim })},
	{key: "oauth.required_scope", differs: differ(func(c Config) string { return c.OAuth.RequiredScope })},
	{key: "oauth.public_url", differs: differ(func(c Config) string { return c.OAuth.PublicURL })},
	{key: "approval.gate_rules_path", differs: differ(func(c Config) string { return c.Approval.GateRulesPath })},
	{key: "approval.webhook_url", secret: true, differs: secretDiffers(func(c Config) Secret { return c.Approval.WebhookURL })},
	{key: "approval.webhook_secret", secret: true, differs: secretDiffers(func(c Config) Secret { return c.Approval.WebhookSecret })},
	{key: "approval.webhook_timeout", differs: differ(func(c Config) int64 { return int64(c.Approval.WebhookTimeout) })},
	{key: "log.level", differs: differ(func(c Config) int { return int(c.Log.Level) })},
	{key: "log.format", differs: differ(func(c Config) LogFormat { return c.Log.Format })},
	{key: "reach.read_blast_cap", differs: differ(func(c Config) int { return c.Reach.ReadBlastCap })},
	{key: "reach.mutate_blast_cap", differs: differ(func(c Config) int { return c.Reach.MutateBlastCap })},
	{key: "reach.dispatch_concurrency", differs: differ(func(c Config) int { return c.Reach.DispatchConcurrency })},
	{key: "reach.min_daemon_version", differs: differ(func(c Config) string { return c.Reach.MinDaemonVersion })},
	{key: "enrollment.ip_rate_per_minute", differs: differ(func(c Config) int { return c.Enrollment.IPRatePerMinute })},
	{key: "enrollment.ip_burst", differs: differ(func(c Config) int { return c.Enrollment.IPBurst })},
	{key: "enrollment.global_rate_per_minute", differs: differ(func(c Config) int { return c.Enrollment.GlobalRatePerMinute })},
	{key: "enrollment.global_burst", differs: differ(func(c Config) int { return c.Enrollment.GlobalBurst })},
	{key: "enrollment.max_tracked_ips", differs: differ(func(c Config) int { return c.Enrollment.MaxTrackedIPs })},
	{key: "enrollment.max_nodes", differs: differ(func(c Config) int { return c.Enrollment.MaxNodes })},
	{key: "enrollment.cert_expiring_fraction", differs: differ(func(c Config) float64 { return c.Enrollment.CertExpiringFraction })},
}

// Diff returns one Change per setting whose value differs between running and
// next, in schema order. It is pure: no I/O, and no value in its result.
func Diff(running, next Config) []Change {
	var out []Change
	for _, s := range settings {
		if !s.differs(running, next) {
			continue
		}
		out = append(out, Change{Key: s.key, Secret: s.secret, RestartRequired: restartRequired[s.key]})
	}
	return out
}
