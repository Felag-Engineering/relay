package relayconfig

import "slices"

// Change is one setting whose value differs between two configurations. It
// carries the setting's key and never a value, so a list of Changes is safe to
// log and to audit (RC-18).
type Change struct {
	// Key is "section.key" as the schema spells it. A secret is named by its
	// `_file` key (approval.webhook_url_file, approval.webhook_secret_file).
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

// reloadClass says what a reload does with a changed setting. The zero value is
// deliberately unclassified, which Diff treats as restart-required: a setting
// nobody classified is never applied live by default (RC-21).
type reloadClass int

const (
	unclassified reloadClass = iota
	// restartRequired is RC-21's bind-time list: the setting's consumer is
	// built once at start and no reload reaches it. The OAuth identity provider
	// is the whole [oauth] section. console.session_idle is beyond RC-21's
	// enumeration and awaits the owner's ratification: the Console's
	// authentication is constructed with it once, and a reload that silently
	// did not apply it would leave the file and the running Relay
	// disagreeing. tls.extra_names is bind-time by RC-47: the
	// certificate's names are fixed at start.
	restartRequired
	// appliedByReload is a setting whose consumer reads the live snapshot.
	appliedByReload
)

// setting is one logical setting: how to tell whether two configurations
// differ in it, and what a reload does with a change.
type setting struct {
	key     string
	class   reloadClass
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

// settings lists every logical setting in schema order;
// TestDiff_EverySchemaKeyClassified pins that no schema key is left out.
var settings = []setting{
	{key: "node_plane.listen_address", class: restartRequired, differs: differ(func(c Config) string { return c.NodePlane.ListenAddress })},
	{key: "node_plane.advertised_address", class: restartRequired, differs: differ(func(c Config) string { return c.NodePlane.AdvertisedAddress })},
	{key: "control_plane.enabled", class: restartRequired, differs: differ(func(c Config) bool { return c.ControlPlane.Enabled })},
	{key: "control_plane.listen_address", class: restartRequired, differs: differ(func(c Config) string { return c.ControlPlane.ListenAddress })},
	{key: "console.enabled", class: restartRequired, differs: differ(func(c Config) bool { return c.Console.Enabled })},
	{key: "console.session_idle", class: restartRequired, differs: differ(func(c Config) int64 { return int64(c.Console.SessionIdle) })},
	{key: "ca.dir", class: restartRequired, differs: differ(func(c Config) string { return c.CA.Dir })},
	{key: "store.path", class: restartRequired, differs: differ(func(c Config) string { return c.Store.Path })},
	{key: "tls.hostname", class: restartRequired, differs: differ(func(c Config) string { return c.TLS.Hostname })},
	{key: "tls.extra_names", class: restartRequired, differs: func(a, b Config) bool { return !slices.Equal(a.TLS.ExtraNames, b.TLS.ExtraNames) }},
	{key: "oauth.issuer", class: restartRequired, differs: differ(func(c Config) string { return c.OAuth.Issuer })},
	{key: "oauth.audience", class: restartRequired, differs: differ(func(c Config) string { return c.OAuth.Audience })},
	{key: "oauth.account_claim", class: restartRequired, differs: differ(func(c Config) string { return c.OAuth.AccountClaim })},
	{key: "oauth.required_scope", class: restartRequired, differs: differ(func(c Config) string { return c.OAuth.RequiredScope })},
	{key: "oauth.public_url", class: restartRequired, differs: differ(func(c Config) string { return c.OAuth.PublicURL })},
	{key: "approval.rules", class: appliedByReload, differs: func(a, b Config) bool { return !slices.Equal(a.Approval.Rules, b.Approval.Rules) }},
	{key: "approval.webhook_url_file", class: appliedByReload, secret: true, differs: secretDiffers(func(c Config) Secret { return c.Approval.WebhookURL })},
	{key: "approval.webhook_secret_file", class: appliedByReload, secret: true, differs: secretDiffers(func(c Config) Secret { return c.Approval.WebhookSecret })},
	{key: "log.level", class: appliedByReload, differs: differ(func(c Config) int { return int(c.Log.Level) })},
	{key: "reach.read_blast_cap", class: appliedByReload, differs: differ(func(c Config) int { return c.Reach.ReadBlastCap })},
	{key: "reach.mutate_blast_cap", class: appliedByReload, differs: differ(func(c Config) int { return c.Reach.MutateBlastCap })},
	{key: "reach.min_daemon_version", class: appliedByReload, differs: differ(func(c Config) string { return c.Reach.MinDaemonVersion })},
	{key: "enrollment.max_nodes", class: appliedByReload, differs: differ(func(c Config) int { return c.Enrollment.MaxNodes })},
}

// Diff returns one Change per setting whose value differs between running and
// next, in schema order. It is pure: no I/O, and no value in its result.
func Diff(running, next Config) []Change {
	var out []Change
	for _, s := range settings {
		if !s.differs(running, next) {
			continue
		}
		out = append(out, Change{Key: s.key, Secret: s.secret, RestartRequired: s.class != appliedByReload})
	}
	return out
}
