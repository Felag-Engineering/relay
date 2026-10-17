package relayconfig

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// retiredEnv maps each RELAY_* name the Relay once read to the key that
// replaced it. The Relay reads no setting from the environment (ADR-0043
// decision 6), so a retired name that is still set is a refusal rather than a
// silently ignored override.
//
// Not mapped, because neither is a startup setting: the Freeze lever's
// operator note, read when its signal arrives, and the devharness test seam.
var retiredEnv = map[string]string{
	"RELAY_ADDR":                         "node_plane.listen_address",
	"RELAY_CONTROL_ENABLED":              "control_plane.enabled",
	"RELAY_CONTROL_ADDR":                 "control_plane.listen_address",
	"RELAY_CONSOLE_ENABLED":              "console.enabled",
	"RELAY_CONSOLE_SESSION_MAX_AGE":      "console.session_max_age",
	"RELAY_CONSOLE_SESSION_IDLE":         "console.session_idle",
	"RELAY_CONSOLE_STEP_UP_WINDOW":       "console.step_up_window",
	"RELAY_CA_DIR":                       "ca.dir",
	"RELAY_STORE_PATH":                   "store.path",
	"RELAY_HOSTNAME":                     "tls.hostname",
	"RELAY_OAUTH_ISSUER":                 "oauth.issuer",
	"RELAY_OAUTH_AUDIENCE":               "oauth.audience",
	"RELAY_OAUTH_ACCOUNT_CLAIM":          "oauth.account_claim",
	"RELAY_OAUTH_REQUIRED_SCOPE":         "oauth.required_scope",
	"RELAY_OAUTH_PUBLIC_URL":             "oauth.public_url",
	"RELAY_APPROVAL_GATE_CONFIG":         "approval.gate_rules_path",
	"RELAY_APPROVAL_WEBHOOK_URL":         keyWebhookURL,
	"RELAY_APPROVAL_WEBHOOK_SECRET_FILE": keyWebhookSecret,
	"RELAY_APPROVAL_WEBHOOK_TIMEOUT":     keyWebhookTimeout,
	"RELAY_READ_BLAST_CAP":               "reach.read_blast_cap",
	"RELAY_MUTATE_BLAST_CAP":             "reach.mutate_blast_cap",
	"RELAY_DISPATCH_CONCURRENCY":         "reach.dispatch_concurrency",
	"RELAY_MIN_DAEMON_VERSION":           "reach.min_daemon_version",
	"RELAY_ENROLL_IP_RATE":               "enrollment.ip_rate_per_minute",
	"RELAY_ENROLL_IP_BURST":              "enrollment.ip_burst",
	"RELAY_ENROLL_GLOBAL_RATE":           "enrollment.global_rate_per_minute",
	"RELAY_ENROLL_GLOBAL_BURST":          "enrollment.global_burst",
	"RELAY_ENROLL_MAX_TRACKED_IPS":       "enrollment.max_tracked_ips",
	"RELAY_MAX_NODES":                    "enrollment.max_nodes",
	"RELAY_CERT_EXPIRING_FRACTION":       "enrollment.cert_expiring_fraction",
}

// secretKeys are the keys that also take an _file spelling.
var secretKeys = map[string]string{
	keyWebhookURL:    keyWebhookURLFile,
	keyWebhookSecret: keyWebhookSecFile,
}

// RefuseRetiredEnv refuses an environment that still sets a retired name, even
// with an empty value. The caller passes os.Environ(); this package reads no
// environment. The error lists every such name and never a value.
func RefuseRetiredEnv(environ []string) error {
	var found []string
	for _, kv := range environ {
		name, _, _ := strings.Cut(kv, "=")
		if _, ok := retiredEnv[name]; ok {
			found = append(found, name)
		}
	}
	if len(found) == 0 {
		return nil
	}
	sort.Strings(found)
	found = slices.Compact(found)
	lines := make([]string, len(found))
	for i, name := range found {
		key := retiredEnv[name]
		if file, ok := secretKeys[key]; ok {
			key += " or " + file
		}
		lines[i] = fmt.Sprintf("%s is set in the environment; the Relay reads no setting from the environment — set %s in the configuration file", name, key)
	}
	return fmt.Errorf("configuration: %s", strings.Join(lines, "; "))
}
