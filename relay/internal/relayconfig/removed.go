package relayconfig

// removedKeys are the keys the configuration file no longer accepts (RC-44).
// A file that names one is refused at start and on reload, naming the key. The
// set is closed and written here, so rendering a member can never print a value
// or a line of source text (RC-18).
var removedKeys = map[string]string{
	"enrollment.ip_rate_per_minute":     reasonBuiltIn,
	"enrollment.ip_burst":               reasonBuiltIn,
	"enrollment.global_rate_per_minute": reasonBuiltIn,
	"enrollment.global_burst":           reasonBuiltIn,
	"enrollment.max_tracked_ips":        reasonBuiltIn,
	"enrollment.cert_expiring_fraction": reasonBuiltIn,
	"reach.dispatch_concurrency":        reasonBuiltIn,
	"approval.webhook_timeout":          reasonBuiltIn,
	"log.format":                        reasonBuiltIn,
	"console.session_max_age":           reasonBuiltIn,
	"console.step_up_window":            reasonBuiltIn,
	"approval.webhook_url":              "is no longer accepted inline: name a file holding it with approval.webhook_url_file",
	"approval.webhook_secret":           "is no longer accepted inline: name a file holding it with approval.webhook_secret_file",
}

const reasonBuiltIn = "is no longer a setting: the Relay uses a built-in value; remove the key"

// removedKey reports whether parts names a removed key, or something under one
// (a table written where the key was), and if so its key and reason.
func removedKey(parts []string) (key, reason string, ok bool) {
	if len(parts) < 2 {
		return "", "", false
	}
	key = parts[0] + "." + parts[1]
	reason, ok = removedKeys[key]
	return key, reason, ok
}
