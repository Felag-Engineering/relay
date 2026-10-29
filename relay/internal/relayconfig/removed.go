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

// movedKeys are keys whose setting moved into the file itself (RC-37). They are
// refused like removedKeys, but kept apart because RC-44 names a closed set.
var movedKeys = map[string]string{
	"approval.gate_rules_path": "is no longer accepted: gate rules are [[approval.rules]] sections of this file; move each rule here and remove the key",
}

// removedRuleFields are the fields a gate rule used to carry and no longer does
// (AP-81). A rule names only what it matches and its ttl.
var removedRuleFields = map[string]bool{
	"count":             true,
	"audience":          true,
	"requester_allowed": true,
	"channel":           true,
}

const reasonRemovedRuleField = "is not a gate-rule field: a rule names only what it matches and its ttl; remove it"

// removedKey reports whether parts names a removed key, or something under one
// (a table written where the key was), and if so its key, its reason, and how
// many leading segments of parts the key spans: 2 for a section's key, 3 for a
// gate-rule field.
func removedKey(parts []string) (key, reason string, depth int, ok bool) {
	if len(parts) < 2 {
		return "", "", 0, false
	}
	if len(parts) >= 3 && parts[0] == "approval" && parts[1] == "rules" && removedRuleFields[parts[2]] {
		return "approval.rules." + parts[2], reasonRemovedRuleField, 3, true
	}
	key = parts[0] + "." + parts[1]
	if reason, ok = removedKeys[key]; ok {
		return key, reason, 2, true
	}
	reason, ok = movedKeys[key]
	return key, reason, 2, ok
}
