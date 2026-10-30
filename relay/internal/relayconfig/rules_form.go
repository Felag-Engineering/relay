package relayconfig

import "strings"

const (
	keyRules = "approval.rules"

	// reasonRulesForm is fixed text: it names no value, no rule and no source
	// line (RC-18).
	reasonRulesForm = "must be written as [[approval.rules]] sections, one per rule"
)

// withinRules reports whether a header key is the rules section or a table
// under it.
func withinRules(headerKey string) bool {
	return headerKey == keyRules || strings.HasPrefix(headerKey, keyRules+".")
}
