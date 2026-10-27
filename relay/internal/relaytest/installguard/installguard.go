// Package installguard is the name matcher shared by the per-surface absence tests
// that prove no Relay surface installs, configures or upgrades a daemon (the
// installation spec's DI-18, invariant 14). Each surface's test feeds it the names the
// surface registers: a tool, a route, an RPC, a wire field.
//
// A name is split into words and the words are compared with Terms, so `upgrade_daemon`
// and `InstallDaemon` hit and `task_cancel` does not. The matcher flags a name; it
// cannot see behaviour, which is why the Node plane also pins its RPC set outright.
//
// Like its parent relaytest, installguard links into no production binary: only
// _test.go files import it (depguard `relaytest-is-test-only`).
package installguard

import (
	"strings"
	"unicode"
)

// Terms are the words that name installing, configuring or upgrading a daemon, or the
// things that are installed. The list is deliberately broad: a legitimate name that
// hits is renamed or its test is reviewed, which is cheaper than a missed verb.
var Terms = []string{
	"install", "uninstall", "reinstall", "upgrade", "downgrade", "update",
	"binary", "package", "pkg", "deploy", "provision", "bootstrap",
	"configure", "config", "configuration", "setting", "settings",
	"unit", "systemd", "daemon", "artifact", "rollout",
}

// Words splits name on every non-alphanumeric rune and at lower-to-upper camel
// boundaries, lowercased.
func Words(name string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = nil
		}
	}
	var prev rune
	for _, r := range name {
		switch {
		case !unicode.IsLetter(r) && !unicode.IsDigit(r):
			flush()
		case unicode.IsUpper(r) && unicode.IsLower(prev):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
		prev = r
	}
	flush()
	return words
}

// Hits returns the words of name that are Terms.
func Hits(name string) []string {
	var hits []string
	for _, w := range Words(name) {
		for _, term := range Terms {
			if w == term {
				hits = append(hits, w)
				break
			}
		}
	}
	return hits
}
