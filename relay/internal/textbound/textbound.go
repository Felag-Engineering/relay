// Package textbound bounds attacker-influenced strings to a byte budget
// without splitting a UTF-8 rune. It imports only unicode/utf8.
package textbound

import "unicode/utf8"

// Truncate returns s cut to at most n bytes on a rune boundary, and whether it
// cut. A cut never leaves an invalid UTF-8 fragment at the end of the result.
func Truncate(s string, n int) (string, bool) {
	if len(s) <= n {
		return s, false
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}
