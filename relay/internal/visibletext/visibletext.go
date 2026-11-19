// Package visibletext renders an untrusted string so that no character a
// reader cannot see, and none that reorders what they see, is drawn raw
// (AP-97; the same rule governs the Console, audit views and log lines in
// docs/specs/audit-and-read-lane.md and docs/specs/observability.md).
//
// Escaped: C0 and C1 controls, DEL, zero-width and other invisible
// characters, bidirectional controls, every Unicode space except the ASCII
// space, and invalid UTF-8 bytes. Three forms, lowercase hex, fixed width:
//
//	\u + 4 digits   a hidden rune up to U+FFFF
//	\U + 8 digits   a hidden rune above U+FFFF
//	\x + 2 digits   one invalid UTF-8 byte
//
// A backslash is written \u005c when the next unit is a backslash, u, U, x,
// a double quote or any escaped unit, and, in Quote, when it ends the value.
// So in the output a raw backslash is never followed by a backslash, u, U, x
// or a double quote, and never precedes Quote's closing quote: it never
// begins an escape, never escapes a quote, and never sits against an escape
// where a reader could join the two. Every other backslash is written as
// itself, so a Policy regex such as ^/usr/bin/systemctl\s+status reads as
// written.
//
// Escape, Block and Quote are injective over every byte string: a
// left-to-right decoder reads each escape as its own unit and every other
// character literally, so two different values never render the same. That
// keeps clustering and diffing exact on rendered text. Prose is not
// injective and nothing may compare, cluster or hash its output.
package visibletext

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

const hexDigits = "0123456789abcdef"

// Escape renders s on one line.
func Escape(s string) string { return escape(s, false, false) }

// Block renders s as Escape does but leaves U+000A raw, for multi-line output
// drawn in a pre element where the newline is the block's structure. TAB and
// CR are still escaped.
func Block(s string) string { return escape(s, true, false) }

// Quote renders s as Escape does with the double quote also escaped, then
// wraps it in double quotes, so a value cannot forge an argument boundary.
func Quote(s string) string { return `"` + escape(s, false, true) + `"` }

// Prose escapes only hidden runes and invalid bytes, in the same forms, and
// applies no backslash or quote rule. It is for Relay-authored text that
// already embeds caller values quoted with %q, whose own escapes it must not
// double. Its output is not injective.
func Prose(s string) string {
	var b strings.Builder
	last := 0
	changed := false
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		invalid := r == utf8.RuneError && size == 1
		if !invalid && !hidden(r) {
			i += size
			continue
		}
		b.WriteString(s[last:i])
		writeUnit(&b, s[i:i+size], r, invalid)
		i += size
		last = i
		changed = true
	}
	if !changed {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

func escape(s string, keepLF, quote bool) string {
	var b strings.Builder
	last := 0
	changed := false
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		invalid := r == utf8.RuneError && size == 1
		switch {
		case r == '\\' && !invalid:
			if !backslashTriggers(s[i+size:], keepLF, quote) {
				i += size
				continue
			}
			b.WriteString(s[last:i])
			b.WriteString(`\u005c`)
		case escapedUnit(r, invalid, keepLF, quote):
			b.WriteString(s[last:i])
			if r == '"' && !invalid {
				b.WriteString(`\u0022`)
			} else {
				writeUnit(&b, s[i:i+size], r, invalid)
			}
		default:
			i += size
			continue
		}
		i += size
		last = i
		changed = true
	}
	if !changed {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// backslashTriggers reports whether a backslash followed by rest must be
// written as an escape. It decodes the next unit and tests it with the same
// predicate the main loop uses, so the two cannot disagree.
func backslashTriggers(rest string, keepLF, quote bool) bool {
	if rest == "" {
		return quote
	}
	r, size := utf8.DecodeRuneInString(rest)
	invalid := r == utf8.RuneError && size == 1
	if invalid {
		return true
	}
	switch r {
	case '\\', 'u', 'U', 'x', '"':
		return true
	}
	return escapedUnit(r, invalid, keepLF, quote)
}

func escapedUnit(r rune, invalid, keepLF, quote bool) bool {
	if invalid {
		return true
	}
	if r == '"' && quote {
		return true
	}
	if r == '\n' && keepLF {
		return false
	}
	return hidden(r)
}

// hidden reports whether r draws nothing, reorders neighbouring text, or is a
// space other than the ASCII space.
func hidden(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f:
		return true
	case r < 0x80:
		return false
	case r <= 0x9f, r == 0x2800:
		return true
	}
	return unicode.In(r, unicode.White_Space, unicode.Zs, unicode.Zl, unicode.Zp,
		unicode.Cf, unicode.Bidi_Control, unicode.Other_Default_Ignorable_Code_Point,
		unicode.Variation_Selector)
}

// writeUnit writes the escape for one hidden rune or invalid byte. raw is the
// unit's source bytes, used for an invalid byte.
func writeUnit(b *strings.Builder, raw string, r rune, invalid bool) {
	switch {
	case invalid:
		b.WriteString(`\x`)
		writeHex(b, int(raw[0]), 2)
	case r <= 0xFFFF:
		b.WriteString(`\u`)
		writeHex(b, int(r), 4)
	default:
		b.WriteString(`\U`)
		writeHex(b, int(r), 8)
	}
}

func writeHex(b *strings.Builder, v, width int) {
	for shift := 4 * (width - 1); shift >= 0; shift -= 4 {
		b.WriteByte(hexDigits[(v>>shift)&0xf])
	}
}
