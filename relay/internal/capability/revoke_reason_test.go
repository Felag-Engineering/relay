package capability

import (
	"errors"
	"strings"
	"testing"
)

// bad builds a string carrying exactly one hazardous code point, written by
// NUMBER rather than as a literal or an escape.
//
// Deliberate: this file's subject is characters that are invisible or that
// reorder the text around them, and a test for those must not contain any. A
// literal U+202E here would reorder this source in the reviewer's editor, and
// an escape would still be a character a careless copy-paste could smuggle
// somewhere. rune(0x202e) is greppable, reviewable and inert.
func bad(before string, cp rune, after string) string {
	return before + string(cp) + after
}

// TestValidateRevokeReason is the direct test for the #487 gate. It exists
// because every other test of this rule reaches it through an HTTP handler,
// and none of those passes a bidi override, a zero-width character or a C1
// control -- so deleting isBidiOrZeroWidth's switch body, or the call to it,
// passed the entire suite green.
//
// Every malformed case carries ONE hazard, not a bundle: a payload with four
// bad characters at once is still refused after three of the four checks are
// deleted, which is how a table like this ends up proving nothing.
func TestValidateRevokeReason(t *testing.T) {
	t.Run("accepted", func(t *testing.T) {
		cases := []struct {
			name string
			raw  string
			want string
		}{
			{"a plain sentence", "compromised host, INC-4471", "compromised host, INC-4471"},
			{"surrounding whitespace is trimmed", "  decommissioned\t\n ", "decommissioned"},
			{"interior punctuation and digits", "ticket OPS-91: disk failure (rack 3)", "ticket OPS-91: disk failure (rack 3)"},
			{"non-ASCII prose is fine -- this is not an allowlist",
				bad("au", 0x00df, "er Betrieb genommen"), bad("au", 0x00df, "er Betrieb genommen")},
			{"exactly at the cap", strings.Repeat("x", MaxRevokeReasonBytes), strings.Repeat("x", MaxRevokeReasonBytes)},
			{"multi-byte runes are counted as bytes, not characters",
				strings.Repeat(string(rune(0x00e9)), MaxRevokeReasonBytes/2),
				strings.Repeat(string(rune(0x00e9)), MaxRevokeReasonBytes/2)},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := ValidateRevokeReason(tc.raw)
				if err != nil {
					t.Fatalf("ValidateRevokeReason(%q) error = %v, want nil", tc.raw, err)
				}
				if got != tc.want {
					t.Errorf("ValidateRevokeReason(%q) = %q, want %q", tc.raw, got, tc.want)
				}
			})
		}
	})

	t.Run("refused", func(t *testing.T) {
		cases := []struct {
			name string
			raw  string
			want error
		}{
			{"empty", "", ErrRevokeReasonRequired},
			{"spaces only", "     ", ErrRevokeReasonRequired},
			{"tabs and newlines only", "\t\n\r ", ErrRevokeReasonRequired},
			{"non-breaking space only -- unicode.IsSpace, so it trims to empty",
				string(rune(0x00a0)), ErrRevokeReasonRequired},

			{"one byte over the cap", strings.Repeat("x", MaxRevokeReasonBytes+1), ErrRevokeReasonTooLong},
			{"under the cap in characters but over it in bytes",
				strings.Repeat(string(rune(0x00e9)), MaxRevokeReasonBytes/2+1), ErrRevokeReasonTooLong},

			{"interior newline", "revoked\nby nobody", ErrRevokeReasonMalformed},
			{"interior tab", "revoked\tby nobody", ErrRevokeReasonMalformed},
			{"NUL", "revoked\x00", ErrRevokeReasonMalformed},
			{"DEL", "revoked\x7f", ErrRevokeReasonMalformed},
			{"C1 NEL -- a line break the C0 check alone misses",
				bad("revoked", 0x0085, "next line"), ErrRevokeReasonMalformed},
			{"C1 lower bound", bad("revoked", 0x0080, ""), ErrRevokeReasonMalformed},
			{"C1 upper bound", bad("revoked", 0x009f, ""), ErrRevokeReasonMalformed},

			{"lone continuation byte", "revoked \x80", ErrRevokeReasonMalformed},
			{"truncated two-byte sequence", "revoked \xc3", ErrRevokeReasonMalformed},
			{"overlong encoding of a slash", "revoked \xc0\xaf", ErrRevokeReasonMalformed},
			{"surrogate half", "revoked \xed\xa0\x80", ErrRevokeReasonMalformed},
			{"out-of-range four-byte form", "revoked \xf4\x90\x80\x80", ErrRevokeReasonMalformed},

			{"RLO override", bad("revoked ", 0x202e, "gnihton"), ErrRevokeReasonMalformed},
			{"LRO override", bad("revoked ", 0x202d, "text"), ErrRevokeReasonMalformed},
			{"LRE embedding", bad("revoked ", 0x202a, "text"), ErrRevokeReasonMalformed},
			{"pop directional formatting", bad("revoked ", 0x202c, "text"), ErrRevokeReasonMalformed},
			{"zero-width space", bad("rev", 0x200b, "oked"), ErrRevokeReasonMalformed},
			{"zero-width non-joiner", bad("rev", 0x200c, "oked"), ErrRevokeReasonMalformed},
			{"zero-width joiner", bad("rev", 0x200d, "oked"), ErrRevokeReasonMalformed},
			{"LTR mark", bad("revoked", 0x200e, ""), ErrRevokeReasonMalformed},
			{"RTL mark", bad("revoked", 0x200f, ""), ErrRevokeReasonMalformed},
			{"word joiner", bad("rev", 0x2060, "oked"), ErrRevokeReasonMalformed},
			{"first strong isolate", bad("revoked ", 0x2068, "x"), ErrRevokeReasonMalformed},
			{"pop directional isolate", bad("revoked ", 0x2069, "x"), ErrRevokeReasonMalformed},
			{"BOM mid-string", bad("revoked", 0xfeff, "host"), ErrRevokeReasonMalformed},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := ValidateRevokeReason(tc.raw)
				if !errors.Is(err, tc.want) {
					t.Fatalf("ValidateRevokeReason(%q) error = %v, want %v", tc.raw, err, tc.want)
				}
				if got != "" {
					t.Errorf("a refused reason returned %q, want the empty string -- a caller "+
						"that ignores the error must not be handed a usable value", got)
				}
			})
		}
	})
}

// TestIsBidiOrZeroWidthCoversWhatItsCommentClaims guards the hand-written list
// against a later edit that trims it. Separate from the table above because
// that one proves the CHECK runs; this one proves the LIST is whole.
func TestIsBidiOrZeroWidthCoversWhatItsCommentClaims(t *testing.T) {
	for _, cp := range []rune{
		0x200b, 0x200c, 0x200d, 0x200e, 0x200f,
		0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
		0x2060,
		0x2066, 0x2067, 0x2068, 0x2069,
		0xfeff,
	} {
		if !isBidiOrZeroWidth(cp) {
			t.Errorf("isBidiOrZeroWidth(%U) = false, want true", cp)
		}
	}
	// And it must not over-reach. The last four pin the edges of the two listed
	// runs -- 0x200a and 0x2010 bracket the 200b-200f run, 0x2065 and 0x206a
	// bracket 2066-2069 -- so widening either run fails here.
	for _, cp := range []rune{
		'a', '0', ' ', 0x00e9, 0x00df, 0x4e2d,
		0x200a, 0x2010, 0x2065, 0x206a,
	} {
		if isBidiOrZeroWidth(cp) {
			t.Errorf("isBidiOrZeroWidth(%U) = true, want false", cp)
		}
	}
}
