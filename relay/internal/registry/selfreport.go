// The bounds for what a Node reports about itself, applied at the ingress
// (ADR-0017: a self-report is trusted only as much as the Node). A value that
// fails is omitted, never sanitised. Labels are bounded by MaxLabelKeyLen and
// MaxLabelValueLen in label.go.
package registry

// MaxSelfReportedTextBytes bounds a self-reported free-text field in bytes: the
// Facts strings and the daemon version. It is the longest DNS name; Linux
// HOST_NAME_MAX is 64, so a well-behaved Node never nears it. Without it a
// value is bounded only by gRPC's message cap. It does not bound Labels.
const MaxSelfReportedTextBytes = 253

// WellFormedFingerprint reports whether fp is exactly 64 lowercase hexadecimal
// characters: the daemon's SHA-256 rendering of a Policy fingerprint and of a
// template-set fingerprint.
func WellFormedFingerprint(fp string) bool {
	if len(fp) != 64 {
		return false
	}
	for i := 0; i < len(fp); i++ {
		c := fp[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// WellFormedSelfReportedText reports whether s is at most
// MaxSelfReportedTextBytes long and made only of printable, non-space ASCII
// (0x21..0x7E). The empty string is well-formed: absence is not a refusal.
//
// It is a byte loop on purpose. Any non-ASCII rune (U+202E, U+2028, a
// zero-width space, U+2800) carries a byte >= 0x80, and whitespace and control
// bytes fall outside the range, so one check closes oversize, bidi spoofing and
// imitation of Console wording together.
func WellFormedSelfReportedText(s string) bool {
	if len(s) > MaxSelfReportedTextBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7E {
			return false
		}
	}
	return true
}
