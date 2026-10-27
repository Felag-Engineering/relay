// The bounds for what a Node reports about itself (ADR-0017: a self-report is
// trusted only as much as the Node). One rule holds at both ends: the Hello and
// Enroll ingresses refuse a value that fails, and the read-back of a stored
// Node record declines one stored before the ingress was bounded. A value that
// fails is omitted, never sanitised.
package registry

import (
	"net/netip"
	"slices"
)

// MaxSelfReportedTextBytes bounds a self-reported free-text field in bytes: the
// Facts strings and the daemon version. It is the longest DNS name; Linux
// HOST_NAME_MAX is 64, so a well-behaved Node never nears it. Without it a
// value is bounded only by gRPC's message cap. It does not bound Labels.
const MaxSelfReportedTextBytes = 253

// TemplateUnloadable is the literal the daemon reports in place of a
// template-set fingerprint when its local set failed to load (ADR-0021).
const TemplateUnloadable = "unloadable"

// The names of the self-reported fields a bound can omit, as the proto names
// them. They are the closed vocabulary an omission is logged under: a log line
// names the field and never carries the value.
const (
	FieldPolicyFingerprint      = "policy_fingerprint"
	FieldTemplateSetFingerprint = "template_set_fingerprint"
	FieldDaemonVersion          = "daemon_version"
	FieldHostname               = "facts.hostname"
	FieldOS                     = "facts.os"
	FieldKernel                 = "facts.kernel"
	FieldArch                   = "facts.arch"
	FieldIPAddresses            = "facts.ip_addresses"
)

// SelfReport is what a Node reports about itself apart from its Labels: the
// part of a Node record the self-report bounds govern. Labels are bounded by
// WellFormedNodeLabel.
type SelfReport struct {
	Facts                  Facts
	PolicyFingerprint      string
	TemplateSetFingerprint string
	DaemonVersion          string
}

// DeclineMalformedSelfReport returns r with every field that fails its bound
// omitted, and the names of the omitted fields from the Field* set, in a fixed
// order. A text field that fails becomes "", which is an outcome the Node could
// choose by reporting nothing; an address that is not a plain IP is dropped
// from the list. Nothing is rewritten (ADR-0017).
//
// The IP list keeps the nil-versus-empty distinction: it is returned unchanged
// when every entry passes, and rebuilt from nil when one is dropped, so an
// all-dropped list is nil.
//
// For template_set_fingerprint "" means "no templates loaded", not "not
// reported", so a malformed value reads as the Node claiming no templates: a
// claim it could make for itself, and one that gains it no Template reach.
func DeclineMalformedSelfReport(r SelfReport) (SelfReport, []string) {
	var omitted []string
	text := func(field string, v *string) {
		if !WellFormedSelfReportedText(*v) {
			*v = ""
			omitted = append(omitted, field)
		}
	}
	text(FieldHostname, &r.Facts.Hostname)
	text(FieldOS, &r.Facts.OS)
	text(FieldKernel, &r.Facts.Kernel)
	text(FieldArch, &r.Facts.Arch)

	if slices.ContainsFunc(r.Facts.IPAddresses, func(s string) bool { return !WellFormedIPAddress(s) }) {
		var kept []string
		for _, s := range r.Facts.IPAddresses {
			if WellFormedIPAddress(s) {
				kept = append(kept, s)
			}
		}
		r.Facts.IPAddresses = kept
		omitted = append(omitted, FieldIPAddresses)
	}

	if !WellFormedReportedPolicyFingerprint(r.PolicyFingerprint) {
		r.PolicyFingerprint = ""
		omitted = append(omitted, FieldPolicyFingerprint)
	}
	if !WellFormedReportedTemplateSetFingerprint(r.TemplateSetFingerprint) {
		r.TemplateSetFingerprint = ""
		omitted = append(omitted, FieldTemplateSetFingerprint)
	}
	if !WellFormedReportedDaemonVersion(r.DaemonVersion) {
		r.DaemonVersion = ""
		omitted = append(omitted, FieldDaemonVersion)
	}
	return r, omitted
}

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

// WellFormedReportedPolicyFingerprint reports whether fp may be recorded as a
// Node's Policy fingerprint: "" (not reported) or WellFormedFingerprint.
func WellFormedReportedPolicyFingerprint(fp string) bool {
	return fp == "" || WellFormedFingerprint(fp)
}

// WellFormedReportedTemplateSetFingerprint reports whether fp may be recorded
// as a Node's template-set fingerprint: "" (no templates loaded),
// TemplateUnloadable, or WellFormedFingerprint.
func WellFormedReportedTemplateSetFingerprint(fp string) bool {
	return fp == "" || fp == TemplateUnloadable || WellFormedFingerprint(fp)
}

// WellFormedReportedDaemonVersion reports whether v may be recorded as a
// Node's daemon version: "" (not reported), or valid semver of at most
// MaxSelfReportedTextBytes. The length is checked before the parse.
func WellFormedReportedDaemonVersion(v string) bool {
	return v == "" || (len(v) <= MaxSelfReportedTextBytes && ValidVersion(v))
}

// WellFormedIPAddress reports whether s is a plain IP address, IPv4 or IPv6,
// with no zone.
func WellFormedIPAddress(s string) bool {
	addr, err := netip.ParseAddr(s)
	return err == nil && addr.Zone() == ""
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
