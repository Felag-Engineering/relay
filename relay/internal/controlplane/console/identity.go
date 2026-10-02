package console

import "strings"

// maxHostnameBytes is the longest DNS name (RFC 1035).
const maxHostnameBytes = 253

// selfReportedTitle is the tooltip on any self-reported name drawn as a visual
// primary. It is one const so the layout (the Node detail heading) and the
// screens (a Fleet row) say the same thing.
const selfReportedTitle = "Self-reported by this Node's daemon. Nothing checked it — the Node ID is the identity its certificate proves."

// primaryHostname returns the Node's hostname when it may stand as the visual
// primary of a heading or a row, and "" when the caller must fall back to the
// Node ID.
//
// The hostname is self-reported: the Node's daemon says it and nothing checks
// it. So only RFC 1123 hostname characters (plus "_", which real hosts carry)
// may become a heading, with an alphanumeric first byte and at most
// maxHostnameBytes. That mirrors accounts.ValidateName's display-spoofing
// reasoning: it keeps invisible, bidi-reordering, combining and non-ASCII
// lookalike characters out of a heading. Checking bytes is enough because every
// allowed byte is ASCII, so any multi-byte rune fails.
//
// A value shaped like a Node ID never becomes the primary: it would let a Node
// wear another Node's verified identity as its heading. Shaped like one means
// looksLikeNodeID: "node" then only hex, of any length to be conservative, with
// case, any suffix after the first ".", and every "-" and "_" ignored. It falls
// back to the full Node ID like any other unusable value.
//
// It does NOT stop a Node choosing a misleading ASCII name, such as another
// machine's hostname. That is why the verified Node ID is always rendered
// beside it. The raw value still appears verbatim in Node detail's Facts panel.
func primaryHostname(h string) string {
	h = strings.TrimSpace(h)
	if h == "" || len(h) > maxHostnameBytes || !isASCIIAlnum(h[0]) {
		return ""
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !isASCIIAlnum(c) && c != '.' && c != '_' && c != '-' {
			return ""
		}
	}
	if looksLikeNodeID(h) {
		return ""
	}
	return h
}

// looksLikeNodeID reports whether h, folded the way a reader's eye folds it,
// is "node" followed only by hex characters. Folding: lower-case, cut at the
// first "." (so "node-<hex>." and "node-<hex>.local" match), and drop every "-"
// and "_" (so "node_<hex>", "node--<hex>" and "node-<hex>-" match).
func looksLikeNodeID(h string) bool {
	h, _, _ = strings.Cut(strings.ToLower(h), ".")
	h = strings.NewReplacer("-", "", "_", "").Replace(h)
	rest, ok := strings.CutPrefix(h, "node")
	if !ok || rest == "" {
		return false
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func isASCIIAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
