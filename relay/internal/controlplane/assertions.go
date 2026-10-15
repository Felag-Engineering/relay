package controlplane

import (
	"net/http"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// Asserted-attribution request headers (ADR-0027
// decision 10; docs/specs/approval.md).
//
// Headers rather than tool arguments or a request-body field, for three
// reasons. They are uniform across both surfaces — MCP rides Streamable HTTP,
// so one mechanism covers MCP tool calls and /api/v1 calls identically. They
// are set by the *harness* rather than chosen by the model, which does not
// make them trustworthy but does make them meaningfully less
// model-influenced. And `traceparent` is already a standard header (W3C Trace
// Context), so accepting it anywhere else would be inventing a second spelling
// for something the ecosystem already agrees on.
const (
	// HeaderTraceparent is the standard W3C Trace Context header, taken
	// verbatim under its own name.
	HeaderTraceparent = "traceparent"

	// The Relay-specific asserted fields. `X-Relay-` prefixed so they cannot
	// be confused with anything standard, and so an operator reading a request
	// log can see at a glance which headers this system consumes.
	HeaderOnBehalfOf = "X-Relay-On-Behalf-Of"
	HeaderSessionRef = "X-Relay-Session-Ref"
	HeaderChangeRef  = "X-Relay-Change-Ref"
)

// assertionsFromRequest reads the asserted-attribution headers off r and
// validates them against audit's bound and character rule.
//
// It returns the caller-facing error verbatim when validation fails, because
// unlike an authentication failure there is no oracle concern here: the caller
// supplied these values, already knows them, and needs to be told which header
// was wrong so they can fix it.
func assertionsFromRequest(r *http.Request) (capability.Assertions, error) {
	a := audit.Asserted{
		OnBehalfOf:  r.Header.Get(HeaderOnBehalfOf),
		Traceparent: r.Header.Get(HeaderTraceparent),
		SessionRef:  r.Header.Get(HeaderSessionRef),
		ChangeRef:   r.Header.Get(HeaderChangeRef),
	}
	if err := audit.ValidateAsserted(a); err != nil {
		return capability.Assertions{}, err
	}
	return capability.Assertions{
		OnBehalfOf:  a.OnBehalfOf,
		Traceparent: a.Traceparent,
		SessionRef:  a.SessionRef,
		ChangeRef:   a.ChangeRef,
	}, nil
}

// badAssertedAttribution writes the 400 for a malformed asserted header.
//
// A refusal, not a truncation: a shortened session id or traceparent joins to
// nothing, so quietly trimming one produces an audit record that looks
// complete and is not. The caller controls the value and the fix is trivial.
func badAssertedAttribution(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(err.Error() + "\n")) //nolint:gosec // G705: served as text/plain (set above), so nothing is interpreted as HTML
}
