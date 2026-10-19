package capability

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// policyalias.go is the Policy alias capability: the admin-only audited write
// (PolicyAliasAdmin) and the recorded read (ReadLane.PolicyAliases).
//
// A Policy alias is a display name the Relay holds for a Policy fingerprint. It
// is not Policy and never leaves the Relay (invariant 2): it is not a Selector
// term, not part of a Plan, and not sent to a Node. It attaches to a
// fingerprint and nothing else (invariant 9). The decision — who may write,
// what a name may be, that one name names one fingerprint, that every change is
// on the trail — is made here and never per interface (invariant 10).

// toolListPolicyAliases is the read record's tool name.
const toolListPolicyAliases = "list_policy_aliases"

// maxPolicyAliasRunes bounds an alias, in Unicode code points after trimming.
const maxPolicyAliasRunes = 64

// ReadLaneOption configures a ReadLane built by NewReadLane.
type ReadLaneOption func(*ReadLane)

// WithPolicyAliasSource wires the Policy alias read into the lane.
func WithPolicyAliasSource(src PolicyAliasSource) ReadLaneOption {
	return func(l *ReadLane) { l.aliases = src }
}

// Refusals and failures of the Policy alias capability. Their text names the
// rule and never echoes caller input into the trail.
var (
	ErrPolicyAliasesUnavailable    = errors.New("capability: Policy aliases are not configured on this Relay")
	ErrPolicyFingerprintMalformed  = errors.New("capability: a Policy alias must name a well-formed Policy fingerprint: 64 lowercase hexadecimal characters")
	ErrPolicyAliasEmpty            = errors.New("capability: a Policy alias is empty after trimming")
	ErrPolicyAliasTooLong          = errors.New("capability: a Policy alias is longer than 64 characters")
	ErrPolicyAliasControlCharacter = errors.New("capability: a Policy alias contains a control or format character (Unicode Cc or Cf)")
	ErrPolicyAliasInvalidUTF8      = errors.New("capability: a Policy alias is not valid UTF-8")
	ErrPolicyAliasTaken            = errors.New("capability: a Policy alias already names another Policy fingerprint; one alias names at most one fingerprint")
	ErrPolicyAliasChanged          = errors.New("capability: a Policy alias changed while this change was being made; reload and retry")
)

// PolicyAliases returns every Policy alias held, fingerprint to alias. One call
// is one recorded read, so a consumer rendering a page calls it once per render.
//
// The read is recorded first and fails closed (ADR-0025): an unrecordable read
// returns ErrReadUnaudited before the source is touched. Like every lane read
// it needs authentication and nothing more (QRY-15). An unwired source is an
// error, never an empty map.
func (l *ReadLane) PolicyAliases(ctx context.Context, p Principal) (map[string]string, error) {
	if l.aliases == nil {
		return nil, ErrPolicyAliasesUnavailable
	}
	if err := l.auditSinkPresent(); err != nil {
		return nil, err
	}
	if err := l.recordQueryRead(ctx, p, toolListPolicyAliases, "", "", ""); err != nil {
		return nil, err
	}
	held, err := l.aliases.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("capability: list policy aliases: %w", err)
	}
	out := make(map[string]string, len(held))
	for fp, alias := range held {
		out[fp] = alias
	}
	return out, nil
}

// ValidPolicyFingerprint reports whether fp is a well-formed Policy
// fingerprint: exactly 64 lowercase hexadecimal characters, the daemon's
// SHA-256 rendering. Exported so a surface consumes the rule rather than
// re-deriving it.
func ValidPolicyFingerprint(fp string) bool {
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

// NormalizePolicyAlias returns the alias that is stored for s, or the rule it
// breaks. strings.TrimSpace removes Unicode White_Space at the ends, which
// includes some Cc runes (TAB, LF, CR, U+0085); the control and format rule
// applies to what remains. Uniqueness is exact equality of the result.
func NormalizePolicyAlias(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", ErrPolicyAliasInvalidUTF8
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ErrPolicyAliasEmpty
	}
	if utf8.RuneCountInString(s) > maxPolicyAliasRunes {
		return "", ErrPolicyAliasTooLong
	}
	for _, r := range s {
		if unicode.Is(unicode.Cc, r) || unicode.Is(unicode.Cf, r) {
			return "", ErrPolicyAliasControlCharacter
		}
	}
	return s, nil
}

// PolicyAliasAdmin sets, renames and clears Policy aliases: admin and human
// Account only, no step-up, every change on the audit trail in the same
// transaction as the change. Construct it with NewPolicyAliasAdmin.
type PolicyAliasAdmin struct {
	control *Control
	src     PolicyAliasSource
	rec     PolicyAliasRecorder
}

// NewPolicyAliasAdmin returns a PolicyAliasAdmin over control and src. It
// requires a real Authorizer and an AuditSink that is also a
// PolicyAliasRecorder, read through control, so there is one Recorder and one
// trail: an un-floored or unaudited alias write is a composition-root bug and
// panics.
func NewPolicyAliasAdmin(control *Control, src PolicyAliasSource) *PolicyAliasAdmin {
	if control == nil {
		panic("capability: NewPolicyAliasAdmin: control must not be nil")
	}
	if src == nil {
		panic("capability: NewPolicyAliasAdmin: alias source must not be nil")
	}
	if _, ok := control.authz.(allowAllAuthorizer); ok {
		panic("capability: NewPolicyAliasAdmin: requires a real Authorizer (NewControl); allowAllAuthorizer would fail open on every alias write")
	}
	if _, ok := control.rec.audit.(noopAuditSink); ok {
		panic("capability: NewPolicyAliasAdmin: requires a real AuditSink (NewRecorder); noopAuditSink would record no alias change")
	}
	rec, ok := control.rec.audit.(PolicyAliasRecorder)
	if !ok {
		panic("capability: NewPolicyAliasAdmin: the AuditSink must also be a PolicyAliasRecorder; without it a change cannot be recorded atomically")
	}
	return newPolicyAliasAdmin(control, src, rec)
}

// newPolicyAliasAdmin assembles a PolicyAliasAdmin with no checks. Only
// NewPolicyAliasAdmin and _test.go files call it.
func newPolicyAliasAdmin(control *Control, src PolicyAliasSource, rec PolicyAliasRecorder) *PolicyAliasAdmin {
	return &PolicyAliasAdmin{control: control, src: src, rec: rec}
}

// SetPolicyAlias gives fingerprint the alias name, renaming it if it has one.
// Setting the alias a fingerprint already carries is a successful no-op and
// records nothing.
//
// Refusals (role, human-only, malformed fingerprint, invalid name, name taken)
// are audited as refusals through refuseControl, like ReleaseFreeze's missing
// reason. A store conflict (ErrPolicyAliasChanged) changed nothing and is
// returned unaudited.
func (a *PolicyAliasAdmin) SetPolicyAlias(ctx context.Context, p Principal, fingerprint, name string) error {
	if a.src == nil || a.rec == nil {
		return ErrPolicyAliasesUnavailable
	}
	if err := a.control.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlPolicyAlias); err != nil {
		return a.control.rec.refuseControl(ctx, p, err)
	}
	if !ValidPolicyFingerprint(fingerprint) {
		return a.control.rec.refuseControl(ctx, p, ErrPolicyFingerprintMalformed)
	}
	name, err := NormalizePolicyAlias(name)
	if err != nil {
		return a.control.rec.refuseControl(ctx, p, err)
	}
	held, err := a.src.List(ctx)
	if err != nil {
		return fmt.Errorf("capability: list policy aliases: %w", err)
	}
	if held[fingerprint] == name {
		return nil
	}
	for fp, alias := range held {
		if alias == name && fp != fingerprint {
			return a.control.rec.refuseControl(ctx, p, ErrPolicyAliasTaken)
		}
	}
	return a.record(ctx, p, fingerprint, held[fingerprint], name)
}

// ClearPolicyAlias removes fingerprint's alias. Clearing an unset alias is not
// an error and records nothing.
func (a *PolicyAliasAdmin) ClearPolicyAlias(ctx context.Context, p Principal, fingerprint string) error {
	if a.src == nil || a.rec == nil {
		return ErrPolicyAliasesUnavailable
	}
	if err := a.control.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlPolicyAlias); err != nil {
		return a.control.rec.refuseControl(ctx, p, err)
	}
	if !ValidPolicyFingerprint(fingerprint) {
		return a.control.rec.refuseControl(ctx, p, ErrPolicyFingerprintMalformed)
	}
	held, err := a.src.List(ctx)
	if err != nil {
		return fmt.Errorf("capability: list policy aliases: %w", err)
	}
	if held[fingerprint] == "" {
		return nil
	}
	return a.record(ctx, p, fingerprint, held[fingerprint], "")
}

// record makes the change and its audit record in one transaction.
func (a *PolicyAliasAdmin) record(ctx context.Context, p Principal, fingerprint, old, name string) error {
	err := a.rec.RecordPolicyAlias(ctx, PolicyAliasEvent{
		Principal:   p,
		Fingerprint: fingerprint,
		Old:         old,
		New:         name,
		Asserted:    AssertionsFromContext(ctx),
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrPolicyAliasTaken):
		return a.control.rec.refuseControl(ctx, p, ErrPolicyAliasTaken)
	case errors.Is(err, ErrPolicyAliasChanged):
		return ErrPolicyAliasChanged
	default:
		return fmt.Errorf("capability: record policy alias change: %w", err)
	}
}
