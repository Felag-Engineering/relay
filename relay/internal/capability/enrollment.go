package capability

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// enrollment.go is the Console's Enrollment Token mint. The admin floor, the
// input bounds and the record are decided here and never per interface
// (invariant 10). Only the Console is handed it: the Control API keeps its own
// mint route and an AI-agent surface has no mint.

// Refusals and failures of the Enrollment Token mint. Each message is constant
// and never echoes input.
var (
	ErrEnrollmentTokensUnavailable    = errors.New("capability: Enrollment Token minting is not configured on this Relay")
	ErrEnrollmentUseLimit             = errors.New("capability: an Enrollment Token is minted for a positive number of Nodes; this mint has no unlimited form")
	ErrEnrollmentTTL                  = errors.New("capability: an Enrollment Token's expiry is positive and at most one year")
	ErrEnrollmentInitialTags          = errors.New("capability: an initial tag was refused")
	ErrEnrollmentInitialTagsNeedHuman = errors.New("capability: only a human Account writes tags, so a machine Account's mint names no initial tag (ADR-0050)")
	ErrEnrollmentMintNotRecorded      = errors.New("capability: the mint could not be recorded, so its join string was discarded")
	ErrEnrollmentTokenMayBeLive       = errors.New("capability: the mint could not be recorded and the token could not be withdrawn, so it may still be live")
)

// EnrollmentTokenLiveError reports a mint that could be neither recorded nor
// withdrawn: the token may admit a Node until it expires, and nobody holds its
// join string. It carries the public token ID, never the join string or secret,
// so an operator can revoke the token. It matches ErrEnrollmentTokenMayBeLive and
// ErrEnrollmentMintNotRecorded, and unwraps to both underlying failures.
type EnrollmentTokenLiveError struct {
	TokenID     string
	RecordErr   error
	WithdrawErr error
}

func (e *EnrollmentTokenLiveError) Error() string {
	return ErrEnrollmentTokenMayBeLive.Error() + " (token_id=" + e.TokenID + "): " +
		e.RecordErr.Error() + "; " + e.WithdrawErr.Error()
}

// Unwrap returns the sentinels and both failures for errors.Is and errors.As.
func (e *EnrollmentTokenLiveError) Unwrap() []error {
	return []error{ErrEnrollmentTokenMayBeLive, ErrEnrollmentMintNotRecorded, e.RecordErr, e.WithdrawErr}
}

const (
	// MaxEnrollmentTokenTTL is the longest an Enrollment Token may live.
	MaxEnrollmentTokenTTL = 365 * 24 * time.Hour
	// DefaultEnrollmentTokenTTL is the expiry a mint form offers first (ADR-0048).
	DefaultEnrollmentTokenTTL = 2 * time.Hour
)

// EnrollmentMint is one mint request. MaxUses is the number of Nodes the token
// is for and must be positive. InitialTags are in written form, tag:key=value,
// and are passed unparsed to the issuer, which decides them. There is
// deliberately no unlimited field: this mint cannot ask for unlimited use.
type EnrollmentMint struct {
	MaxUses     int
	TTL         time.Duration
	InitialTags []string
}

// MintedEnrollmentToken is a minted token as the caller may show it once. The
// join string is held behind a pointer and the type owns every fmt verb, so
// neither fmt nor slog reaches it.
type MintedEnrollmentToken struct {
	id          string
	initialTags []string
	expiresAt   time.Time
	maxUses     int
	joinString  *string
}

// NewMintedEnrollmentToken assembles a MintedEnrollmentToken. It copies initialTags.
func NewMintedEnrollmentToken(id, joinString string, initialTags []string, expiresAt time.Time, maxUses int) MintedEnrollmentToken {
	return MintedEnrollmentToken{
		id:          id,
		initialTags: append([]string(nil), initialTags...),
		expiresAt:   expiresAt,
		maxUses:     maxUses,
		joinString:  &joinString,
	}
}

// ID is the token's public identifier.
func (m MintedEnrollmentToken) ID() string { return m.id }

// InitialTags returns a copy of the token's initial tags.
func (m MintedEnrollmentToken) InitialTags() []string {
	return append([]string(nil), m.initialTags...)
}

// ExpiresAt is when the token stops admitting Nodes.
func (m MintedEnrollmentToken) ExpiresAt() time.Time { return m.expiresAt }

// MaxUses is the number of Nodes the token is for.
func (m MintedEnrollmentToken) MaxUses() int { return m.maxUses }

// JoinString is the text a Node's operator pastes at the join prompt. Handle it
// as a secret.
func (m MintedEnrollmentToken) JoinString() string {
	if m.joinString == nil {
		return ""
	}
	return *m.joinString
}

// String renders only the token ID.
func (m MintedEnrollmentToken) String() string {
	return "MintedEnrollmentToken{token_id=" + m.id + " join_string=[REDACTED]}"
}

// GoString renders the same redacted text for %#v.
func (m MintedEnrollmentToken) GoString() string { return m.String() }

// Format owns every verb.
func (m MintedEnrollmentToken) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(m.String())) }

// LogValue implements slog.LogValuer; the group carries only the token ID.
func (m MintedEnrollmentToken) LogValue() slog.Value {
	return slog.GroupValue(slog.String("token_id", m.id))
}

// EnrollmentTokens mints Enrollment Tokens for the Console: an admin, a
// positive number of Nodes, a bounded expiry, and a token_mint record. Construct
// it with NewEnrollmentTokens.
type EnrollmentTokens struct {
	control *Control
	issuer  EnrollmentTokenIssuer
	rec     EnrollmentMintRecorder
}

// NewEnrollmentTokens returns an EnrollmentTokens over control and issuer. It
// requires a real Authorizer and an AuditSink that is also an
// EnrollmentMintRecorder, read through control, so there is one Recorder and one
// trail: an un-floored or unrecorded mint is a composition-root bug and panics.
func NewEnrollmentTokens(control *Control, issuer EnrollmentTokenIssuer) *EnrollmentTokens {
	if control == nil {
		panic("capability: NewEnrollmentTokens: control must not be nil")
	}
	if issuer == nil {
		panic("capability: NewEnrollmentTokens: issuer must not be nil")
	}
	if _, ok := control.authz.(allowAllAuthorizer); ok {
		panic("capability: NewEnrollmentTokens: requires a real Authorizer (NewControl); allowAllAuthorizer would fail open on every mint")
	}
	if _, ok := control.rec.audit.(noopAuditSink); ok {
		panic("capability: NewEnrollmentTokens: requires a real AuditSink (NewRecorder); noopAuditSink would record no mint")
	}
	rec, ok := control.rec.audit.(EnrollmentMintRecorder)
	if !ok {
		panic("capability: NewEnrollmentTokens: the AuditSink must also be an EnrollmentMintRecorder; without it a mint cannot be recorded")
	}
	return newEnrollmentTokens(control, issuer, rec)
}

// newEnrollmentTokens assembles an EnrollmentTokens with no checks. Only
// NewEnrollmentTokens and _test.go files call it.
func newEnrollmentTokens(control *Control, issuer EnrollmentTokenIssuer, rec EnrollmentMintRecorder) *EnrollmentTokens {
	return &EnrollmentTokens{control: control, issuer: issuer, rec: rec}
}

// MintEnrollmentToken mints a token for req.MaxUses Nodes and records it.
//
// Authorization runs first, at ControlMintEnrollmentToken, so a refused caller
// learns nothing about the input rules; a refusal is audited (invariant 10,
// ADR-0032 decision 5, kept by ADR-0048). The use limit and expiry bounds are
// refused unaudited. The token rules for initial tags are the issuer's
// (ADR-0050); a machine Account naming one is an audited refusal. When the mint
// cannot be recorded the token is withdrawn and nothing is returned: no record
// names it and nobody will hold its join string. If the withdrawal fails too the
// error is an *EnrollmentTokenLiveError naming the token.
func (e *EnrollmentTokens) MintEnrollmentToken(ctx context.Context, p Principal, req EnrollmentMint) (MintedEnrollmentToken, error) {
	if e.issuer == nil || e.rec == nil {
		return MintedEnrollmentToken{}, ErrEnrollmentTokensUnavailable
	}
	if err := e.control.authz.AuthorizeControl(withoutAssertions(ctx), p, ControlMintEnrollmentToken); err != nil {
		return MintedEnrollmentToken{}, e.control.rec.refuseControl(ctx, p, err)
	}
	if req.MaxUses < 1 {
		return MintedEnrollmentToken{}, ErrEnrollmentUseLimit
	}
	if req.TTL <= 0 || req.TTL > MaxEnrollmentTokenTTL {
		return MintedEnrollmentToken{}, ErrEnrollmentTTL
	}
	minted, err := e.issuer.IssueEnrollmentToken(ctx, p, req)
	if err != nil {
		if errors.Is(err, ErrEnrollmentInitialTagsNeedHuman) {
			return MintedEnrollmentToken{}, e.control.rec.refuseControl(ctx, p, err)
		}
		return MintedEnrollmentToken{}, err
	}
	recErr := e.rec.RecordEnrollmentTokenMint(ctx, EnrollmentMintEvent{
		Principal: p,
		TokenID:   minted.ID(),
		Asserted:  AssertionsFromContext(ctx),
	})
	if recErr != nil {
		// No record names this token and nobody will hold its join string, so it
		// is withdrawn rather than left live.
		if wdErr := e.issuer.WithdrawEnrollmentToken(context.WithoutCancel(ctx), minted.ID()); wdErr != nil {
			return MintedEnrollmentToken{}, &EnrollmentTokenLiveError{TokenID: minted.ID(), RecordErr: recErr, WithdrawErr: wdErr}
		}
		return MintedEnrollmentToken{}, fmt.Errorf("%w: %w", ErrEnrollmentMintNotRecorded, recErr)
	}
	return minted, nil
}
