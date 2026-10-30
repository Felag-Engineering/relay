package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/enroll"
)

// enrollmentTokenIssuer hands the capability layer's Enrollment Token mint the
// enroll.Minter it cannot import. It decides nothing: authorization, the input
// bounds and the record are capability.EnrollmentTokens' (invariant 10).
type enrollmentTokenIssuer struct {
	minter *enroll.Minter
	tokens *enroll.Service
}

var _ capability.EnrollmentTokenIssuer = enrollmentTokenIssuer{}

// IssueEnrollmentToken mints a token for req.MaxUses Nodes. It never sets
// enroll.UseLimit.Unlimited.
func (i enrollmentTokenIssuer) IssueEnrollmentToken(ctx context.Context, p capability.Principal, req capability.EnrollmentMint) (capability.MintedEnrollmentToken, error) {
	minted, err := i.minter.Mint(ctx, req.InitialTags, req.TTL, enroll.UseLimit{MaxUses: req.MaxUses}, enroll.WithMinter(p.AccountID, p))
	switch {
	case err == nil:
	case errors.Is(err, enroll.ErrInvalidInitialTags):
		return capability.MintedEnrollmentToken{}, fmt.Errorf("%w: %w", capability.ErrEnrollmentInitialTags, err)
	case errors.Is(err, enroll.ErrInitialTagsNeedHuman):
		return capability.MintedEnrollmentToken{}, capability.ErrEnrollmentInitialTagsNeedHuman
	case errors.Is(err, enroll.ErrInvalidTTL):
		return capability.MintedEnrollmentToken{}, capability.ErrEnrollmentTTL
	case errors.Is(err, enroll.ErrInvalidUseLimit):
		return capability.MintedEnrollmentToken{}, capability.ErrEnrollmentUseLimit
	default:
		return capability.MintedEnrollmentToken{}, fmt.Errorf("enrollment mint: %w", err)
	}
	tok := minted.Token()
	return capability.NewMintedEnrollmentToken(tok.ID, minted.JoinString(), tok.InitialTags, tok.ExpiresAt, tok.MaxUses), nil
}

// WithdrawEnrollmentToken revokes a token nobody holds, the primitive
// enroll.Minter.Mint uses itself. No cascade is needed: the join string was
// never shown, so no Node can have enrolled under it.
func (i enrollmentTokenIssuer) WithdrawEnrollmentToken(ctx context.Context, tokenID string) error {
	return i.tokens.Revoke(ctx, tokenID)
}
