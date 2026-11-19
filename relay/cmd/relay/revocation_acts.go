package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/revocation"
)

// revocationActs hands the capability layer's Revocations the revocation act it
// cannot import. It decides nothing: authorization, the reason rule and the
// records are capability.Revocations' (invariant 10).
type revocationActs struct {
	svc *revocation.Service
}

var _ capability.Revoker = revocationActs{}

// RevokeNodeRecorded revokes one Node, recording before the act under the
// Node's lock.
func (a revocationActs) RevokeNodeRecorded(ctx context.Context, nodeID string, record func(nodeIDs []string) error) error {
	return capabilityRevokeError(a.svc.RevokeNodeRecorded(ctx, nodeID, record))
}

// RevokeToken revokes an Enrollment Token and cascades to every Node it
// enrolled.
func (a revocationActs) RevokeToken(ctx context.Context, tokenID string, record func(nodeIDs []string) error) error {
	return capabilityRevokeError(a.svc.RevokeToken(ctx, tokenID, record))
}

// capabilityRevokeError maps the cascade's two outcome errors onto the
// capability layer's sentinels, keeping the original matchable. An
// IncompleteCascade never wraps ErrCascadeNotRecorded, so the order is free,
// and any other error, context.Canceled included, passes through unchanged.
func capabilityRevokeError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, revocation.ErrCascadeIncomplete):
		return fmt.Errorf("%w: %w", capability.ErrRevokeCascadeIncomplete, err)
	case errors.Is(err, revocation.ErrCascadeNotRecorded):
		return fmt.Errorf("%w: %w", capability.ErrRevokeCascadeNotRecorded, err)
	default:
		return err
	}
}
