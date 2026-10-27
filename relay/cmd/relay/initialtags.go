package main

import (
	"context"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/enroll"
)

// initialTagWriter hands the Enrollment service the capability layer's tag
// write. The service records who minted a token as plain values, because it
// cannot import the capability layer; this rebuilds that Account as the
// Principal the tag write authorizes and records, and decides nothing itself
// (invariant 10).
type initialTagWriter struct {
	tags *capability.TagWriter
}

var _ enroll.InitialTagWriter = initialTagWriter{}

func (w initialTagWriter) CheckInitialTags(ctx context.Context, minter enroll.MintedBy, tags []string) error {
	return w.tags.CheckInitialTags(ctx, minterPrincipal(minter), tags)
}

func (w initialTagWriter) WriteInitialTags(ctx context.Context, minter enroll.MintedBy, tokenID, nodeID string, tags []string) error {
	return w.tags.WriteInitialTags(ctx, minterPrincipal(minter), tokenID, nodeID, tags)
}

func minterPrincipal(minter enroll.MintedBy) capability.Principal {
	p := capability.Principal{AccountID: minter.AccountID, Account: minter.Account, Role: minter.Role}
	if minter.Human {
		p.Kind = capability.PrincipalKindHuman
	}
	return p
}
