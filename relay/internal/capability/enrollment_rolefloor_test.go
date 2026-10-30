package capability_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

// The role ladder is the real authz.RoleGate, so this file is an external test
// package (authz imports capability).

// mintTrail is an AuditSink that keeps every entry and an
// EnrollmentMintRecorder that keeps every mint.
type mintTrail struct {
	nopAuditSink
	mu      sync.Mutex
	entries []capability.AuditEntry
	mints   []capability.EnrollmentMintEvent
}

func (m *mintTrail) Record(_ context.Context, e capability.AuditEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	return nil
}

func (m *mintTrail) RecordEnrollmentTokenMint(_ context.Context, e capability.EnrollmentMintEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mints = append(m.mints, e)
	return nil
}

type countingIssuer struct {
	mu      sync.Mutex
	issued  []capability.EnrollmentMint
	minters []capability.Principal
}

func (c *countingIssuer) IssueEnrollmentToken(_ context.Context, p capability.Principal, req capability.EnrollmentMint) (capability.MintedEnrollmentToken, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.issued = append(c.issued, req)
	c.minters = append(c.minters, p)
	return capability.NewMintedEnrollmentToken("tok-1", "cred", "join", req.InitialTags, time.Now().Add(req.TTL), req.MaxUses, req.Unlimited), nil
}

func (c *countingIssuer) WithdrawEnrollmentToken(context.Context, string) error { return nil }

// Proves EN-36.
func TestEnrollmentTokens_MintIsAdminOnlyOnTheSameControlAction(t *testing.T) {
	req := capability.EnrollmentMint{MaxUses: 2, TTL: time.Hour, InitialTags: []string{"tag:env=prod"}}

	refused := []struct {
		name string
		p    capability.Principal
	}{
		{"a human viewer", principal("viewer", capability.PrincipalKindHuman)},
		{"a human operator", principal("operator", capability.PrincipalKindHuman)},
		{"an operator machine Account", principal("operator", "machine")},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			trail, issuer := &mintTrail{}, &countingIssuer{}
			ctl := capability.NewControl(capability.NewRecorder(trail, nil, nil), authz.NewRoleGate(), neverFrozen{})
			_, err := capability.NewEnrollmentTokens(ctl, issuer).MintEnrollmentToken(context.Background(), tc.p, req)
			if !errors.Is(err, authz.ErrUnauthorized) || !strings.Contains(err.Error(), "minting an Enrollment Token") {
				t.Errorf("err = %v, want an authz refusal naming the act", err)
			}
			if len(trail.entries) != 1 || len(trail.mints) != 0 || len(issuer.issued) != 0 {
				t.Errorf("entries = %d, mints = %d, issued = %d, want one refusal and nothing minted",
					len(trail.entries), len(trail.mints), len(issuer.issued))
			}
		})
	}

	trail, issuer := &mintTrail{}, &countingIssuer{}
	ctl := capability.NewControl(capability.NewRecorder(trail, nil, nil), authz.NewRoleGate(), neverFrozen{})
	if _, err := capability.NewEnrollmentTokens(ctl, issuer).MintEnrollmentToken(context.Background(), humanAdmin, req); err != nil {
		t.Fatalf("a human admin was refused: %v", err)
	}
	if len(issuer.issued) != 1 || issuer.issued[0].MaxUses != 2 || len(issuer.issued[0].InitialTags) != 1 || len(trail.mints) != 1 {
		t.Errorf("issued = %+v, mints = %d, want the request unchanged and one record", issuer.issued, len(trail.mints))
	}
}
