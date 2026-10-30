package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/enroll"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

const mintTestFingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type mintTestFingerprintSource struct{}

func (mintTestFingerprintSource) Fingerprint() string { return mintTestFingerprint }

// countingTokenRepo counts Creates, so a refused mint can be shown to have
// stored nothing.
type countingTokenRepo struct {
	enroll.Repository
	mu      sync.Mutex
	creates int
}

func (c *countingTokenRepo) Create(ctx context.Context, t *enroll.Token) error {
	c.mu.Lock()
	c.creates++
	c.mu.Unlock()
	return c.Repository.Create(ctx, t)
}

func (c *countingTokenRepo) created() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.creates
}

func newMintTestIssuer(t *testing.T) (enrollmentTokenIssuer, *countingTokenRepo, *enroll.Service) {
	t.Helper()
	repo := &countingTokenRepo{Repository: enroll.NewMemoryRepository()}
	svc := enroll.NewService(repo)
	minter, err := enroll.NewMinter(svc, mintTestFingerprintSource{}, "relay.example.com:7654")
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	return enrollmentTokenIssuer{minter: minter, tokens: svc}, repo, svc
}

var mintTestHuman = capability.Principal{AccountID: "acct-admin", Account: "mike", Role: "admin", Kind: capability.PrincipalKindHuman}

// Proves EN-36.
func TestEnrollmentTokenIssuer_MintsTheNumberOfNodesGivenAndAJoinStringCarryingIt(t *testing.T) {
	issuer, repo, _ := newMintTestIssuer(t)
	req := capability.EnrollmentMint{MaxUses: 4, TTL: 2 * time.Hour, InitialTags: []string{"tag:env=prod"}}

	minted, err := issuer.IssueEnrollmentToken(context.Background(), mintTestHuman, req)
	if err != nil {
		t.Fatalf("IssueEnrollmentToken: %v", err)
	}
	js, err := enroll.DecodeJoinString(minted.JoinString())
	if err != nil {
		t.Fatalf("DecodeJoinString: %v", err)
	}
	if !strings.HasPrefix(js.EnrollmentToken(), minted.ID()+".") {
		t.Errorf("the join string's token does not start with %q.", minted.ID())
	}

	stored, err := repo.ByID(context.Background(), minted.ID())
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if stored.MaxUses != 4 || stored.MaxUses != minted.MaxUses() {
		t.Errorf("stored MaxUses = %d (minted %d), want 4", stored.MaxUses, minted.MaxUses())
	}
	if d := time.Until(stored.ExpiresAt) - req.TTL; d > time.Minute || d < -time.Minute {
		t.Errorf("ExpiresAt is %v from now plus the TTL", d)
	}
	if stored.CreatedByAccountID != "acct-admin" || !stored.CreatedByHuman {
		t.Errorf("minter = %q human=%v, want the calling Account, human", stored.CreatedByAccountID, stored.CreatedByHuman)
	}
	if len(stored.InitialTags) != 1 || stored.InitialTags[0] != "tag:env=prod" {
		t.Errorf("InitialTags = %v", stored.InitialTags)
	}
}

// Proves EN-40, EN-35.
func TestEnrollmentTokenIssuer_MalformedOrRelayTagRefusesAndIsNeverRewritten(t *testing.T) {
	for _, entry := range []string{"env=prod", "tag:bad key=x", "relay:node-id=x", " tag:env=prod "} {
		issuer, repo, _ := newMintTestIssuer(t)
		_, err := issuer.IssueEnrollmentToken(context.Background(), mintTestHuman,
			capability.EnrollmentMint{MaxUses: 1, TTL: time.Hour, InitialTags: []string{entry}})
		var tagErr *registry.InitialTagError
		if !errors.Is(err, capability.ErrEnrollmentInitialTags) || !errors.As(err, &tagErr) || tagErr.Entry != entry {
			t.Errorf("entry %q: err = %v, want ErrEnrollmentInitialTags naming it", entry, err)
		}
		if repo.created() != 0 {
			t.Errorf("entry %q: a refused mint stored a token", entry)
		}
	}

	issuer, repo, _ := newMintTestIssuer(t)
	_, err := issuer.IssueEnrollmentToken(context.Background(), mintTestHuman,
		capability.EnrollmentMint{MaxUses: 1, TTL: time.Hour, InitialTags: []string{"tag:a=1", "tag:a=2"}})
	if !errors.Is(err, capability.ErrEnrollmentInitialTags) || !errors.Is(err, registry.ErrInitialTagKeyTwice) || repo.created() != 0 {
		t.Errorf("a duplicated key: err = %v, creates = %d", err, repo.created())
	}
}

// Proves EN-44.
func TestEnrollmentTokenIssuer_MachineMinterNamingTagsIsRefused(t *testing.T) {
	issuer, repo, _ := newMintTestIssuer(t)
	machine := capability.Principal{AccountID: "acct-bot", Account: "bot", Role: "admin", Kind: "machine"}
	_, err := issuer.IssueEnrollmentToken(context.Background(), machine,
		capability.EnrollmentMint{MaxUses: 1, TTL: time.Hour, InitialTags: []string{"tag:env=prod"}})
	if !errors.Is(err, capability.ErrEnrollmentInitialTagsNeedHuman) || repo.created() != 0 {
		t.Errorf("err = %v, creates = %d, want ErrEnrollmentInitialTagsNeedHuman and nothing stored", err, repo.created())
	}
}

func TestEnrollmentTokenIssuer_WithdrawRevokesTheToken(t *testing.T) {
	issuer, _, svc := newMintTestIssuer(t)
	minted, err := issuer.IssueEnrollmentToken(context.Background(), mintTestHuman,
		capability.EnrollmentMint{MaxUses: 1, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	js, err := enroll.DecodeJoinString(minted.JoinString())
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.WithdrawEnrollmentToken(context.Background(), minted.ID()); err != nil {
		t.Fatalf("WithdrawEnrollmentToken: %v", err)
	}
	if _, err := svc.Validate(context.Background(), js.EnrollmentToken()); !errors.Is(err, enroll.ErrRevoked) {
		t.Errorf("Validate after withdraw = %v, want ErrRevoked", err)
	}
}
