package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/enroll"
)

// mintSink is the capability layer's audit seam for a mint: it keeps every
// Record entry and every EnrollmentMintEvent, and fails the mint record when
// recordErr is set.
type mintSink struct {
	*fakeCapabilityAuditSink
	mu        sync.Mutex
	entries   []capability.AuditEntry
	events    []capability.EnrollmentMintEvent
	recordErr error
}

func newMintSink() *mintSink { return &mintSink{fakeCapabilityAuditSink: &fakeCapabilityAuditSink{}} }

func (s *mintSink) Record(_ context.Context, e capability.AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, e)
	return nil
}

func (s *mintSink) RecordEnrollmentTokenMint(_ context.Context, e capability.EnrollmentMintEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recordErr != nil {
		return s.recordErr
	}
	s.events = append(s.events, e)
	return nil
}

func (s *mintSink) mintEvents() []capability.EnrollmentMintEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]capability.EnrollmentMintEvent(nil), s.events...)
}

func (s *mintSink) refusals() []capability.AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []capability.AuditEntry
	for _, e := range s.entries {
		if e.Kind == capability.AuditKindRefusal {
			out = append(out, e)
		}
	}
	return out
}

// apiTestIssuer mirrors cmd/relay's enrollmentTokenIssuer over a real
// enroll.Minter, with the same error mapping; cmd/relay's enrollmentmint_test.go
// proves the production adapter. withdrawErr makes the withdrawal fail.
type apiTestIssuer struct {
	minter      *enroll.Minter
	tokens      *enroll.Service
	withdrawErr error
}

func (i apiTestIssuer) IssueEnrollmentToken(ctx context.Context, p capability.Principal, req capability.EnrollmentMint) (capability.MintedEnrollmentToken, error) {
	minted, err := i.minter.Mint(ctx, req.InitialTags, req.TTL, enroll.UseLimit{MaxUses: req.MaxUses, Unlimited: req.Unlimited}, enroll.WithMinter(p.AccountID, p))
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
	return capability.NewMintedEnrollmentToken(tok.ID, minted.Plaintext(), minted.JoinString(), tok.InitialTags, tok.ExpiresAt, tok.MaxUses, tok.Unlimited()), nil
}

func (i apiTestIssuer) WithdrawEnrollmentToken(ctx context.Context, tokenID string) error {
	if i.withdrawErr != nil {
		return i.withdrawErr
	}
	return i.tokens.Revoke(ctx, tokenID)
}

// newTestEnrollmentTokensWithSink builds the real capability mint over svc, the
// production RoleGate and sink, as the composition root hands it to Deps.Tokens.
func newTestEnrollmentTokensWithSink(t *testing.T, svc *enroll.Service, sink *mintSink) TokenMinter {
	t.Helper()
	return newTestEnrollmentTokensWithWithdrawErr(t, svc, sink, nil)
}

func newTestEnrollmentTokensWithWithdrawErr(t *testing.T, svc *enroll.Service, sink capability.AuditSink, withdrawErr error) TokenMinter {
	t.Helper()
	minter, err := enroll.NewMinter(svc, fakeFingerprint{}, "relay.test:7654")
	if err != nil {
		t.Fatalf("enroll.NewMinter: %v", err)
	}
	control := capability.NewControl(capability.NewRecorder(sink, nil, nil), authz.NewRoleGate(), neverFrozen{})
	return capability.NewEnrollmentTokens(control, apiTestIssuer{minter: minter, tokens: svc, withdrawErr: withdrawErr})
}

// newTestEnrollmentTokens is newTestEnrollmentTokensWithSink with a sink the
// caller does not inspect.
func newTestEnrollmentTokens(t *testing.T, svc *enroll.Service) TokenMinter {
	t.Helper()
	return newTestEnrollmentTokensWithSink(t, svc, newMintSink())
}

// Proves EN-36, EN-1.
func TestHandleMintToken_WritesOneTokenMintRecordThroughTheCapabilityLayer(t *testing.T) {
	sink := newMintSink()
	auditor := &fakeAuditor{}
	d := Deps{Tokens: newTestEnrollmentTokensWithSink(t, enroll.NewService(enroll.NewMemoryRepository()), sink), Audit: auditor, Now: fixedNow}
	h := newTestHandler(d)

	rec := do(t, h, http.MethodPost, "/api/v1/enrollment-tokens", mintTokenRequest{TTLSeconds: 3600, MaxUses: 1})
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
	var resp mintTokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	events := sink.mintEvents()
	if len(events) != 1 || events[0].TokenID != resp.ID || events[0].Principal.Account != testAdmin().Account {
		t.Fatalf("capability mint events = %+v, want exactly one naming %s and the caller", events, resp.ID)
	}
	if got := auditor.all(); len(got) != 0 {
		t.Errorf("the surface wrote %d audit records, want 0: the record is the capability layer's", len(got))
	}
}

// Proves EN-4, EN-1.
func TestHandleMintToken_AnUnrecordedMintIsWithdrawnAndReturnsNothing(t *testing.T) {
	t.Run("withdrawn", func(t *testing.T) {
		repo := &createdIDRepo{Repository: enroll.NewMemoryRepository()}
		svc := enroll.NewService(repo)
		sink := newMintSink()
		sink.recordErr = errors.New("audit store down")
		h := newTestHandler(Deps{Tokens: newTestEnrollmentTokensWithSink(t, svc, sink), Audit: &fakeAuditor{}, Now: fixedNow})

		rec := do(t, h, http.MethodPost, "/api/v1/enrollment-tokens", mintTokenRequest{TTLSeconds: 3600, MaxUses: 1})
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500; body = %s", rec.Code, rec.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		for _, field := range []string{"token", "join_string"} {
			if _, ok := body[field]; ok {
				t.Errorf("the failed mint's response carries %q", field)
			}
		}

		stored, err := repo.ByID(context.Background(), repo.onlyID(t))
		if err != nil {
			t.Fatalf("repo.ByID: %v", err)
		}
		if !stored.Revoked {
			t.Error("the unrecorded token was not withdrawn")
		}
	})

	t.Run("a failed withdrawal names the token and no secret", func(t *testing.T) {
		repo := &createdIDRepo{Repository: enroll.NewMemoryRepository()}
		svc := enroll.NewService(repo)
		sink := newMintSink()
		sink.recordErr = errors.New("audit store down")
		tokens := newTestEnrollmentTokensWithWithdrawErr(t, svc, sink, errors.New("store down"))
		h := newTestHandler(Deps{Tokens: tokens, Audit: &fakeAuditor{}, Now: fixedNow})

		rec := do(t, h, http.MethodPost, "/api/v1/enrollment-tokens", mintTokenRequest{TTLSeconds: 3600, MaxUses: 1})
		if rec.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500; body = %s", rec.Code, rec.Body.String())
		}
		var problem struct {
			Detail string `json:"detail"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil {
			t.Fatalf("decode response: %v", err)
		}
		id := repo.onlyID(t)
		if !strings.Contains(problem.Detail, id) || !strings.Contains(problem.Detail, "DELETE /api/v1/enrollment-tokens/"+id) {
			t.Errorf("detail %q does not name the live token and its revoke route", problem.Detail)
		}
		if strings.Contains(rec.Body.String(), "join_string") || strings.Contains(rec.Body.String(), "\"token\"") {
			t.Errorf("the response carries a credential field: %s", rec.Body.String())
		}
	})
}

// createdIDRepo remembers the ID of every token stored through it.
type createdIDRepo struct {
	enroll.Repository
	ids []string
}

func (r *createdIDRepo) Create(ctx context.Context, tok *enroll.Token) error {
	r.ids = append(r.ids, tok.ID)
	return r.Repository.Create(ctx, tok)
}

// onlyID returns the ID of the one token the repository stored.
func (r *createdIDRepo) onlyID(t *testing.T) string {
	t.Helper()
	if len(r.ids) != 1 {
		t.Fatalf("stored %d tokens, want exactly one", len(r.ids))
	}
	return r.ids[0]
}
