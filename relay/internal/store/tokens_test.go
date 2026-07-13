package store

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/enroll"
)

// sampleToken returns a fully-populated Token for round-trip assertions. Times
// are pre-rounded to the store's persisted precision so reflect.DeepEqual holds
// after a read-back.
func sampleToken(id string) *enroll.Token {
	return &enroll.Token{
		ID:         id,
		SecretHash: []byte{0xde, 0xad, 0xbe, 0xef},
		Scope:      []string{"relay:env=prod", "relay:role=web"},
		ExpiresAt:  roundTripTime(time.Date(2026, 8, 1, 12, 0, 0, 42, time.UTC)),
		MaxUses:    5,
		Uses:       0,
		CreatedAt:  roundTripTime(time.Date(2026, 7, 12, 9, 30, 0, 7, time.UTC)),
		CreatedBy:  "admin@example",
	}
}

func TestTokens_CreateByIDRoundTrip(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.Tokens()
	ctx := context.Background()

	want := sampleToken("tok-1")
	if err := repo.Create(ctx, want); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.ByID(ctx, "tok-1")
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestTokens_Create_Duplicate(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.Tokens()
	ctx := context.Background()

	tok := sampleToken("dup")
	if err := repo.Create(ctx, tok); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if err := repo.Create(ctx, tok); !errors.Is(err, enroll.ErrDuplicateID) {
		t.Errorf("duplicate Create: want ErrDuplicateID, got %v", err)
	}
}

func TestTokens_ByID_Unknown(t *testing.T) {
	st, _ := openTestStore(t)
	if _, err := st.Tokens().ByID(context.Background(), "ghost"); !errors.Is(err, enroll.ErrNotFound) {
		t.Errorf("ByID unknown: want ErrNotFound, got %v", err)
	}
}

func TestTokens_Save_Unknown(t *testing.T) {
	st, _ := openTestStore(t)
	err := st.Tokens().Save(context.Background(), sampleToken("ghost"))
	if !errors.Is(err, enroll.ErrNotFound) {
		t.Errorf("Save unknown: want ErrNotFound, got %v", err)
	}
}

func TestTokens_Save_PersistsRevokedAndUses(t *testing.T) {
	st, _ := openTestStore(t)
	repo := st.Tokens()
	ctx := context.Background()

	tok := sampleToken("mutate")
	if err := repo.Create(ctx, tok); err != nil {
		t.Fatalf("Create: %v", err)
	}

	tok.Uses = 3
	tok.Revoked = true
	if err := repo.Save(ctx, tok); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := repo.ByID(ctx, "mutate")
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got.Uses != 3 {
		t.Errorf("Uses after Save: want 3, got %d", got.Uses)
	}
	if !got.Revoked {
		t.Error("Revoked after Save: want true, got false")
	}
}

// TestTokens_RestartRoundTrip is the token half of the issue #133 acceptance at
// the store layer: a revoked token with a non-zero use count must survive a
// Close/Open of the same database, so a revoked token can never mint a new
// identity after a Relay restart.
func TestTokens_RestartRoundTrip(t *testing.T) {
	st, path := openTestStore(t)
	ctx := context.Background()

	tok := sampleToken("survivor")
	if err := st.Tokens().Create(ctx, tok); err != nil {
		t.Fatalf("Create: %v", err)
	}
	tok.Uses = 2
	tok.Revoked = true
	if err := st.Tokens().Save(ctx, tok); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { reopened.Close() }) //nolint:errcheck

	got, err := reopened.Tokens().ByID(ctx, "survivor")
	if err != nil {
		t.Fatalf("ByID after restart: %v", err)
	}
	if !got.Revoked {
		t.Error("token should still be revoked after restart")
	}
	if got.Uses != 2 {
		t.Errorf("Uses after restart: want 2, got %d", got.Uses)
	}
}
