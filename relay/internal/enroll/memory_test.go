package enroll

import (
	"context"
	"errors"
	"testing"
)

func TestMemoryRepository_ByID_Unknown(t *testing.T) {
	repo := NewMemoryRepository()
	_, err := repo.ByID(context.Background(), "nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("ByID unknown: want ErrNotFound, got %v", err)
	}
}

func TestMemoryRepository_Save_Unknown(t *testing.T) {
	repo := NewMemoryRepository()
	err := repo.Save(context.Background(), &Token{ID: "ghost"})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Save unknown: want ErrNotFound, got %v", err)
	}
}

func TestMemoryRepository_Create_Duplicate(t *testing.T) {
	repo := NewMemoryRepository()
	tok := &Token{ID: "dup-id", SecretHash: []byte{1}, Scope: []string{"relay:x=1"}}

	if err := repo.Create(context.Background(), tok); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if err := repo.Create(context.Background(), tok); !errors.Is(err, ErrDuplicateID) {
		t.Errorf("duplicate Create: want ErrDuplicateID, got %v", err)
	}
}

// TestMemoryRepository_ByID_ReturnsCopy verifies that mutating a returned Token does
// not affect the stored copy.
func TestMemoryRepository_ByID_ReturnsCopy(t *testing.T) {
	repo := NewMemoryRepository()
	tok := &Token{
		ID:         "copy-id",
		SecretHash: []byte{1, 2},
		Scope:      []string{"relay:x=1"},
	}

	if err := repo.Create(context.Background(), tok); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.ByID(context.Background(), "copy-id")
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}

	// Mutate the returned copy.
	got.Uses = 99
	got.SecretHash[0] = 0xFF
	got.Scope[0] = "relay:tampered=true"

	// A subsequent ByID must return the original unmodified data.
	got2, err := repo.ByID(context.Background(), "copy-id")
	if err != nil {
		t.Fatalf("second ByID: %v", err)
	}
	if got2.Uses != 0 {
		t.Errorf("stored Uses changed to %d, want 0", got2.Uses)
	}
	if got2.SecretHash[0] != 1 {
		t.Errorf("stored SecretHash[0] changed to %d, want 1", got2.SecretHash[0])
	}
	if got2.Scope[0] != "relay:x=1" {
		t.Errorf("stored Scope[0] changed to %q, want relay:x=1", got2.Scope[0])
	}
}

// TestMemoryRepository_Save_PersistsMutation verifies that Save updates the stored token.
func TestMemoryRepository_Save_PersistsMutation(t *testing.T) {
	repo := NewMemoryRepository()
	tok := &Token{
		ID:         "mutate-id",
		SecretHash: []byte{1},
		Scope:      []string{"relay:x=1"},
	}

	if err := repo.Create(context.Background(), tok); err != nil {
		t.Fatalf("Create: %v", err)
	}

	stored, err := repo.ByID(context.Background(), "mutate-id")
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}

	stored.Uses = 7
	stored.Revoked = true
	if err := repo.Save(context.Background(), stored); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := repo.ByID(context.Background(), "mutate-id")
	if err != nil {
		t.Fatalf("ByID after Save: %v", err)
	}
	if got.Uses != 7 {
		t.Errorf("Uses after Save: want 7, got %d", got.Uses)
	}
	if !got.Revoked {
		t.Error("Revoked after Save: want true, got false")
	}
}
