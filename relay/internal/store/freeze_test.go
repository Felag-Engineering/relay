package store

import (
	"context"
	"testing"
)

// TestFreezeDefaultsNotFrozen: a fresh store with no freeze row is not
// frozen — "no row" means not-frozen, not an error.
func TestFreezeDefaultsNotFrozen(t *testing.T) {
	st, _ := openTestStore(t)
	frozen, err := st.Freeze().Frozen(context.Background())
	if err != nil {
		t.Fatalf("Frozen: %v", err)
	}
	if frozen {
		t.Error("Frozen() = true on a fresh store, want false")
	}
}

// TestFreezeEngageReleaseRoundTrip: Engage sets Frozen true; Release clears
// it and persists the reason.
func TestFreezeEngageReleaseRoundTrip(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Freeze()

	if err := repo.Engage(ctx, "local-host"); err != nil {
		t.Fatalf("Engage: %v", err)
	}
	frozen, err := repo.Frozen(ctx)
	if err != nil {
		t.Fatalf("Frozen after Engage: %v", err)
	}
	if !frozen {
		t.Error("Frozen() = false after Engage, want true")
	}

	if err := repo.Release(ctx, "local-host", "incident resolved"); err != nil {
		t.Fatalf("Release: %v", err)
	}
	frozen, err = repo.Frozen(ctx)
	if err != nil {
		t.Fatalf("Frozen after Release: %v", err)
	}
	if frozen {
		t.Error("Frozen() = true after Release, want false")
	}
}

// TestFreezeEngageIdempotent: engaging an already-engaged Freeze twice
// leaves it engaged (no error, no duplicate-row conflict).
func TestFreezeEngageIdempotent(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	repo := st.Freeze()

	if err := repo.Engage(ctx, "local-host"); err != nil {
		t.Fatalf("first Engage: %v", err)
	}
	if err := repo.Engage(ctx, "local-host"); err != nil {
		t.Fatalf("second Engage: %v", err)
	}
	frozen, err := repo.Frozen(ctx)
	if err != nil {
		t.Fatalf("Frozen: %v", err)
	}
	if !frozen {
		t.Error("Frozen() = false after a double Engage, want true")
	}
}

// TestFreezeSurvivesRestart is the store-level half of acceptance #2: a
// Freeze engaged before a Close is still engaged after a fresh Open of the
// same path.
func TestFreezeSurvivesRestart(t *testing.T) {
	st, path := openTestStore(t)
	ctx := context.Background()

	if err := st.Freeze().Engage(ctx, "local-host"); err != nil {
		t.Fatalf("Engage: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen Open(%s): %v", path, err)
	}
	t.Cleanup(func() { reopened.Close() }) //nolint:errcheck

	frozen, err := reopened.Freeze().Frozen(ctx)
	if err != nil {
		t.Fatalf("Frozen after reopen: %v", err)
	}
	if !frozen {
		t.Error("Frozen() = false after restart, want true (a Freeze a crash forgets is not a Freeze)")
	}
}
