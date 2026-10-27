package enroll

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// testAccount is the minting Account tests hand WithMinter.
type testAccount struct {
	attribution string
	human       bool
}

func (a testAccount) Attribution() string { return a.attribution }
func (a testAccount) Human() bool         { return a.human }

// asHuman and asMachine are the two minters most tests need: a human admin
// Account, which may name initial tags, and a machine admin Account, which may not.
var (
	asHuman   = WithMinter("acct-alice", testAccount{"alice:admin", true})
	asMachine = WithMinter("acct-bot", testAccount{"bot:admin", false})
)

// fakeNow is a controllable clock for deterministic expiry tests.
type fakeNow struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeNow(base time.Time) *fakeNow { return &fakeNow{t: base} }

func (f *fakeNow) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *fakeNow) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t = f.t.Add(d)
}

// newTestService creates a Service with a MemoryRepository and a controllable clock.
func newTestService(t *testing.T) (*Service, *fakeNow) {
	t.Helper()
	clk := newFakeNow(time.Now())
	repo := NewMemoryRepository()
	svc := NewService(repo, WithClock(clk.now))
	return svc, clk
}

// TestCreate_StoresHashedReturnsPlaintextOnce checks that:
//   - Create returns a non-empty credential of form id.secret
//   - Token.SecretHash equals sha256(secretPart)
//   - Token.SecretHash is not equal to the raw plaintext bytes
//
// Proves EN-4.
func TestCreate_StoresHashedReturnsPlaintextOnce(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	tok, plaintext, err := svc.Create(ctx, nil, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if plaintext == "" {
		t.Fatal("plaintext credential is empty")
	}

	parts := strings.SplitN(plaintext, secretSep, 2)
	if len(parts) != 2 {
		t.Fatalf("credential missing separator: %q", plaintext)
	}
	secretPart := parts[1]

	// Hash of secret part must equal SecretHash.
	want256 := sha256.Sum256([]byte(secretPart))
	if !bytes.Equal(want256[:], tok.SecretHash) {
		t.Error("SecretHash does not equal sha256(secretPart)")
	}

	// SecretHash must not be equal to the raw plaintext bytes.
	if bytes.Equal([]byte(plaintext), tok.SecretHash) {
		t.Error("SecretHash equals raw plaintext bytes — plaintext stored unhashed")
	}
}

// TestValidate_Valid_ReturnsGrant checks that a valid credential returns the
// initial tags the token was minted with and the Account that minted it, and
// that mutating the returned tags does not affect a subsequent Validate.
//
// Proves EN-41.
func TestValidate_Valid_ReturnsGrant(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	tags := []string{"tag:role=web", "tag:env=prod"}
	_, plaintext, err := svc.Create(ctx, tags, time.Hour, asHuman)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := svc.Validate(ctx, plaintext)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(got.InitialTags) != len(tags) {
		t.Fatalf("initial tags length mismatch: want %d got %d", len(tags), len(got.InitialTags))
	}
	for i := range tags {
		if got.InitialTags[i] != tags[i] {
			t.Errorf("initial tag[%d]: want %q got %q", i, tags[i], got.InitialTags[i])
		}
	}
	want := MintedBy{AccountID: "acct-alice", Account: "alice", Role: "admin", Human: true}
	if got.MintedBy != want {
		t.Errorf("MintedBy = %+v, want %+v", got.MintedBy, want)
	}

	// Mutate the returned slice and validate again — stored tags must be unaffected.
	got.InitialTags[0] = "tag:tampered=true"
	got2, err := svc.Validate(ctx, plaintext)
	if err != nil {
		t.Fatalf("second Validate: %v", err)
	}
	if got2.InitialTags[0] != tags[0] {
		t.Errorf("returned tags mutated stored tags: got %q want %q", got2.InitialTags[0], tags[0])
	}
}

// TestValidate_WrongSecret checks that a tampered secret returns ErrInvalidToken.
func TestValidate_WrongSecret(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	_, plaintext, err := svc.Create(ctx, nil, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	parts := strings.SplitN(plaintext, secretSep, 2)
	tampered := parts[0] + secretSep + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	_, err = svc.Validate(ctx, tampered)
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("wrong secret: want ErrInvalidToken, got %v", err)
	}
}

// TestValidate_Malformed checks that malformed credentials return ErrInvalidToken.
func TestValidate_Malformed(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	cases := []string{
		"",
		"noseparator",
		string([]byte{0x00, 0x01}),
	}
	for _, c := range cases {
		_, err := svc.Validate(ctx, c)
		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("Validate(%q): want ErrInvalidToken, got %v", c, err)
		}
	}
}

// TestValidate_UnknownID checks that a well-formed credential with an unknown id
// returns ErrInvalidToken (not ErrNotFound — no existence oracle).
func TestValidate_UnknownID(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	// Construct a valid-looking credential with an id that was never created.
	unknown := "deadbeefdeadbeefdeadbeefdeadbeef" + secretSep + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	_, err := svc.Validate(ctx, unknown)
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("unknown id: want ErrInvalidToken, got %v", err)
	}
}

// TestValidate_Expired checks that an expired token returns ErrExpired.
func TestValidate_Expired(t *testing.T) {
	svc, clk := newTestService(t)
	ctx := context.Background()

	_, plaintext, err := svc.Create(ctx, nil, time.Minute)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Advance the clock past expiry.
	clk.advance(2 * time.Minute)

	_, err = svc.Validate(ctx, plaintext)
	if !errors.Is(err, ErrExpired) {
		t.Errorf("expired token: want ErrExpired, got %v", err)
	}
}

// TestValidate_Revoked checks that a revoked token returns ErrRevoked.
func TestValidate_Revoked(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	tok, plaintext, err := svc.Create(ctx, nil, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := svc.Revoke(ctx, tok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	_, err = svc.Validate(ctx, plaintext)
	if !errors.Is(err, ErrRevoked) {
		t.Errorf("revoked token: want ErrRevoked, got %v", err)
	}
}

// TestValidate_SecretCheckedBeforeState proves that Validate verifies the secret
// before disclosing token state: a revoked token presented with a wrong secret must
// return ErrInvalidToken, not ErrRevoked.
func TestValidate_SecretCheckedBeforeState(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	tok, plaintext, err := svc.Create(ctx, nil, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := svc.Revoke(ctx, tok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Tamper the secret part so it is wrong.
	parts := strings.SplitN(plaintext, secretSep, 2)
	tampered := parts[0] + secretSep + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	_, err = svc.Validate(ctx, tampered)
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("revoked+wrong secret: want ErrInvalidToken, got %v (must not disclose state without correct secret)", err)
	}
}

// TestReusable_ValidatesRepeatedly checks that a token with default options (MaxUses 0)
// can be validated many times without error.
// Proves EN-5.
func TestReusable_ValidatesRepeatedly(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	_, plaintext, err := svc.Create(ctx, nil, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	for i := 0; i < 10; i++ {
		if _, err := svc.Validate(ctx, plaintext); err != nil {
			t.Errorf("Validate #%d: %v", i+1, err)
		}
	}
}

// TestMaxUses_Enforced checks that WithMaxUses limits successful Validate calls.
func TestMaxUses_Enforced(t *testing.T) {
	cases := []struct {
		maxUses int
		name    string
	}{
		{1, "single-use"},
		{2, "two-use"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newTestService(t)
			ctx := context.Background()

			_, plaintext, err := svc.Create(ctx, nil, time.Hour, WithMaxUses(tc.maxUses))
			if err != nil {
				t.Fatalf("Create: %v", err)
			}

			for i := 0; i < tc.maxUses; i++ {
				if _, err := svc.Validate(ctx, plaintext); err != nil {
					t.Errorf("Validate #%d (within limit): %v", i+1, err)
				}
			}

			_, err = svc.Validate(ctx, plaintext)
			if !errors.Is(err, ErrExhausted) {
				t.Errorf("Validate after limit: want ErrExhausted, got %v", err)
			}
		})
	}
}

// TestMaxUses_Concurrent checks that MaxUses is enforced atomically under concurrent
// Validate calls: exactly MaxUses goroutines succeed; all others get ErrExhausted.
// Proves EN-5.
func TestMaxUses_Concurrent(t *testing.T) {
	const k = 5
	const goroutines = 50

	svc, _ := newTestService(t)
	ctx := context.Background()

	_, plaintext, err := svc.Create(ctx, nil, time.Hour, WithMaxUses(k))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	var (
		successes atomic.Int64
		exhausted atomic.Int64
		wg        sync.WaitGroup
	)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.Validate(ctx, plaintext)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrExhausted):
				exhausted.Add(1)
			default:
				// unexpected error; counted so the totals assertion catches it
			}
		}()
	}
	wg.Wait()

	if got := successes.Load(); got != k {
		t.Errorf("successes: want %d, got %d", k, got)
	}
	if total := successes.Load() + exhausted.Load(); total != goroutines {
		t.Errorf("total (success+exhausted): want %d, got %d", goroutines, total)
	}
}

// TestCreate_InitialTagMalformedRefused checks that an entry which is not a
// well-formed tag: label refuses the mint, whatever the way it is wrong, and
// that nothing is stored.
//
// RED ON: a gate that sanitises or truncates instead of refusing, that skips the
// length bounds, or that checks the whole entry with WellFormedLabel (which
// would reject the ":" in "tag:" itself).
//
// Proves EN-40.
func TestCreate_InitialTagMalformedRefused(t *testing.T) {
	long := func(n int) string { return strings.Repeat("a", n) }
	many := make([]string, 0, 65)
	for i := 0; i < 65; i++ {
		many = append(many, fmt.Sprintf("tag:k%d=v", i))
	}

	cases := []struct {
		name string
		tags []string
	}{
		{"no-prefix", []string{"env=prod"}},
		{"node-prefix", []string{"node:role=web"}},
		{"state-prefix", []string{"state:connected=true"}},
		{"upper-case prefix", []string{"TAG:env=prod"}},
		{"no equals", []string{"tag:env"}},
		{"empty key", []string{"tag:=prod"}},
		{"empty bare entry", []string{"tag:"}},
		{"empty entry", []string{"tag:env=prod", ""}},
		// The comma smuggles a second, cross-namespace term into what would
		// otherwise store as one value.
		{"comma-injected second term", []string{"tag:env=prod,node:role=web"}},
		{"zero width space in key", []string{"tag:quarantine\u200b=on"}},
		{"space in value", []string{"tag:env=prod x"}},
		{"two equals signs", []string{"tag:a=b=c"}},
		{"64-byte key", []string{"tag:" + long(64) + "=v"}},
		{"256-byte value", []string{"tag:k=" + long(256)}},
		{"a key twice", []string{"tag:env=prod", "tag:env=dev"}},
		{"65 tags", many},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := NewMemoryRepository()
			svc := NewService(repo)
			_, _, err := svc.Create(context.Background(), tc.tags, time.Hour, asHuman)
			if !errors.Is(err, ErrInvalidInitialTags) {
				t.Errorf("tags %v: want ErrInvalidInitialTags, got %v", tc.tags, err)
			}
			if n := len(repo.tokens); n != 0 {
				t.Errorf("a refused mint stored %d tokens", n)
			}
		})
	}
}

// TestCreate_InitialTagsWellFormedAccepted checks that none, one, several and
// the longest tags the bounds allow are accepted and stored verbatim.
//
// RED ON: an over-tight gate that rejects an empty value, the length maxima, or
// no tags at all.
//
// Proves EN-40.
func TestCreate_InitialTagsWellFormedAccepted(t *testing.T) {
	maxKey := strings.Repeat("k", 63)
	maxValue := strings.Repeat("v", 255)
	cases := []struct {
		name string
		tags []string
	}{
		{"none", nil},
		{"one", []string{"tag:env=prod"}},
		{"several", []string{"tag:env=prod", "tag:role=web-1.a_b", "tag:marker="}},
		{"longest key and value", []string{"tag:" + maxKey + "=" + maxValue}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _ := newTestService(t)
			tok, _, err := svc.Create(context.Background(), tc.tags, time.Hour, asHuman)
			if err != nil {
				t.Fatalf("Create(%v): unexpected error: %v", tc.tags, err)
			}
			if len(tok.InitialTags) != len(tc.tags) {
				t.Fatalf("stored %v, want %v", tok.InitialTags, tc.tags)
			}
			for i := range tc.tags {
				if tok.InitialTags[i] != tc.tags[i] {
					t.Errorf("stored tag[%d] = %q, want %q verbatim", i, tok.InitialTags[i], tc.tags[i])
				}
			}
		})
	}
}

// TestCreate_RelayLabelRefusedNamingIt checks that a relay: label refuses the
// mint naming the label, whoever mints: a machine Account naming one is told
// about the label, not about being a machine.
//
// RED ON: running the machine-Account rule before the tag syntax, which would
// answer a machine mint of relay:env=prod with the human-only refusal.
//
// Proves EN-35.
func TestCreate_RelayLabelRefusedNamingIt(t *testing.T) {
	minters := map[string]Option{"human": asHuman, "machine": asMachine}
	for who, minter := range minters {
		for _, label := range []string{"relay:env=prod", "relay:node-id=x"} {
			t.Run(who+" "+label, func(t *testing.T) {
				svc, _ := newTestService(t)
				_, _, err := svc.Create(context.Background(), []string{"tag:ok=1", label}, time.Hour, minter)
				if !errors.Is(err, ErrInvalidInitialTags) || !errors.Is(err, registry.ErrInitialTagRelayLabel) {
					t.Fatalf("want ErrInvalidInitialTags wrapping ErrInitialTagRelayLabel, got %v", err)
				}
				if errors.Is(err, ErrInitialTagsNeedHuman) {
					t.Errorf("a relay: label must not be reported as the machine-Account rule: %v", err)
				}
				if !strings.Contains(err.Error(), label) {
					t.Errorf("the refusal does not name %q: %v", label, err)
				}
			})
		}
	}
}

// TestCreate_MachineAccountNamingTagsRefused checks that a machine Account's
// mint naming any initial tag is refused and stores nothing, that a machine
// mint naming none is unaffected, and that a mint with only WithCreatedBy,
// which records no human minter, is treated as a machine.
//
// RED ON: deciding the rule from anything but the minting Account's recorded
// kind, or defaulting an unknown minter to human.
//
// Proves EN-44.
func TestCreate_MachineAccountNamingTagsRefused(t *testing.T) {
	t.Run("machine naming a tag", func(t *testing.T) {
		repo := NewMemoryRepository()
		_, _, err := NewService(repo).Create(context.Background(), []string{"tag:env=prod"}, time.Hour, asMachine)
		if !errors.Is(err, ErrInitialTagsNeedHuman) {
			t.Fatalf("want ErrInitialTagsNeedHuman, got %v", err)
		}
		if n := len(repo.tokens); n != 0 {
			t.Errorf("a refused mint stored %d tokens", n)
		}
	})
	t.Run("machine naming none", func(t *testing.T) {
		svc, _ := newTestService(t)
		tok, _, err := svc.Create(context.Background(), nil, time.Hour, asMachine)
		if err != nil {
			t.Fatalf("a machine mint naming no tag: %v", err)
		}
		if tok.CreatedByHuman || tok.CreatedByAccountID != "acct-bot" || tok.CreatedBy != "bot:admin" {
			t.Errorf("minter snapshot = %q %q human=%v", tok.CreatedBy, tok.CreatedByAccountID, tok.CreatedByHuman)
		}
	})
	t.Run("no recorded minter", func(t *testing.T) {
		svc, _ := newTestService(t)
		_, _, err := svc.Create(context.Background(), []string{"tag:env=prod"}, time.Hour, WithCreatedBy("someone:admin"))
		if !errors.Is(err, ErrInitialTagsNeedHuman) {
			t.Fatalf("want ErrInitialTagsNeedHuman, got %v", err)
		}
	})
}

// TestValidate_RefusesLegacyMalformedScope pins the second write seam: a
// Token whose scope predates the well-formedness gate can still be sitting
// in the repository (an upgrade does not retroactively validate stored
// rows). Validate must refuse it, and must do so BEFORE incrementing Uses.
//
// The Token is written straight into the Repository, bypassing Create —
// the same device store/registry_test.go's legacy-row tests use to forge a
// pre-gate row — because Create itself now refuses what this test needs to
// exist in storage.
//
// RED ON: gating only Create (the upgrade-path hole this seam exists to
// close); moving the check below the repo.Save that PERSISTS the increment.
//
// Not "after t.Uses++": t is the defensive copy ByID handed back, so the
// increment alone changes nothing a reader can observe, and a check placed
// between it and the Save is behaviour-preserving. Save is where a use is
// actually burned, and that is the mutation this assertion catches.
func TestValidate_RefusesLegacyMalformedScope(t *testing.T) {
	repo := NewMemoryRepository()
	svc := NewService(repo)
	ctx := context.Background()

	const secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	hash := sha256.Sum256([]byte(secret))
	legacy := &Token{
		ID:          "deadbeefdeadbeefdeadbeefdeadbeef", // 32 hex chars, tokenIDLen's shape
		SecretHash:  hash[:],
		LegacyScope: []string{"relay:quarantine\u200b=on"},
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	if err := repo.Create(ctx, legacy); err != nil {
		t.Fatalf("seeding legacy token: %v", err)
	}

	_, err := svc.Validate(ctx, legacy.ID+secretSep+secret)
	if !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("Validate: want ErrInvalidScope, got %v", err)
	}

	stored, err := repo.ByID(ctx, legacy.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if stored.Uses != 0 {
		t.Errorf("Uses = %d, want 0 — a scope refusal must not burn a use", stored.Uses)
	}
}

// TestValidate_StoredMachineMintedTagsRefusedBeforeAUse checks that a stored
// token naming initial tags whose minter was not a human Account is refused
// without burning a use: only a human Account writes tags.
//
// RED ON: trusting the stored row, or checking after the repo.Save that burns a use.
//
// Proves EN-44.
func TestValidate_StoredMachineMintedTagsRefusedBeforeAUse(t *testing.T) {
	repo := NewMemoryRepository()
	svc := NewService(repo)
	ctx := context.Background()

	const secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	hash := sha256.Sum256([]byte(secret))
	stored := &Token{
		ID:          "deadbeefdeadbeefdeadbeefdeadbeef",
		SecretHash:  hash[:],
		InitialTags: []string{"tag:env=prod"},
		ExpiresAt:   time.Now().Add(time.Hour),
		CreatedBy:   "bot:admin",
	}
	if err := repo.Create(ctx, stored); err != nil {
		t.Fatalf("seeding token: %v", err)
	}

	_, err := svc.Validate(ctx, stored.ID+secretSep+secret)
	if !errors.Is(err, ErrInvalidInitialTags) || !errors.Is(err, ErrInitialTagsNeedHuman) {
		t.Fatalf("Validate: want ErrInvalidInitialTags wrapping ErrInitialTagsNeedHuman, got %v", err)
	}
	got, err := repo.ByID(ctx, stored.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got.Uses != 0 {
		t.Errorf("Uses = %d, want 0 — a refusal must not burn a use", got.Uses)
	}
}

// TestValidate_StoredMalformedInitialTagRefusedBeforeAUse checks that a stored
// token whose initial tags no longer hold is refused without burning a use.
//
// Proves EN-40.
func TestValidate_StoredMalformedInitialTagRefusedBeforeAUse(t *testing.T) {
	repo := NewMemoryRepository()
	svc := NewService(repo)
	ctx := context.Background()

	const secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	hash := sha256.Sum256([]byte(secret))
	stored := &Token{
		ID:                 "deadbeefdeadbeefdeadbeefdeadbeef",
		SecretHash:         hash[:],
		InitialTags:        []string{"tag:quarantine\u200b=on"},
		ExpiresAt:          time.Now().Add(time.Hour),
		CreatedBy:          "alice:admin",
		CreatedByAccountID: "acct-alice",
		CreatedByHuman:     true,
	}
	if err := repo.Create(ctx, stored); err != nil {
		t.Fatalf("seeding token: %v", err)
	}

	if _, err := svc.Validate(ctx, stored.ID+secretSep+secret); !errors.Is(err, ErrInvalidInitialTags) {
		t.Fatalf("Validate: want ErrInvalidInitialTags, got %v", err)
	}
	got, err := repo.ByID(ctx, stored.ID)
	if err != nil {
		t.Fatalf("ByID: %v", err)
	}
	if got.Uses != 0 {
		t.Errorf("Uses = %d, want 0 — a refusal must not burn a use", got.Uses)
	}
}

// TestCreate_InvalidTTL checks that zero and negative TTLs are rejected.
func TestCreate_InvalidTTL(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	cases := []time.Duration{0, -time.Second, -time.Hour}
	for _, d := range cases {
		_, _, err := svc.Create(ctx, nil, d)
		if !errors.Is(err, ErrInvalidTTL) {
			t.Errorf("TTL %v: want ErrInvalidTTL, got %v", d, err)
		}
	}
}

// TestRevoke_UnknownID checks that revoking an unknown id returns ErrNotFound.
func TestRevoke_UnknownID(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	err := svc.Revoke(ctx, "doesnotexist")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("revoke unknown: want ErrNotFound, got %v", err)
	}
}

// TestRevoke_Idempotent checks that revoking an already-revoked token returns nil.
func TestRevoke_Idempotent(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	tok, _, err := svc.Create(ctx, nil, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := svc.Revoke(ctx, tok.ID); err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	if err := svc.Revoke(ctx, tok.ID); err != nil {
		t.Errorf("second Revoke (idempotent): want nil, got %v", err)
	}
}

// TestService_IsRevoked covers the three cases of IsRevoked: unknown id, existing
// not-revoked token, and existing revoked token.
func TestService_IsRevoked(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	// Unknown id: a token that never existed is treated as not-revoked.
	revoked, err := svc.IsRevoked(ctx, "doesnotexist")
	if err != nil {
		t.Fatalf("IsRevoked unknown: unexpected error: %v", err)
	}
	if revoked {
		t.Error("IsRevoked unknown: want false, got true")
	}

	// Existing, not-revoked token.
	tok, _, err := svc.Create(ctx, nil, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	revoked, err = svc.IsRevoked(ctx, tok.ID)
	if err != nil {
		t.Fatalf("IsRevoked not-revoked: unexpected error: %v", err)
	}
	if revoked {
		t.Error("IsRevoked not-revoked: want false, got true")
	}

	// After Revoke: must return true.
	if err := svc.Revoke(ctx, tok.ID); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	revoked, err = svc.IsRevoked(ctx, tok.ID)
	if err != nil {
		t.Fatalf("IsRevoked revoked: unexpected error: %v", err)
	}
	if !revoked {
		t.Error("IsRevoked revoked: want true, got false")
	}
}

// TestNoSecretInLogs verifies that neither the plaintext secret nor the SecretHash
// appears in log or fmt output.
//
//	(a) slog path (structural: LogValue omits SecretHash; plaintext is never on Token):
//	    check that the slog output contains neither the plaintext nor the hash in
//	    hex or decimal []byte form.
//	(b) fmt.Sprintf path (structural: plaintext is never stored on Token):
//	    check only that the plaintext is absent from %+v output.
func TestNoSecretInLogs(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	tok, plaintext, err := svc.Create(ctx, nil, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// (a) slog path -------------------------------------------------------
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	logger.Info("audit", slog.Any("token", tok))
	logOutput := buf.String()

	// plaintext must not appear in slog output
	if strings.Contains(logOutput, plaintext) {
		t.Errorf("slog output contains plaintext secret")
	}

	// SecretHash must not appear in hex form in slog output
	hashHex := hex.EncodeToString(tok.SecretHash)
	if strings.Contains(logOutput, hashHex) {
		t.Errorf("slog output contains SecretHash in hex form: %s", hashHex)
	}

	// SecretHash must not appear in Go's decimal []byte representation in slog output.
	// Go prints []byte as "[b0 b1 b2 ...]" via reflect, so we build that string and check.
	hashDecimal := fmt.Sprintf("%v", tok.SecretHash)
	if strings.Contains(logOutput, hashDecimal) {
		t.Errorf("slog output contains SecretHash in decimal form: %s", hashDecimal)
	}

	// (b) fmt.Sprintf path — structural guarantee: plaintext is never stored on Token,
	// so it cannot appear in %+v output regardless of hash redaction.
	fmtOutput := fmt.Sprintf("%+v", tok)
	if strings.Contains(fmtOutput, plaintext) {
		t.Errorf("fmt.Sprintf(%%+v) contains plaintext secret")
	}
}
