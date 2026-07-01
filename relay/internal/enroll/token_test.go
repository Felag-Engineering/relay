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
)

// testScope is a minimal valid scope used by most tests.
var testScope = []string{"relay:env=prod"}

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
func TestCreate_StoresHashedReturnsPlaintextOnce(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	tok, plaintext, err := svc.Create(ctx, testScope, time.Hour)
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

// TestValidate_Valid_ReturnsScope checks that a valid credential returns the created
// scope and that mutating the returned scope does not affect a subsequent Validate.
func TestValidate_Valid_ReturnsScope(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	scope := []string{"relay:role=web", "relay:env=prod"}
	_, plaintext, err := svc.Create(ctx, scope, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := svc.Validate(ctx, plaintext)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(got) != len(scope) {
		t.Fatalf("scope length mismatch: want %d got %d", len(scope), len(got))
	}
	for i := range scope {
		if got[i] != scope[i] {
			t.Errorf("scope[%d]: want %q got %q", i, scope[i], got[i])
		}
	}

	// Mutate the returned slice and validate again — stored scope must be unaffected.
	got[0] = "relay:tampered=true"
	got2, err := svc.Validate(ctx, plaintext)
	if err != nil {
		t.Fatalf("second Validate: %v", err)
	}
	if got2[0] != scope[0] {
		t.Errorf("returned scope mutated stored scope: got %q want %q", got2[0], scope[0])
	}
}

// TestValidate_WrongSecret checks that a tampered secret returns ErrInvalidToken.
func TestValidate_WrongSecret(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	_, plaintext, err := svc.Create(ctx, testScope, time.Hour)
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

	_, plaintext, err := svc.Create(ctx, testScope, time.Minute)
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

	tok, plaintext, err := svc.Create(ctx, testScope, time.Hour)
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

	tok, plaintext, err := svc.Create(ctx, testScope, time.Hour)
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
func TestReusable_ValidatesRepeatedly(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	_, plaintext, err := svc.Create(ctx, testScope, time.Hour)
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

			_, plaintext, err := svc.Create(ctx, testScope, time.Hour, WithMaxUses(tc.maxUses))
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
func TestMaxUses_Concurrent(t *testing.T) {
	const k = 5
	const goroutines = 50

	svc, _ := newTestService(t)
	ctx := context.Background()

	_, plaintext, err := svc.Create(ctx, testScope, time.Hour, WithMaxUses(k))
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

// TestCreate_InvalidScope checks that scopes without relay: prefixes are rejected.
func TestCreate_InvalidScope(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	cases := []struct {
		name  string
		scope []string
	}{
		{"empty", []string{}},
		{"nil", nil},
		{"no-prefix", []string{"env=prod"}},
		{"node-prefix", []string{"node:role=web"}},
		{"mixed", []string{"relay:env=prod", "node:role=web"}},
		{"empty-entry", []string{"relay:env=prod", ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := svc.Create(ctx, tc.scope, time.Hour)
			if !errors.Is(err, ErrInvalidScope) {
				t.Errorf("scope %v: want ErrInvalidScope, got %v", tc.scope, err)
			}
		})
	}
}

// TestCreate_InvalidTTL checks that zero and negative TTLs are rejected.
func TestCreate_InvalidTTL(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	cases := []time.Duration{0, -time.Second, -time.Hour}
	for _, d := range cases {
		_, _, err := svc.Create(ctx, testScope, d)
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

	tok, _, err := svc.Create(ctx, testScope, time.Hour)
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
	tok, _, err := svc.Create(ctx, testScope, time.Hour)
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

	tok, plaintext, err := svc.Create(ctx, testScope, time.Hour)
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
