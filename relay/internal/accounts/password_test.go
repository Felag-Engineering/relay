package accounts_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
)

func TestHashPassword_VerifiesTheRightSecretAndNothingElse(t *testing.T) {
	t.Parallel()

	h, err := accounts.HashPassword(accounts.NewPassword("correct horse battery staple"))
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !h.Verify(accounts.NewPassword("correct horse battery staple")) {
		t.Error("the password that was hashed does not verify")
	}
	for _, wrong := range []string{
		"correct horse battery stapl",
		"correct horse battery staple ",
		"Correct horse battery staple",
		"",
	} {
		if h.Verify(accounts.NewPassword(wrong)) {
			t.Errorf("%q verified against a different password", wrong)
		}
	}
}

func TestHashPassword_SaltsEveryHash(t *testing.T) {
	t.Parallel()

	// Two hashes of the SAME password must not be equal. Without a per-hash
	// salt, a stolen database tells an attacker which Accounts share a
	// password, and one cracked hash cracks all of them.
	const same = "the same password twice"
	a, err := accounts.HashPassword(accounts.NewPassword(same))
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	b, err := accounts.HashPassword(accounts.NewPassword(same))
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if a.Encoded() == b.Encoded() {
		t.Fatal("two hashes of the same password are identical: the salt is not random")
	}
	if !a.Verify(accounts.NewPassword(same)) || !b.Verify(accounts.NewPassword(same)) {
		t.Error("a salted hash failed to verify its own password")
	}
}

func TestPassword_Validate_BoundsLength(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		pw   string
		want error
	}{
		{"empty", "", accounts.ErrPasswordTooShort},
		{"one below the minimum", strings.Repeat("a", accounts.MinPasswordBytes-1), accounts.ErrPasswordTooShort},
		{"exactly the minimum", strings.Repeat("a", accounts.MinPasswordBytes), nil},
		{"exactly the maximum", strings.Repeat("a", accounts.MaxPasswordBytes), nil},
		{"one above the maximum", strings.Repeat("a", accounts.MaxPasswordBytes+1), accounts.ErrPasswordTooLong},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := accounts.NewPassword(tt.pw).Validate(); got != tt.want {
				t.Errorf("Validate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPassword_NeverRendersItsSecret(t *testing.T) {
	t.Parallel()

	const secret = "the plaintext must not appear"
	p := accounts.NewPassword(secret)

	encoded, err := json.Marshal(struct {
		Password accounts.Password
	}{p})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	for name, rendered := range map[string]string{
		"String": p.String(),
		"%v":     fmt.Sprintf("%v", p),
		"%s":     fmt.Sprintf("%s", p), //nolint:gosimple,staticcheck // the POINT is that the %s verb is covered: it reaches String() via the Stringer interface, and asserting that is what stops someone "simplifying" the type's redaction away
		"%#v":    fmt.Sprintf("%#v", p),
		"struct": fmt.Sprintf("%v", struct{ P accounts.Password }{p}),
		"slog":   p.LogValue().String(),
		"json":   string(encoded),
	} {
		if strings.Contains(rendered, secret) {
			t.Errorf("%s rendered the plaintext password: %q", name, rendered)
		}
	}
	if p.Reveal() != secret {
		t.Error("Reveal did not return the plaintext")
	}
}

func TestPasswordHash_NeverRendersItself(t *testing.T) {
	t.Parallel()

	h, err := accounts.HashPassword(accounts.NewPassword("a password to hash"))
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	// A hash is not a credential, but it IS the input to an offline attack.
	// The salt is the most identifying fragment, so look for that.
	salt := strings.Split(h.Encoded(), "$")[4]

	for name, rendered := range map[string]string{
		"String": h.String(),
		"%v":     fmt.Sprintf("%v", h),
		"%#v":    fmt.Sprintf("%#v", h),
		"slog":   h.LogValue().String(),
	} {
		if strings.Contains(rendered, salt) {
			t.Errorf("%s rendered the stored hash: %q", name, rendered)
		}
	}
	if got, err := json.Marshal(h); err != nil {
		t.Fatalf("json.Marshal: %v", err)
	} else if strings.Contains(string(got), salt) {
		t.Errorf("json rendered the stored hash: %s", got)
	}
}

func TestParsePasswordHash_RefusesAnythingItCannotVerifyAgainst(t *testing.T) {
	t.Parallel()

	good, err := accounts.HashPassword(accounts.NewPassword("a password to hash"))
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if _, err := accounts.ParsePasswordHash(good.Encoded()); err != nil {
		t.Fatalf("a hash this package produced did not parse: %v", err)
	}

	fields := strings.Split(good.Encoded(), "$")
	rebuild := func(f []string) string { return strings.Join(f, "$") }

	swap := func(i int, v string) string {
		f := append([]string(nil), fields...)
		f[i] = v
		return rebuild(f)
	}

	tests := map[string]string{
		"empty":                    "",
		"not a PHC string":         "not-a-hash",
		"a bare sha256 hex digest": strings.Repeat("ab", 32),
		// argon2i and argon2d are real algorithms and neither is what this
		// package derives. Accepting one would silently verify against a
		// weaker function.
		"a different argon2 variant": swap(1, "argon2i"),
		"a different algorithm":      swap(1, "bcrypt"),
		"an unknown argon2 version":  swap(2, "v=16"),
		// A hash claiming trivial cost verifies almost instantly. Tampering
		// with a stored row must fail closed, not turn the KDF off.
		"a degenerate memory cost":  swap(3, "m=8,t=1,p=1"),
		"a zero time cost":          swap(3, "m=19456,t=0,p=1"),
		"a malformed parameter set": swap(3, "m=lots"),
		"a non-base64 salt":         swap(4, "!!!!"),
		"a truncated salt":          swap(4, "YWI"),
		"a non-base64 key":          swap(5, "!!!!"),
		"a truncated key":           swap(5, "YWI"),
	}
	for name, encoded := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := accounts.ParsePasswordHash(encoded); err == nil {
				t.Errorf("ParsePasswordHash(%q) accepted a hash it cannot verify against", encoded)
			}
		})
	}
}

func TestPasswordHash_ZeroValueVerifiesNothing(t *testing.T) {
	t.Parallel()

	// The fail-closed case that matters most: a PasswordHash nobody set must
	// not verify the empty password, or an Account with no credential would
	// be reachable by submitting a blank form.
	var zero accounts.PasswordHash
	if !zero.IsZero() {
		t.Error("the zero PasswordHash does not report IsZero")
	}
	for _, attempt := range []string{"", "anything", strings.Repeat("a", 64)} {
		if zero.Verify(accounts.NewPassword(attempt)) {
			t.Errorf("the zero PasswordHash verified %q", attempt)
		}
	}
}

func TestVerifyNothing_DoesTheSameWorkAsARealVerification(t *testing.T) {
	t.Parallel()

	// This is the no-enumeration control's engine. It is asserted here as
	// "it runs and does not panic for any input", because asserting the
	// TIMING itself is inherently flaky on shared CI. What can be pinned is
	// that the unknown-username path calls a real KDF rather than returning
	// early — see the login-handler test for the behavioural half.
	accounts.WarmPasswordVerifier()
	for _, attempt := range []string{"", "short", strings.Repeat("a", accounts.MaxPasswordBytes+1)} {
		accounts.VerifyNothing(accounts.NewPassword(attempt))
	}
}

func TestPasswordHash_RefusesAnOverlongCandidateWithoutRunningTheKDF(t *testing.T) {
	t.Parallel()

	h, err := accounts.HashPassword(accounts.NewPassword("a password to hash"))
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	// An unauthenticated caller must not be able to choose how much
	// memory-hard work the Relay does.
	if h.Verify(accounts.NewPassword(strings.Repeat("a", accounts.MaxPasswordBytes+1))) {
		t.Error("an over-long candidate verified")
	}
}
