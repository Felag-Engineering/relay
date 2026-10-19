package enroll

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/ca/catest"
)

type fixedFingerprint string

func (f fixedFingerprint) Fingerprint() string { return string(f) }

func TestEnroll_JoinStringCarriesFingerprintAddressAndToken(t *testing.T) {
	ctx := context.Background()
	relayCA, err := catest.Generate()
	if err != nil {
		t.Fatalf("catest.Generate: %v", err)
	}
	svc := NewService(NewMemoryRepository())
	minter, err := NewMinter(svc, relayCA, "relay.example.com:7654")
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}

	m, err := minter.Mint(ctx, testScope, time.Hour)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	js, err := DecodeJoinString(m.JoinString())
	if err != nil {
		t.Fatalf("DecodeJoinString: %v", err)
	}
	if got := js.RelayAddress(); got != "relay.example.com:7654" {
		t.Errorf("RelayAddress = %q", got)
	}
	fp := js.CAFingerprint()
	if got := hex.EncodeToString(fp[:]); got != relayCA.Fingerprint() {
		t.Errorf("fingerprint = %s, want %s", got, relayCA.Fingerprint())
	}
	block, _ := pem.Decode(relayCA.Bundle())
	if block == nil {
		t.Fatal("CA bundle is not PEM")
	}
	if want := sha256.Sum256(block.Bytes); fp != want {
		t.Errorf("fingerprint is not SHA-256 over the CA DER")
	}
	if js.EnrollmentToken() != m.Plaintext() {
		t.Errorf("join string token differs from the minted plaintext")
	}

	assertRedacted(t, m)

	if _, err := svc.Validate(ctx, m.Plaintext()); err != nil {
		t.Errorf("Validate(minted plaintext): %v", err)
	}
}

// assertRedacted fails if any rendering of m reveals the plaintext or join string.
func assertRedacted(t *testing.T, m Minted) {
	t.Helper()
	secrets := []string{m.Plaintext(), m.JoinString()}

	var logBuf bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("minted", "minted", m)

	jsonBytes, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	nested := struct{ inner Minted }{inner: m}
	pnested := &nested

	renderings := map[string]string{
		"fmt":      fmt.Sprintf("%v %+v %#v %s %d %x", m, m, m, m, m, m),
		"slog":     logBuf.String(),
		"json":     string(jsonBytes),
		"nested":   fmt.Sprintf("%v %+v %#v", nested, nested, nested),
		"nested-p": fmt.Sprintf("%+v", pnested),
	}
	for name, out := range renderings {
		for _, s := range secrets {
			if s != "" && strings.Contains(out, s) {
				t.Errorf("%s rendering leaks a secret: %s", name, out)
			}
		}
	}
}

func TestEnroll_AdvertisedAddressDefaultsToHostnameAndListenPort(t *testing.T) {
	cases := []struct{ name, listen, host, want string }{
		{"empty listen host", ":7654", "relay.example.com", "relay.example.com:7654"},
		{"wildcard v4 listen host", "0.0.0.0:9000", "relay.example.com", "relay.example.com:9000"},
		{"wildcard v6 listen host", "[::]:7654", "relay.example.com", "relay.example.com:7654"},
		{"v6 hostname is bracketed", ":7654", "::1", "[::1]:7654"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AdvertisedAddress("", tc.host, tc.listen)
			if err != nil {
				t.Fatalf("AdvertisedAddress: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("configured value wins", func(t *testing.T) {
		got, err := AdvertisedAddress("relay.internal:443", "relay.example.com", ":7654")
		if err != nil || got != "relay.internal:443" {
			t.Errorf("got %q, %v", got, err)
		}
	})
	t.Run("listen address without a port", func(t *testing.T) {
		if _, err := AdvertisedAddress("", "relay.example.com", "0.0.0.0"); !errors.Is(err, ErrAdvertisedListenAddr) {
			t.Errorf("err = %v, want ErrAdvertisedListenAddr", err)
		}
	})
	t.Run("empty hostname", func(t *testing.T) {
		if _, err := AdvertisedAddress("", "", ":7654"); !errors.Is(err, ErrAdvertisedHostname) {
			t.Errorf("err = %v, want ErrAdvertisedHostname", err)
		}
	})
}

func TestNewMinter_RefusesBadInputs(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	good := fixedFingerprint(strings.Repeat("ab", sha256.Size))

	for _, addr := range []string{"", "relay.example.com", "relay.example.com:", ":7654"} {
		if _, err := NewMinter(svc, good, addr); !errors.Is(err, ErrMinterAddress) {
			t.Errorf("address %q: err = %v, want ErrMinterAddress", addr, err)
		}
	}
	for _, fp := range []fixedFingerprint{"", "abcd", "zz" + fixedFingerprint(strings.Repeat("ab", 31))} {
		if _, err := NewMinter(svc, fp, "relay.example.com:7654"); !errors.Is(err, ErrMinterFingerprint) {
			t.Errorf("fingerprint %q: err = %v, want ErrMinterFingerprint", fp, err)
		}
	}
	if _, err := NewMinter(nil, good, "relay.example.com:7654"); !errors.Is(err, ErrMinterNoTokens) {
		t.Errorf("nil tokens: err = %v, want ErrMinterNoTokens", err)
	}
}

func TestMinter_Mint_PassesTokenErrorsThrough(t *testing.T) {
	svc := NewService(NewMemoryRepository())
	minter, err := NewMinter(svc, fixedFingerprint(strings.Repeat("ab", sha256.Size)), "relay.example.com:7654")
	if err != nil {
		t.Fatalf("NewMinter: %v", err)
	}
	ctx := context.Background()

	if _, err := minter.Mint(ctx, testScope, 0); !errors.Is(err, ErrInvalidTTL) {
		t.Errorf("zero ttl: err = %v, want ErrInvalidTTL", err)
	}
	if _, err := minter.Mint(ctx, nil, time.Hour); !errors.Is(err, ErrInvalidScope) {
		t.Errorf("empty scope: err = %v, want ErrInvalidScope", err)
	}
}
