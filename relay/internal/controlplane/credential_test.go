package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validHashString() (plaintext, hashStr string) {
	plaintext = "s3cr3t-control-plane-credential"
	sum := sha256.Sum256([]byte(plaintext))
	return plaintext, "sha256:" + hex.EncodeToString(sum[:])
}

func TestParseCredentialHash_Valid(t *testing.T) {
	plaintext, hashStr := validHashString()

	digest, err := ParseCredentialHash(hashStr)
	if err != nil {
		t.Fatalf("ParseCredentialHash: %v", err)
	}
	if len(digest) != sha256.Size {
		t.Fatalf("digest length = %d, want %d", len(digest), sha256.Size)
	}

	want := sha256.Sum256([]byte(plaintext))
	if !bytesEqual(digest, want[:]) {
		t.Fatal("digest does not match expected SHA-256 of plaintext")
	}
}

func TestParseCredentialHash_TrimsWhitespace(t *testing.T) {
	_, hashStr := validHashString()

	digest, err := ParseCredentialHash("  " + hashStr + "\n")
	if err != nil {
		t.Fatalf("ParseCredentialHash: %v", err)
	}
	if len(digest) != sha256.Size {
		t.Fatalf("digest length = %d, want %d", len(digest), sha256.Size)
	}
}

func TestParseCredentialHash_Malformed(t *testing.T) {
	cases := map[string]string{
		"empty":             "",
		"no prefix":         strings.Repeat("a", 64),
		"wrong prefix":      "sha1:" + strings.Repeat("a", 64),
		"too short":         "sha256:" + strings.Repeat("a", 63),
		"too long":          "sha256:" + strings.Repeat("a", 65),
		"uppercase hex":     "sha256:" + strings.Repeat("A", 64),
		"non-hex chars":     "sha256:" + strings.Repeat("z", 64),
		"plaintext looking": "hunter2",
	}

	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			digest, err := ParseCredentialHash(in)
			if !errors.Is(err, ErrMalformedCredentialHash) {
				t.Fatalf("err = %v, want ErrMalformedCredentialHash", err)
			}
			if digest != nil {
				t.Fatal("digest should be nil on error")
			}
			// The error must never embed the offending input.
			if in != "" && strings.Contains(err.Error(), in) {
				t.Fatalf("error message embeds input: %q", err.Error())
			}
		})
	}
}

func TestLoadCredentialHashFile_Valid(t *testing.T) {
	_, hashStr := validHashString()
	path := filepath.Join(t.TempDir(), "credential-hash")
	if err := os.WriteFile(path, []byte(hashStr+"\n"), 0o400); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	digest, err := LoadCredentialHashFile(path)
	if err != nil {
		t.Fatalf("LoadCredentialHashFile: %v", err)
	}
	if len(digest) != sha256.Size {
		t.Fatalf("digest length = %d, want %d", len(digest), sha256.Size)
	}
}

func TestLoadCredentialHashFile_Missing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist")

	_, err := LoadCredentialHashFile(path)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), path) {
		t.Fatalf("error should name the path for operator diagnosis: %v", err)
	}
}

func TestLoadCredentialHashFile_Malformed(t *testing.T) {
	secret := "this-is-not-a-hash"
	path := filepath.Join(t.TempDir(), "credential-hash")
	if err := os.WriteFile(path, []byte(secret), 0o400); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := LoadCredentialHashFile(path)
	if !errors.Is(err, ErrMalformedCredentialHash) {
		t.Fatalf("err = %v, want ErrMalformedCredentialHash", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error message embeds file contents: %q", err.Error())
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
