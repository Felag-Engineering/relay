package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestHashCredential_Success(t *testing.T) {
	const token = "s3cr3t-control-plane-credential"

	var out bytes.Buffer
	if err := hashCredential(strings.NewReader(token), &out); err != nil {
		t.Fatalf("hashCredential: %v", err)
	}

	sum := sha256.Sum256([]byte(token))
	want := "sha256:" + hex.EncodeToString(sum[:]) + "\n"
	if out.String() != want {
		t.Errorf("output = %q, want %q", out.String(), want)
	}
}

func TestHashCredential_TrimsTrailingNewline(t *testing.T) {
	const token = "s3cr3t-control-plane-credential"

	var withLF, withCRLF, without bytes.Buffer
	if err := hashCredential(strings.NewReader(token+"\n"), &withLF); err != nil {
		t.Fatalf("hashCredential (LF): %v", err)
	}
	if err := hashCredential(strings.NewReader(token+"\r\n"), &withCRLF); err != nil {
		t.Fatalf("hashCredential (CRLF): %v", err)
	}
	if err := hashCredential(strings.NewReader(token), &without); err != nil {
		t.Fatalf("hashCredential (none): %v", err)
	}

	if withLF.String() != without.String() {
		t.Errorf("trailing LF changed the hash: %q != %q", withLF.String(), without.String())
	}
	if withCRLF.String() != without.String() {
		t.Errorf("trailing CRLF changed the hash: %q != %q", withCRLF.String(), without.String())
	}
}

func TestHashCredential_EmptyInput(t *testing.T) {
	var out bytes.Buffer
	err := hashCredential(strings.NewReader(""), &out)
	if err == nil {
		t.Fatal("expected an error for empty stdin")
	}
	if out.Len() != 0 {
		t.Errorf("no output expected on error, got %q", out.String())
	}
}

// TestHashCredential_OutputNeverEmbedsPlaintext guards against a future
// regression that accidentally echoes the plaintext instead of (or alongside)
// the hash.
func TestHashCredential_OutputNeverEmbedsPlaintext(t *testing.T) {
	const token = "s3cr3t-control-plane-credential"

	var out bytes.Buffer
	if err := hashCredential(strings.NewReader(token), &out); err != nil {
		t.Fatalf("hashCredential: %v", err)
	}
	if strings.Contains(out.String(), token) {
		t.Fatalf("output embeds the plaintext credential: %q", out.String())
	}
}
