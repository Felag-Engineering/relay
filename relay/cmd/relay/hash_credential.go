package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

var (
	errReadStdin       = errors.New("read stdin failed")
	errEmptyCredential = errors.New("no credential read from stdin")
)

// runHashCredentialCommand implements `relay hash-credential`: it reads a
// plaintext control-plane credential from stdin — never argv or an
// environment variable, so the plaintext never appears in shell history, a
// process listing, or a CI log — and prints its canonical
// "sha256:<64 lowercase hex>" hash (relay/internal/controlplane.
// ParseCredentialHash) to stdout. The plaintext itself is never printed,
// logged, or otherwise echoed. Kept as a small, self-contained file so it can
// be reviewed independently of the composition root (main.go) that invokes
// it; see docs/operations/control-plane-credential.md for the operator flow
// and the openssl-based fallback.
func runHashCredentialCommand() {
	if err := hashCredential(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "relay hash-credential:", err)
		os.Exit(1)
	}
}

// hashCredential reads a plaintext credential from stdin, hashes it, and
// writes its canonical "sha256:<hex>" form to stdout followed by a newline.
// It is the pure, testable core of runHashCredentialCommand: it never touches
// os.Stdin/os.Exit directly, so tests can substitute in-memory readers and
// writers.
func hashCredential(stdin io.Reader, stdout io.Writer) error {
	raw, err := io.ReadAll(stdin)
	if err != nil {
		return errReadStdin
	}

	// Trim a trailing newline only (the common case for a typed or piped
	// credential); the credential itself is otherwise passed through
	// unmodified since it is opaque, high-entropy bearer-token material.
	token := trimTrailingNewline(raw)
	if len(token) == 0 {
		return errEmptyCredential
	}

	sum := sha256.Sum256(token)
	_, err = fmt.Fprintln(stdout, "sha256:"+hex.EncodeToString(sum[:]))
	return err
}

// trimTrailingNewline strips one trailing "\n" or "\r\n" from b.
func trimTrailingNewline(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
		if n := len(b); n > 0 && b[n-1] == '\r' {
			b = b[:n-1]
		}
	}
	return b
}
