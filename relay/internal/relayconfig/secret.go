package relayconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
)

const redacted = "[redacted]"

// Secret is a configuration value that cannot print itself. It is read from a
// file the configuration names (RC-41, ADR-0043). The value
// sits behind a pointer to an unexported struct, so fmt, slog and
// encoding/json print a placeholder, never the value. Reveal is the only
// accessor.
type Secret struct {
	v *secretValue
}

type secretValue struct {
	value    string
	path     string
	key      string
	line     int
	resolved bool
}

func fileSecret(path, key string, line int) Secret {
	return Secret{&secretValue{path: path, key: key, line: line}}
}

// IsSet reports whether a file was named.
func (s Secret) IsSet() bool { return s.v != nil }

// Path returns the file the value is read from, or "" when unset.
func (s Secret) Path() string {
	if s.v == nil {
		return ""
	}
	return s.v.path
}

// Reveal returns the value. It is false when the secret is unset, or is
// file-backed and not yet resolved.
func (s Secret) Reveal() (string, bool) {
	if s.v == nil || !s.v.resolved {
		return "", false
	}
	return s.v.value, true
}

// The methods below are value receivers so a Config passed by value redacts
// as well as one passed by pointer.

func (s Secret) String() string   { return redacted }
func (s Secret) GoString() string { return redacted }

// Format redacts for every verb, so no %d or %x spelling reaches the bytes.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

func (s Secret) LogValue() slog.Value { return slog.StringValue(redacted) }

func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }
func (s Secret) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// ResolveSecrets reads every file-backed secret through read and stores the
// value. The caller supplies read so each file is read through its own file
// check; this package opens nothing.
func (c *Config) ResolveSecrets(read func(path string) ([]byte, error)) error {
	var errs []error
	for _, s := range []*Secret{&c.Approval.WebhookURL, &c.Approval.WebhookSecret} {
		if s.v == nil || s.v.path == "" || s.v.resolved {
			continue
		}
		if err := s.resolve(read); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// resolve replaces *s with a fresh value rather than filling in the old one,
// because Config copies share the old pointer.
func (s *Secret) resolve(read func(path string) ([]byte, error)) *Error {
	old := s.v
	data, err := read(old.path)
	if err != nil {
		reason := "the file could not be read, or was refused by the file check"
		var class error
		switch {
		case errors.Is(err, fs.ErrNotExist):
			reason, class = "the file does not exist", fs.ErrNotExist
		case errors.Is(err, fs.ErrPermission):
			reason, class = "the file cannot be read: permission denied", fs.ErrPermission
		}
		return &Error{Key: old.key, Line: old.line, Reason: reason, class: class}
	}
	value := string(bytes.TrimSpace(data))
	if value == "" {
		return &Error{Key: old.key, Line: old.line, Reason: "the file is empty"}
	}
	if old.key == keyWebhookURLFile {
		if reason := httpURLProblem(value); reason != "" {
			return &Error{Key: old.key, Line: old.line, Reason: "the file does not hold " + reason}
		}
	}
	fresh := *old
	fresh.value, fresh.resolved = value, true
	s.v = &fresh
	return nil
}
