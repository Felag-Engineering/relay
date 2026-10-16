//go:build !linux

package hostfile

import (
	"errors"
	"testing"
)

func TestOpen_RefusesOffLinux(t *testing.T) {
	for _, open := range []func(string, Rule) error{
		func(p string, r Rule) error { _, err := Open(p, r); return err },
		func(p string, r Rule) error { _, err := OpenDir(p, r); return err },
	} {
		var ref *Refusal
		if err := open("/etc/relay/relay.toml", Secret); !errors.As(err, &ref) || ref.Clause != ClauseUnsupportedOS {
			t.Fatalf("got %v", err)
		}
	}
}
