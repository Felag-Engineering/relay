package approval

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/hostfile"
)

const validConfig = `{
  "rules": [
    {
      "name": "prod-mutates-need-two",
      "match": {"risk_class": "mutate", "min_fan_out": 10, "selector_namespace": "relay"},
      "require": {"count": 2, "channel": "out-of-band", "ttl": "2h"}
    }
  ]
}`

func writeConfig(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "approval-gates.json")
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatalf("write config: %v", err)
	}
	// WriteFile's mode is masked by the process umask (commonly 022), which
	// would quietly turn the 0666 case into 0644 and make the world-writable
	// test vacuous. Chmod is not masked.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod config: %v", err)
	}
	return path
}

func TestLoadValidConfig(t *testing.T) {
	g, err := loadPlain(writeConfig(t, validConfig, 0o600))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	rules := g.Rules()
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	r := rules[0]
	if r.Name != "prod-mutates-need-two" || r.Require.Count != 2 || r.Require.TTL != 2*time.Hour {
		t.Errorf("rule did not round-trip: %+v", r)
	}
	if r.Require.RequesterAllowed {
		t.Error("requester_allowed must default to false — an omitted field must not silently relax the rule")
	}
}

// TestLoadValidConfig_StateNamespaceValidates is ADR-0034's addition to the
// approval-gate vocabulary: a rule scoped to the fourth namespace must load
// exactly as "tag" and "relay" already do.
func TestLoadValidConfig_StateNamespaceValidates(t *testing.T) {
	cfg := `{"rules":[{"name":"r","match":{"selector_namespace":"state"},"require":{"count":1}}]}`
	g, err := loadPlain(writeConfig(t, cfg, 0o600))
	if err != nil {
		t.Fatalf("Load with selector_namespace \"state\": %v", err)
	}
	if len(g.Rules()) != 1 {
		t.Fatalf("got %d rules, want 1", len(g.Rules()))
	}
}

// TestEmptyPathMeansNoGates: the ONLY way to get a gate-less Relay is to
// configure no path at all. Everything else is an error.
func TestEmptyPathMeansNoGates(t *testing.T) {
	g, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\"): %v", err)
	}
	if len(g.Rules()) != 0 {
		t.Error("no configured path must mean no rules")
	}
}

// TestLoadFailsClosed is the security property of this loader. Every one of
// these cases must be an ERROR, never an empty Gate: a Relay that silently
// decides nothing needs approval because it could not read its own config is
// exactly the failure this mechanism exists to prevent.
// loadPlain opens path without hostfile's check, which refuses every temporary directory a
// test can make, and runs the rest of Load on it. The check itself is hostfile's table test,
// and the real binary meets it on the separate-uid harness.
func loadPlain(path string) (*Gate, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return loadOpened(f, path)
}

func TestLoadFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		load func(string) (*Gate, error) // nil: loadPlain
		path func(t *testing.T) string
		want string
	}{
		{
			name: "missing file",
			load: Load,
			path: func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.json") },
			want: "does not exist",
		},
		{
			name: "malformed json",
			path: func(t *testing.T) string { return writeConfig(t, `{"rules": [`, 0o600) },
			want: "parse gate config",
		},
		{
			name: "unknown field",
			path: func(t *testing.T) string {
				return writeConfig(t, `{"rules":[{"name":"r","require":{"count":1,"requester_allowd":true}}]}`, 0o600)
			},
			want: "parse gate config",
		},
		{
			name: "unknown risk class",
			path: func(t *testing.T) string {
				return writeConfig(t, `{"rules":[{"name":"r","match":{"risk_class":"destroy"},"require":{"count":1}}]}`, 0o600)
			},
			want: "unknown risk_class",
		},
		{
			name: "unknown channel",
			path: func(t *testing.T) string {
				return writeConfig(t, `{"rules":[{"name":"r","require":{"count":1,"channel":"telepathy"}}]}`, 0o600)
			},
			want: "unknown channel",
		},
		{
			name: "unnamed rule",
			path: func(t *testing.T) string {
				return writeConfig(t, `{"rules":[{"require":{"count":1}}]}`, 0o600)
			},
			want: "no name",
		},
		{
			name: "count above the v1 maximum",
			path: func(t *testing.T) string {
				return writeConfig(t, `{"rules":[{"name":"r","require":{"count":9}}]}`, 0o600)
			},
			want: "exceeds the v1 maximum",
		},
		{
			name: "world-writable file",
			path: func(t *testing.T) string { return writeConfig(t, validConfig, 0o666) },
			want: "world-writable",
		},
		{
			// RC-8 on top of the file check: hostfile passes a group-writable file whose group
			// excludes the Relay (root:wheel 0664), and the gate file still refuses it.
			name: "group-writable file",
			path: func(t *testing.T) string { return writeConfig(t, validConfig, 0o664) },
			want: "group- or world-writable (mode 0664)",
		},
		{
			name: "unknown selector namespace",
			path: func(t *testing.T) string {
				return writeConfig(t, `{"rules":[{"name":"r","match":{"selector_namespace":"tenant"},"require":{"count":1}}]}`, 0o600)
			},
			want: "unknown selector namespace",
		},
		{
			name: "empty audience entry",
			path: func(t *testing.T) string {
				return writeConfig(t, `{"rules":[{"name":"blank-approver","require":{"count":1,"audience":[""]}}]}`, 0o600)
			},
			want: `rule "blank-approver": require.audience`,
		},
		{
			name: "whitespace-only audience entry",
			path: func(t *testing.T) string {
				return writeConfig(t, `{"rules":[{"name":"ws-approver","require":{"count":1,"audience":["ana","  "]}}]}`, 0o600)
			},
			want: `rule "ws-approver": require.audience`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			load := tc.load
			if load == nil {
				load = loadPlain
			}
			g, err := load(tc.path(t))
			if err == nil {
				t.Fatalf("Load succeeded with %d rules; a config the Relay cannot trust must be an error, never an empty Gate", len(g.Rules()))
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestLoadRefusesSymlink: the gate file decides what needs human approval, so
// it must be a real file rather than a link someone else controls; the file
// check refuses the link before anything reads it.
func TestLoadRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	if err := os.WriteFile(real, []byte(validConfig), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, err := Load(link)
	var r *hostfile.Refusal
	if !errors.As(err, &r) || r.Clause != hostfile.ClauseSymlink {
		t.Fatalf("Load(symlink) = %v, want the file check's symlink refusal", err)
	}
}

// TestLoadRefusesDirectory covers the non-regular-file case on the open
// descriptor rather than on the path.
func TestLoadRefusesDirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir); err == nil {
		t.Fatal("Load accepted a directory as a gate config")
	}
	if _, err := loadPlain(dir); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("loadOpened(directory) = %v, want a not-a-regular-file refusal", err)
	}
}

// TestLoadRefusesBlankAudienceEntryRatherThanNormalising is the #608
// regression: pre-fix, a rule whose audience was exactly [""] loaded
// successfully and read back as an UNRESTRICTED audience (an empty entry
// stored and joined comes back indistinguishable from no audience at all).
// Loading must refuse it and name the rule, never silently drop the entry.
func TestLoadRefusesBlankAudienceEntryRatherThanNormalising(t *testing.T) {
	cfg := `{"rules":[{"name":"blank-approver","require":{"count":1,"audience":[""]}}]}`
	g, err := loadPlain(writeConfig(t, cfg, 0o600))
	if g != nil {
		t.Errorf("Load returned a non-nil Gate on a blank audience entry: %+v", g.Rules())
	}
	if !errors.Is(err, ErrAudienceBlankEntry) {
		t.Fatalf("err = %v, want errors.Is(err, ErrAudienceBlankEntry)", err)
	}
	if !strings.Contains(err.Error(), "blank-approver") {
		t.Errorf("error = %q, want it to name the rule", err)
	}
}
