package relaytest

import (
	"os"
	"path/filepath"
	"testing"
)

// FixturePolicy is the TOML policy a daemon subprocess loads across the
// cmd/relay integration e2e suites. It allows file.read (wildcard, except
// /etc/shadow), service.restart for nginx only (sshd denied by default), and
// raw_exec for systemctl status/restart plus a bounded /bin/sleep (used by
// the cancel/concurrency e2e tests to get a measurable long-running,
// Policy-allowed Task).
const FixturePolicy = `
[[operation]]
name = "file.read"
allowed_args = [["*"]]

[[deny]]
name = "file.read"
args = [["/etc/shadow"]]

[[operation]]
name = "system.facts"
allowed_args = []

[[operation]]
name = "service.restart"
allowed_args = [["nginx"]]

[raw_exec]
allow = ["^/usr/bin/systemctl (status|restart) [A-Za-z0-9@._-]+$", "^/bin/sleep [0-9]+$"]
deny  = ["--force", "\\brm\\b"]
`

// FixtureTemplatePack is the Template Operation pack a daemon subprocess loads
// in the e2e suites that exercise the template tier (ADR-0021). One
// zero-parameter read template, so the e2e can prove the whole local-loading
// path — file on disk -> compiled -> fingerprinted -> reported -> dispatchable
// -> Policy-governed — without depending on any host binary beyond `echo`.
const FixtureTemplatePack = `
[[template]]
name = "e2e.template"
risk_class = "read"
body = "echo template-ran"
`

// FixtureTemplatePolicyRule is the [[operation]] allow rule that makes
// FixtureTemplatePack's template runnable — loading a template never allows it
// (deny-by-default, ADR-0002). It is a SEPARATE fragment, appended by the one
// suite that installs the pack, rather than part of FixturePolicy: the shared
// fixture is asserted verbatim by other suites (describe_node's exact
// allowed_operations set, and `policy check`'s unknown-name lint over a Policy
// whose template root they do not install), so an extra rule there would fail
// tests that are correctly checking something else.
const FixtureTemplatePolicyRule = `
[[operation]]
name = "e2e.template"
allowed_args = []
`

// WriteTemplatePack writes content as a single *.toml file inside a fresh
// template-root directory under t.TempDir() (mode 0600 file in a 0755 dir, the
// daemon loader's requirements) and returns the ROOT directory path — the
// value RELAY_TEMPLATE_DIR takes.
func WriteTemplatePack(t *testing.T, content string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "templates.d")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("create template root: %v", err)
	}
	path := filepath.Join(root, "pack.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write template file: %v", err)
	}
	return root
}

// WriteTempFile writes content to a new 0600 temp file under t.TempDir() and
// returns its path.
func WriteTempFile(t *testing.T, pattern, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), pattern)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()
	if err := os.Chmod(f.Name(), 0600); err != nil {
		t.Fatalf("chmod temp file: %v", err)
	}
	return f.Name()
}
