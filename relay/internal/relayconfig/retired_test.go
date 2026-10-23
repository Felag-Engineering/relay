package relayconfig

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// Not startup settings: the Freeze lever's note, read at signal time, and the
// devharness build's test seam.
var retiredExemptions = []string{"RELAY_FREEZE_RELEASE_REASON", "RELAY_DEVHARNESS_SOCKET"}

var relayEnvName = regexp.MustCompile(`RELAY_[A-Z0-9_]*[A-Z0-9]`)

func packageDir(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate the package directory")
	}
	return filepath.Dir(self)
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Proves RC-13.
func TestRetiredEnvMap_CoversEveryRetiredName(t *testing.T) {
	keys := schemaKeys()
	for name, key := range retiredEnv {
		if !slices.Contains(keys, key) {
			t.Errorf("%s maps to %q, which is not a schema key", name, key)
		}
	}

	// Every name the binary or its example reads is retired or exempt.
	dir := packageDir(t)
	sources, err := filepath.Glob(filepath.Join(dir, "..", "..", "cmd", "relay", "*.go"))
	if err != nil || len(sources) == 0 {
		t.Fatalf("no cmd/relay sources found: %v", err)
	}
	sources = slices.DeleteFunc(sources, func(p string) bool { return strings.HasSuffix(p, "_test.go") })
	if example := filepath.Join(dir, "..", "..", "packaging", "relay.env.example"); fileExists(example) {
		sources = append(sources, example)
	}
	seen := map[string]bool{}
	for _, src := range sources {
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range relayEnvName.FindAllString(string(data), -1) {
			seen[name] = true
		}
	}
	for name := range seen {
		_, retired := retiredEnv[name]
		if !retired && !slices.Contains(retiredExemptions, name) {
			t.Errorf("%s is read by the binary but is neither in retiredEnv nor exempt", name)
		}
	}
	for _, name := range retiredExemptions {
		if !seen[name] {
			t.Errorf("exemption %s no longer appears in the scanned source; drop it", name)
		}
	}

	// Removing a name is a decision, so the count is pinned.
	if len(retiredEnv) != 30 {
		t.Errorf("retiredEnv has %d entries, want 30", len(retiredEnv))
	}
}

// Proves RC-13.
func TestRefuseRetiredEnv_NamesKeyNotValue(t *testing.T) {
	err := RefuseRetiredEnv([]string{"PATH=/bin", "RELAY_CONTROL_ADDR=hunter2"})
	if err == nil {
		t.Fatal("a retired name was accepted")
	}
	if !strings.Contains(err.Error(), "RELAY_CONTROL_ADDR") || !strings.Contains(err.Error(), "control_plane.listen_address") {
		t.Errorf("error = %q", err)
	}
	if strings.Contains(err.Error(), "hunter2") {
		t.Errorf("error prints the value: %q", err)
	}

	err = RefuseRetiredEnv([]string{"RELAY_APPROVAL_WEBHOOK_URL=https://x.example/tok"})
	if err == nil || !strings.Contains(err.Error(), "approval.webhook_url or approval.webhook_url_file") {
		t.Errorf("a secret key must render both forms: %v", err)
	}

	if err := RefuseRetiredEnv([]string{"RELAY_HOSTNAME="}); err == nil {
		t.Error("a retired name with an empty value was accepted")
	}

	for _, ok := range [][]string{
		nil,
		{"RELAY_FREEZE_RELEASE_REASON=because", "RELAY_DEVHARNESS_SOCKET=/tmp/s", "HOME=/root", "RELAYX=1"},
	} {
		if err := RefuseRetiredEnv(ok); err != nil {
			t.Errorf("RefuseRetiredEnv(%v) = %v", ok, err)
		}
	}

	a := RefuseRetiredEnv([]string{"RELAY_STORE_PATH=x", "RELAY_CA_DIR=y", "RELAY_ADDR=z"})
	b := RefuseRetiredEnv([]string{"RELAY_ADDR=z", "RELAY_STORE_PATH=x", "RELAY_CA_DIR=y"})
	if a == nil || b == nil || a.Error() != b.Error() {
		t.Fatalf("output is not deterministic:\n%v\n%v", a, b)
	}
	msg := a.Error()
	if i, j, k := strings.Index(msg, "RELAY_ADDR"), strings.Index(msg, "RELAY_CA_DIR"), strings.Index(msg, "RELAY_STORE_PATH"); i >= j || j >= k {
		t.Errorf("names are not sorted: %q", msg)
	}
	if err := RefuseRetiredEnv([]string{"RELAY_ADDR=1", "RELAY_ADDR=2"}); err == nil || strings.Count(err.Error(), "RELAY_ADDR is set") != 1 {
		t.Errorf("a name set twice is listed more than once: %v", err)
	}
}
