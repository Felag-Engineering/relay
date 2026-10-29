package main

import (
	"sync"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/ca"
	"github.com/Felag-Engineering/relay/relay/internal/ca/catest"
	"github.com/Felag-Engineering/relay/relay/internal/startup"
	"github.com/Felag-Engineering/relay/relay/internal/startup/startuptest"
)

// testCAs holds one in-memory CA per CA directory, so a test that restarts the composition
// root against the same directory meets the same CA, as a restarted Relay does.
var testCAs sync.Map

// testStartupFiles stands in for startup.Open in the in-process suites. The real check
// refuses every temporary directory a test can make (sticky, or the test's own, and a test
// may run as root), so the CA is generated in memory. The check itself is hostfile's table test, and the shippable binary
// meets it on the separate-uid harness.
func testStartupFiles(t testing.TB, cfg Config) startup.Files {
	t.Helper()
	fresh, err := catest.Generate()
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	got, _ := testCAs.LoadOrStore(cfg.CADir, fresh)
	files, err := startuptest.Files(got.(*ca.CA), cfg.StorePath)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

// newServer refuses Files that did not come from the check — the zero value is all a
// production file can make without startup.Open.
func TestNewServer_RefusesFilesNotFromTheCheck(t *testing.T) {
	srv, deps, err := newServer(baseTestConfig(t), startup.Files{})
	if err == nil || srv != nil || deps != nil {
		t.Fatalf("newServer with zero Files = %v, %v, %v; want a refusal", srv, deps, err)
	}
}
