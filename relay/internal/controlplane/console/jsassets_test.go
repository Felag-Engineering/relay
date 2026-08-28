package console

// jsassets_test.go runs the Console's asset JavaScript under node, against a
// hand-written DOM stub (testdata/dom.js).
//
// # Why this exists at all
//
// The three properties that matter about assets/*.js are invisible to every
// other test in this package: that the files WIRE UP, that the resume point
// moves in the shared transport rather than in a screen's handler, and that
// day one still works after #422 lifted its transport into the shell. A text
// search for `maxAttempts` proves none of them, and a ReferenceError thrown
// inside an event handler under "use strict" is silent — the live region just
// stops resuming and continues to look healthy.
//
// # Why it SKIPS rather than fails without node
//
// This repository's toolchains are Go and Rust (CLAUDE.md); node is not one of
// them and this must not make it one. Where node is present — every developer
// box, and CI if it grows one — these run and catch the regression. Where it
// is not, the text-level assertions in dayone_test.go still stand. A test that
// made `make test-relay` depend on a third toolchain would be removed by the
// first person it blocked, and then nothing would watch this at all.

// The file is NOT called assets_js_test.go. Go reads the suffix before
// _test.go as a build constraint, `js` is a real GOOS (WebAssembly), and that
// name is silently excluded from every ordinary build — the test compiles,
// lints clean and never runs.
import (
	"os/exec"
	"strings"
	"testing"
)

func TestAssets_JavaScriptBehavesUnderADOM(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed; assets/*.js is asserted at the text level by dayone_test.go")
	}

	for _, script := range []string{"testdata/check_activity.js", "testdata/check_dayone.js"} {
		t.Run(strings.TrimSuffix(strings.TrimPrefix(script, "testdata/check_"), ".js"), func(t *testing.T) {
			out, err := exec.Command(node, script).CombinedOutput()
			if err != nil {
				t.Fatalf("%s failed:\n%s", script, out)
			}
			if !strings.Contains(string(out), "OK") {
				t.Errorf("%s produced no result:\n%s", script, out)
			}
		})
	}
}
