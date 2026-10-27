//go:build integration

// Package main: crossbinary_preflight_e2e_test.go proves, against the real
// relay and relay-daemon binaries, that a Policy preflight deny arrives with
// the pass and rule reference `relay-daemon policy explain` prints for the
// same question (ADR-0011): the daemon's one answer, carried display-only.
//
// Skip condition: RELAY_BIN or RELAY_DAEMON_BIN env var not set.
// Run via: make test-crossbinary.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
)

// TestCrossBinary_PreflightDenyCarriesTheRuleReferencePolicyExplainPrints runs
// each question through `relay-daemon policy explain` and through the Relay's
// Policy preflight against a daemon loading the same file, and requires the
// two to name the same pass, rule and matched-on text.
func TestCrossBinary_PreflightDenyCarriesTheRuleReferencePolicyExplainPrints(t *testing.T) {
	relayBin, daemonBin := skipUnlessFleetBins(t)

	fr := startFleetRelay(t, relayBin, "")
	daemonLog := &syncBuffer{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("relay log:\n%s\ndaemon log:\n%s", fr.proc.Log(), daemonLog.String())
		}
	})

	join := createFleetJoinString(t, fr.harness, "tag:env=test")
	policyPath := relaytest.WriteTempFile(t, "policy-*.toml", relaytest.FixturePolicy)
	relaytest.StartDaemon(t, relaytest.DaemonConfig{
		Bin:        daemonBin,
		JoinString: join,
		StateDir:   t.TempDir(),
		PolicyPath: policyPath,
		Hostname:   "preflight-rule-reference",
		LogWriter:  daemonLog,
	})
	waitForConnected(t, fr.harness, 1)

	// An empty template root keeps explain from falling back to the host's
	// RELAY_TEMPLATE_DIR or default root.
	templatesDir := t.TempDir()

	cases := []struct {
		name        string
		explainSpec []string
		request     map[string]any
	}{
		{
			name:        "operation denied by a [[deny]] rule",
			explainSpec: []string{"operation", "file.read", "path=/etc/shadow"},
			request: map[string]any{
				"operation": "file.read",
				"args":      map[string]string{"path": "/etc/shadow"},
			},
		},
		{
			name:        "raw exec denied by a [raw_exec].deny pattern",
			explainSpec: []string{"raw-exec", "--", "/bin/rm", "-f", "/tmp/x"},
			request:     map[string]any{"raw_exec": []string{"/bin/rm", "-f", "/tmp/x"}},
		},
		{
			name:        "operation denied by default",
			explainSpec: []string{"operation", "service.restart", "unit=sshd"},
			request: map[string]any{
				"operation": "service.restart",
				"args":      map[string]string{"unit": "sshd"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			explain := runPolicyExplain(t, daemonBin, policyPath, templatesDir, tc.explainSpec)

			req := map[string]any{"op": "preflight_job", "selector": "tag:env=test"}
			for k, v := range tc.request {
				req[k] = v
			}
			resp := fr.harness.call(t, req)
			verdicts, _ := resp["verdicts"].([]any)
			if len(verdicts) != 1 {
				t.Fatalf("preflight_job: got %d verdicts, want 1: %v", len(verdicts), resp)
			}
			v, _ := verdicts[0].(map[string]any)
			if status, _ := v["status"].(string); status != "deny" {
				t.Fatalf("verdict status = %q, want deny: %v", status, v)
			}

			for _, key := range []string{"pass", "rule", "matched on"} {
				if explain[key] == "" {
					t.Fatalf("policy explain printed no %q line: %v", key, explain)
				}
			}

			if got, _ := v["pass"].(string); got != explain["pass"] {
				t.Errorf("verdict pass = %q, explain prints %q", got, explain["pass"])
			}
			if got, _ := v["matched_on"].(string); got != explain["matched on"] {
				t.Errorf("verdict matched_on = %q, explain prints %q", got, explain["matched on"])
			}
			if got := formatRuleReference(v); got != explain["rule"] {
				t.Errorf("verdict rule reference = %q, explain prints %q", got, explain["rule"])
			}
			if got, _ := v["deciding_rule"].(string); got != explain["reason"] {
				t.Errorf("verdict deciding_rule = %q, explain reason = %q", got, explain["reason"])
			}
		})
	}
}

// runPolicyExplain runs `relay-daemon policy explain` for a deny and returns
// its `key: value` lines. A deny exits 2.
func runPolicyExplain(t *testing.T, daemonBin, policyPath, templatesDir string, spec []string) map[string]string {
	t.Helper()
	args := append([]string{"policy", "explain", policyPath, "--templates", templatesDir}, spec...)
	cmd := exec.Command(daemonBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("policy explain %v: err = %v, want exit code 2 (would deny)\nstdout: %s\nstderr: %s",
			spec, err, stdout.String(), stderr.String())
	}
	out := map[string]string{}
	for _, line := range strings.Split(stdout.String(), "\n") {
		if key, val, ok := strings.Cut(line, ": "); ok {
			out[key] = val
		}
	}
	return out
}

// formatRuleReference renders a harness verdict's rule reference in the
// grammar `policy explain` prints on its `rule:` line.
func formatRuleReference(v map[string]any) string {
	section, _ := v["rule_section"].(string)
	index, _ := v["rule_index"].(float64)
	line, _ := v["rule_line"].(float64)

	var ref string
	switch section {
	case "operation":
		ref = fmt.Sprintf("[[operation]] #%d", int(index))
	case "deny":
		ref = fmt.Sprintf("[[deny]] #%d", int(index))
	case "raw_exec_allow":
		ref = fmt.Sprintf("[raw_exec].allow[%d]", int(index))
	case "raw_exec_deny":
		ref = fmt.Sprintf("[raw_exec].deny[%d]", int(index))
	default:
		if pass, _ := v["pass"].(string); pass == "default" {
			return "none (deny-by-default)"
		}
		return "none"
	}
	if line > 0 {
		ref += fmt.Sprintf(", line %d", int(line))
	}
	return ref
}
