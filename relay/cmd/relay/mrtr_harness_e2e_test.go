// Package main: mrtr_harness_e2e_test.go holds the run_operation call the MRTR
// end-to-end suites park through the real composition root.
package main

// restartNginxArgs is the run_operation call the sessions in those suites
// park — identical between them, so the parks are directly comparable.
func restartNginxArgs() map[string]any {
	return map[string]any{
		"operation":    "service.restart",
		"args":         map[string]string{"unit": "nginx"},
		"wait_seconds": 300,
	}
}
