// Package main: health_e2e_test.go pins the health endpoint and the day-one
// metrics against the real composition root: the route answers without a
// credential, and the counters and gauges are wired to the places that move
// them.
package main

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/ca"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane/console"
)

func TestE2E_HealthAnswersServingWithoutACredential(t *testing.T) {
	f := startRelay(t, WithControlPlane())

	resp, err := f.ClientFor("").Get(f.ControlBase + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusOK || body != "serving\n" {
		t.Fatalf("GET /healthz = %d %q, want 200 %q", resp.StatusCode, body, "serving\n")
	}
}

// scrapeSeries returns every sample on /metrics keyed by "name{labels}".
func scrapeSeries(t *testing.T, f *relayFixture) map[string]float64 {
	t.Helper()
	resp, err := f.Client().Get(f.ControlBase + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics = %d, want 200: %s", resp.StatusCode, body)
	}
	series := map[string]float64{}
	for _, line := range strings.Split(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndex(line, " ")
		v, err := strconv.ParseFloat(line[i+1:], 64)
		if err != nil {
			t.Fatalf("unparseable sample %q: %v", line, err)
		}
		series[line[:i]] = v
	}
	return series
}

func TestE2E_MetricsCarryTheDayOneSeries(t *testing.T) {
	f := startRelay(t,
		WithControlPlane(),
		WithConfig(func(c *Config) { c.ConsoleEnabled = true }),
	)
	before := scrapeSeries(t, f)

	do := func(client *http.Client, method, path string) {
		t.Helper()
		req, err := http.NewRequest(method, f.ControlBase+path, strings.NewReader(""))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	do(f.ClientFor(""), http.MethodGet, "/api/v1/ping")
	do(f.ClientFor("not-a-real-token"), http.MethodPost, "/mcp")
	do(f.ClientFor(""), http.MethodGet, "/healthz") // not an authentication failure

	browser := consoleClient(t, f)
	loginPage, err := browser.Get(f.ControlBase + console.LoginPath)
	if err != nil {
		t.Fatalf("GET login page: %v", err)
	}
	csrf := consoleHiddenField(t, readAll(t, loginPage), "csrf_token")
	signIn, err := browser.PostForm(f.ControlBase+console.LoginPath, url.Values{
		"username": {testAdminName}, "password": {"wrong-password"}, "csrf_token": {csrf},
	})
	if err != nil {
		t.Fatalf("POST sign-in: %v", err)
	}
	readAll(t, signIn)

	after := scrapeSeries(t, f)

	for series, wantDelta := range map[string]float64{
		`relay_auth_failures_total{surface="control_api",reason="no_credential"}`: 1,
		`relay_auth_failures_total{surface="mcp",reason="rejected"}`:              1,
		`relay_auth_failures_total{surface="console",reason="sign_in_failed"}`:    1,
		`relay_auth_failures_total{surface="other",reason="no_credential"}`:       0,
	} {
		if _, ok := after[series]; !ok {
			t.Errorf("series %s is missing", series)
			continue
		}
		if got := after[series] - before[series]; got != wantDelta {
			t.Errorf("%s moved by %v, want %v", series, got, wantDelta)
		}
	}

	if got, ok := after["relay_approvals_waiting"]; !ok || got != 0 {
		t.Errorf("relay_approvals_waiting = %v (present %v), want 0", got, ok)
	}
	if got, ok := after[`relay_certificate_remaining_seconds{certificate="relay_ca"}`]; !ok || got <= 0 {
		t.Errorf("relay_ca remaining = %v (present %v), want > 0", got, ok)
	}
	got, ok := after[`relay_certificate_remaining_seconds{certificate="server"}`]
	if !ok || got <= 0 || got > ca.ServerLeafValidity.Seconds() {
		t.Errorf("server remaining = %v (present %v), want in (0, %v]", got, ok, ca.ServerLeafValidity.Seconds())
	}
}
