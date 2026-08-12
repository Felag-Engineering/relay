package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/metrics"
)

// TestMetricsSurface_RequiresCredential proves /metrics is reached only
// through the same bearer auth as every other control-plane route (invariant
// 10, DoD: "unauthenticated /metrics request is refused (401)").
func TestMetricsSurface_RequiresCredential(t *testing.T) {
	const token = accounts.TokenPrefix + "0f1e2d3c4b5a6978.metrics-test" //nolint:gosec // test fixture, not a real credential
	authn := controlplane.NewAuthenticator(staticVerifier{credential: token})

	mux := http.NewServeMux()
	sd := surfaceDeps{metrics: metrics.New(metrics.GaugeSources{
		Connected: func() int { return 1 },
	})}
	metricsSurface{}.Mount(mux, sd)

	srv := httptest.NewServer(authn.Middleware(mux))
	defer srv.Close()

	t.Run("no credential", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/metrics") //nolint:noctx // test
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		defer resp.Body.Close() //nolint:errcheck
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
		}
	})

	t.Run("wrong credential", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/metrics", nil)
		req.Header.Set("Authorization", "Bearer wrong-"+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close() //nolint:errcheck
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
		}
	})

	t.Run("correct credential", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/metrics", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		defer resp.Body.Close() //nolint:errcheck
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		body := string(bodyBytes)
		for _, want := range []string{
			"relay_nodes_connected 1",
			"relay_dispatches_total",
			"relay_refusals_total",
			"relay_enrollments_total",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("body missing %q; body = %s", want, body)
			}
		}
	})
}
