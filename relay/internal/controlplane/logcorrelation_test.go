package controlplane

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/logctx"
)

// TestServer_RequestIDIsRelayMintedPerRequest pins the log-correlation id
// (#902): every request through the listener's handler gets its own non-empty
// id, a caller-supplied X-Request-Id is neither adopted (log injection) nor
// echoed, and the id is set before the principal so both reach the handler.
func TestServer_RequestIDIsRelayMintedPerRequest(t *testing.T) {
	srv, base, client := newTestServer(t)

	var mu sync.Mutex
	var ids, principals []string
	srv.Mux().HandleFunc("GET /probe", func(w http.ResponseWriter, r *http.Request) {
		id, _ := logctx.RequestIDFrom(r.Context())
		who, _ := logctx.PrincipalFrom(r.Context())
		mu.Lock()
		ids, principals = append(ids, id), append(principals, who)
		mu.Unlock()
	})

	for i := 0; i < 2; i++ {
		req, err := http.NewRequest(http.MethodGet, base+"/probe", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+testToken)
		req.Header.Set("X-Request-Id", "caller-chosen")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Do: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		if got := resp.Header.Get("X-Request-Id"); got != "" {
			t.Errorf("response carries X-Request-Id %q; the id must never go on the wire", got)
		}
	}

	if len(ids) != 2 {
		t.Fatalf("handler ran %d times, want 2", len(ids))
	}
	if ids[0] == "" || ids[1] == "" || ids[0] == ids[1] {
		t.Errorf("request ids = %q, want two distinct non-empty ids", ids)
	}
	for _, id := range ids {
		if id == "caller-chosen" {
			t.Errorf("an inbound X-Request-Id was adopted as the request id")
		}
	}
	for _, p := range principals {
		if p != "founding-admin:admin" {
			t.Errorf("principal = %q, want the authenticated Account's attribution", p)
		}
	}
}

// TestMiddleware_PrincipalReachesLogContext pins that an authenticated
// request's context carries the Account's attribution for log correlation.
func TestMiddleware_PrincipalReachesLogContext(t *testing.T) {
	var got string
	var ok bool
	h := testAuthenticator().Middleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got, ok = logctx.PrincipalFrom(r.Context())
		p, _ := PrincipalFromContext(r.Context())
		if want := p.Attribution(); got != want {
			t.Errorf("logctx principal = %q, want %q", got, want)
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !ok || got == "" {
		t.Error("no principal on the log context after Middleware")
	}
}
