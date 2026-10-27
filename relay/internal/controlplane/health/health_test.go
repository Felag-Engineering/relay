package health

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

func TestPattern_IsGETHealthz(t *testing.T) {
	if Pattern != "GET /healthz" {
		t.Fatalf("Pattern = %q, want %q", Pattern, "GET /healthz")
	}
}

func TestStatus_ZeroValueIsNotServing(t *testing.T) {
	var s Status
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if got := rec.Body.String(); got != "not serving\n" {
		t.Fatalf("body = %q, want %q", got, "not serving\n")
	}
}

func TestStatus_ServingAnswersOneBit(t *testing.T) {
	var s Status
	s.SetServing(true)

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "serving\n" {
		t.Fatalf("body = %q, want %q", got, "serving\n")
	}
	var keys []string
	for k := range rec.Header() {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if got := strings.Join(keys, ","); got != "Cache-Control,Content-Type" {
		t.Fatalf("header keys = %q, want exactly Cache-Control,Content-Type", got)
	}

	// A request carrying a credential, a cookie and a body gets the identical answer.
	req := httptest.NewRequest(http.MethodGet, "/healthz", strings.NewReader("ignored"))
	req.Header.Set("Authorization", "Bearer x")
	req.AddCookie(&http.Cookie{Name: "relay_session", Value: "y"})
	rec2 := httptest.NewRecorder()
	s.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK || rec2.Body.String() != "serving\n" {
		t.Fatalf("credentialed request = %d %q, want 200 %q", rec2.Code, rec2.Body.String(), "serving\n")
	}

	s.SetServing(false)
	rec3 := httptest.NewRecorder()
	s.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec3.Code != http.StatusServiceUnavailable {
		t.Fatalf("after SetServing(false): status = %d, want 503", rec3.Code)
	}
}
