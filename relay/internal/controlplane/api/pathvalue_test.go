package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequirePathValue(t *testing.T) {
	tests := []struct {
		name      string
		pathValue string
		wantOK    bool
	}{
		{"present", "abc", true},
		{"empty", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/x", nil)
			r.SetPathValue("id", tc.pathValue)
			w := httptest.NewRecorder()

			got, ok := requirePathValue(w, r, "id", "id required", "detail")

			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got != tc.pathValue {
				t.Fatalf("value = %q, want %q", got, tc.pathValue)
			}
			if !ok && w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", w.Code)
			}
			if ok && w.Code != http.StatusOK {
				t.Fatalf("wrote a response on success: %d", w.Code)
			}
		})
	}
}

// TestRequireAccountAdminAndIDEmptyPathParam pins the 400 body an empty path
// parameter renders on the Account and API Token routes.
func TestRequireAccountAdminAndIDEmptyPathParam(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.SetPathValue("token_id", "")
	w := httptest.NewRecorder()

	_, ok := requirePathValue(w, r, "token_id", "missing api token id",
		"path parameter token_id must not be empty")

	if ok || w.Code != http.StatusBadRequest {
		t.Fatalf("ok=%v status=%d, want false/400", ok, w.Code)
	}
	if body := w.Body.String(); !strings.Contains(body, "missing api token id") ||
		!strings.Contains(body, "path parameter token_id must not be empty") {
		t.Fatalf("body = %s", body)
	}
}
