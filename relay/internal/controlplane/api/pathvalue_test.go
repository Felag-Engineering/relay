package api

import (
	"net/http"
	"net/http/httptest"
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
