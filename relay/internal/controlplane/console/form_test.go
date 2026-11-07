package console

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseSubmittedForm(t *testing.T) {
	t.Run("parses a well-formed body", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("a=1"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if !parseSubmittedForm(w, r) {
			t.Fatal("parseSubmittedForm = false, want true")
		}
		if got := r.PostForm.Get("a"); got != "1" {
			t.Fatalf("PostForm a = %q, want 1", got)
		}
		if w.Body.Len() != 0 {
			t.Fatalf("wrote a response on success: %q", w.Body.String())
		}
	})
	t.Run("refuses a malformed body with 400", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("a=%zz"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if parseSubmittedForm(w, r) {
			t.Fatal("parseSubmittedForm = true, want false")
		}
		if w.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", w.Code)
		}
		if !strings.Contains(w.Body.String(), unreadableFormMessage) {
			t.Fatalf("body = %q, want %q", w.Body.String(), unreadableFormMessage)
		}
	})
}
