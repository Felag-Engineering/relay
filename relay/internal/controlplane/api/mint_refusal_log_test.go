package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// TestWriteMintTokenError_LogsARefusalThatWasNotRecorded: a refusal joined with
// its record failure still answers 403 with the sentinel text, and the joined
// error is logged without the request.
func TestWriteMintTokenError_LogsARefusalThatWasNotRecorded(t *testing.T) {
	var buf strings.Builder
	d := Deps{Logger: slog.New(slog.NewTextHandler(&buf, nil))}
	joined := errors.Join(capability.ErrEnrollmentInitialTagsNeedHuman, errors.New("audit store down"))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enrollment-tokens", strings.NewReader(`{"secret":"x"}`))
	writeMintTokenError(rec, req, d, joined)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "audit store down") {
		t.Errorf("body shows the record failure: %s", rec.Body)
	}
	if !strings.Contains(buf.String(), "audit store down") || strings.Contains(buf.String(), "secret") {
		t.Errorf("log = %q, want the joined error and no request", buf.String())
	}
}

// TestWriteMintTokenError_LogsNothingForAnInvalidInitialTag: an invalid initial
// tag is never recorded, so its 400 writes no log line, and the entry the error
// names is not logged.
func TestWriteMintTokenError_LogsNothingForAnInvalidInitialTag(t *testing.T) {
	var buf strings.Builder
	d := Deps{Logger: slog.New(slog.NewTextHandler(&buf, nil))}
	err := fmt.Errorf("%w: %w", capability.ErrEnrollmentInitialTags,
		&registry.InitialTagError{Entry: "tag:SECRETISH", Err: registry.ErrInitialTagMalformed})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enrollment-tokens", strings.NewReader(`{}`))
	writeMintTokenError(rec, req, d, err)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	if buf.Len() != 0 {
		t.Errorf("log = %q, want nothing", buf.String())
	}
}
