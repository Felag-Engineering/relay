package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

// errors_test.go covers decodeJSON's media-type requirement (#459).
//
// # What the requirement is for
//
// text/plain, application/x-www-form-urlencoded and multipart/form-data are
// the three media types an HTML form can POST cross-origin with NO CORS
// preflight — the browser sends the request (and whatever ambient credential
// it holds for the target) and merely hides the response. decodeJSON used to
// accept a body regardless of what it was declared as, so a form POST reached
// a mutating handler.
//
// DisallowUnknownFields raised the bar and did not close it: a form body is
// `name=value`, the name has to be a real field, and for raw-exec the `=`
// simply parks inside an argv element — `{"argv":["sh","-c","curl ...=..."]}`
// is a perfectly good arbitrary command. Requiring the declared media type
// closes the SHAPE rather than one credential's use of it.

// A form-shaped body must not reach a mutating handler, whatever it is
// declared as, and must not dispatch.
func TestDecodeJSON_AFormPostNeverReachesAMutatingHandler(t *testing.T) {
	// The body is valid JSON *and* a valid form field name — the case
	// DisallowUnknownFields does not catch.
	const formBody = `{"selector":"node:env=prod","argv":["/bin/sh","-c","id"]}=`

	for _, contentType := range []string{
		"text/plain",
		"text/plain;charset=UTF-8",
		"application/x-www-form-urlencoded",
		"multipart/form-data; boundary=x",
		"", // no declaration at all
	} {
		t.Run(contentType, func(t *testing.T) {
			exec := &fakeExecutor{}
			h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{})

			req := httptest.NewRequest(http.MethodPost, "/api/v1/raw-exec", strings.NewReader(formBody))
			req.Header.Set("Authorization", "Bearer "+testCredential)
			if contentType != "" {
				req.Header.Set("Content-Type", contentType)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want %d; body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
			// The refusal must be the MEDIA TYPE's, not a downstream
			// validation error that happens to share the status: the
			// selector and argv in this body are both valid.
			if !strings.Contains(rec.Body.String(), "Content-Type") {
				t.Errorf("body = %s, want the refusal to name Content-Type", rec.Body.String())
			}
			if got := len(exec.runCalls()); got != 0 {
				t.Errorf("the request dispatched %d time(s) — a body this surface never agreed to read reached the capability layer", got)
			}
		})
	}
}

// The declared media type is still accepted, with or without parameters and
// whatever it is cased as — a client sending real JSON is not broken by this.
func TestDecodeJSON_AcceptsApplicationJSON(t *testing.T) {
	for _, contentType := range []string{
		"application/json",
		"application/json; charset=utf-8",
		"Application/JSON",
		" application/json ",
	} {
		t.Run(contentType, func(t *testing.T) {
			exec := &fakeExecutor{}
			h := newExecFixture(t, accounts.RoleAdmin, exec, fakeJobs{})

			req := httptest.NewRequest(http.MethodPost, "/api/v1/raw-exec",
				strings.NewReader(`{"selector":"node:env=prod","argv":["/bin/echo","hi"]}`))
			req.Header.Set("Authorization", "Bearer "+testCredential)
			req.Header.Set("Content-Type", contentType)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code == http.StatusBadRequest {
				t.Fatalf("a JSON body declared %q was refused: %s", contentType, rec.Body.String())
			}
			if got := len(exec.runCalls()); got != 1 {
				t.Errorf("dispatched %d time(s), want 1", got)
			}
		})
	}
}

// mediaType is the header reduction the check is built on: type/subtype,
// lower-cased, parameters dropped.
func TestMediaType(t *testing.T) {
	cases := map[string]string{
		"application/json":                 "application/json",
		"application/json; charset=utf-8":  "application/json",
		"APPLICATION/JSON":                 "application/json",
		"  application/json  ":             "application/json",
		"text/plain;charset=UTF-8":         "text/plain",
		"":                                 "",
		"application/json-patch+json":      "application/json-patch+json",
		"multipart/form-data; boundary=xy": "multipart/form-data",
	}
	for header, want := range cases {
		if got := mediaType(header); got != want {
			t.Errorf("mediaType(%q) = %q, want %q", header, got, want)
		}
	}
}

func TestReadJSONBody_WritesProblemOnBadBody(t *testing.T) {
	var dst struct{ Name string }
	for name, tc := range map[string]struct {
		contentType string
		body        string
		wantOK      bool
	}{
		"valid":       {"application/json", `{"Name":"a"}`, true},
		"wrong type":  {"text/plain", `{"Name":"a"}`, false},
		"unknown key": {"application/json", `{"Other":1}`, false},
		"malformed":   {"application/json", `{`, false},
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.contentType)
			if got := readJSONBody(rec, req, &dst); got != tc.wantOK {
				t.Fatalf("readJSONBody = %v, want %v", got, tc.wantOK)
			}
			if wrote := rec.Body.Len() > 0; wrote == tc.wantOK {
				t.Errorf("response written = %v, want %v", wrote, !tc.wantOK)
			}
			if !tc.wantOK && rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
		})
	}
}

func TestReasonTooLong(t *testing.T) {
	rec := httptest.NewRecorder()
	if reasonTooLong(rec, strings.Repeat("a", maxDecisionReasonLen)) || rec.Body.Len() != 0 {
		t.Fatal("a reason at the limit must pass without a response")
	}
	if !reasonTooLong(rec, strings.Repeat("a", maxDecisionReasonLen+1)) {
		t.Fatal("a reason over the limit must be refused")
	}
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "at most 1024 bytes") {
		t.Errorf("got %d %q", rec.Code, rec.Body.String())
	}
}
