package main

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/consoleauth"
	"github.com/Felag-Engineering/relay/relay/internal/metrics"
)

type recordingAuditor struct {
	kinds []string
	err   error
}

func (a *recordingAuditor) RecordLogin(_ context.Context, e consoleauth.LoginEvent) error {
	a.kinds = append(a.kinds, e.Kind)
	return a.err
}

func scrapeText(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	rec := httptest.NewRecorder()
	m.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	return rec.Body.String()
}

func TestLoginAuditCounter_CountsEachFailureKind(t *testing.T) {
	failures := map[string]string{
		audit.KindLoginFailed:     "sign_in_failed",
		audit.KindLoginThrottled:  "sign_in_throttled",
		audit.KindStepUpFailed:    "step_up_failed",
		audit.KindStepUpThrottled: "step_up_throttled",
	}
	m := metrics.New(metrics.GaugeSources{})
	next := &recordingAuditor{}
	c := loginAuditCounter{next: next, metrics: m}

	for kind := range failures {
		if err := c.RecordLogin(context.Background(), consoleauth.LoginEvent{Kind: kind}); err != nil {
			t.Fatalf("RecordLogin(%s): %v", kind, err)
		}
	}
	for _, kind := range []string{audit.KindLoginSucceeded, audit.KindStepUp, audit.KindLogout} {
		_ = c.RecordLogin(context.Background(), consoleauth.LoginEvent{Kind: kind})
	}

	body := scrapeText(t, m)
	for _, reason := range failures {
		want := `relay_auth_failures_total{surface="console",reason="` + reason + `"} 1` + "\n"
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q; body = %s", want, body)
		}
	}
	// Exactly the four failures moved; success, step-up and logout raised nothing.
	moved := 0
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "relay_auth_failures_total{") && !strings.HasSuffix(line, " 0") {
			moved++
		}
	}
	if moved != len(failures) {
		t.Errorf("%d auth series moved, want %d", moved, len(failures))
	}
	if len(next.kinds) != 7 {
		t.Errorf("next saw %d events, want all 7", len(next.kinds))
	}
}

func TestLoginAuditCounter_PropagatesTheAuditError(t *testing.T) {
	boom := errors.New("audit store unavailable")
	m := metrics.New(metrics.GaugeSources{})
	c := loginAuditCounter{next: &recordingAuditor{err: boom}, metrics: m}

	err := c.RecordLogin(context.Background(), consoleauth.LoginEvent{Kind: audit.KindLoginFailed})
	if !errors.Is(err, boom) {
		t.Fatalf("RecordLogin = %v, want the audit error unchanged", err)
	}
	want := `relay_auth_failures_total{surface="console",reason="sign_in_failed"} 1`
	if body := scrapeText(t, m); !strings.Contains(body, want) {
		t.Errorf("the failure was not counted; body = %s", body)
	}
}
