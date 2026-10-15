package logctx

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func jsonLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(NewHandler(slog.NewJSONHandler(buf, nil)))
}

func decode(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("log line is not JSON: %v: %q", err, buf.String())
	}
	return m
}

func TestHandler_AddsContextValues(t *testing.T) {
	var buf bytes.Buffer
	ctx := WithRequestID(WithJobID(WithPrincipal(context.Background(), "alice"), "job-1"), "abc123")
	jsonLogger(&buf).InfoContext(ctx, "m", "k", "v")
	m := decode(t, &buf)
	for key, want := range map[string]string{KeyPrincipal: "alice", KeyJobID: "job-1", KeyRequestID: "abc123", "k": "v"} {
		if m[key] != want {
			t.Errorf("%s = %v, want %q (line %v)", key, m[key], want, m)
		}
	}
}

func TestHandler_AddsNothingWhenAbsent(t *testing.T) {
	var buf bytes.Buffer
	ctx := WithJobID(WithPrincipal(context.Background(), ""), "")
	jsonLogger(&buf).InfoContext(ctx, "m")
	m := decode(t, &buf)
	for _, key := range []string{KeyPrincipal, KeyJobID, KeyRequestID} {
		if _, ok := m[key]; ok {
			t.Errorf("%s present with no value in the context: %v", key, m)
		}
	}
}

func TestHandler_DoesNotDuplicateExplicitKeys(t *testing.T) {
	ctx := WithJobID(context.Background(), "from-ctx")

	t.Run("on the record", func(t *testing.T) {
		var buf bytes.Buffer
		jsonLogger(&buf).InfoContext(ctx, "m", "job_id", "explicit")
		if n := strings.Count(buf.String(), `"job_id"`); n != 1 || decode(t, &buf)["job_id"] != "explicit" {
			t.Errorf("job_id duplicated or overridden: %s", buf.String())
		}
	})
	t.Run("via With", func(t *testing.T) {
		var buf bytes.Buffer
		jsonLogger(&buf).With("job_id", "preset").InfoContext(ctx, "m")
		if n := strings.Count(buf.String(), `"job_id"`); n != 1 || decode(t, &buf)["job_id"] != "preset" {
			t.Errorf("job_id duplicated or overridden: %s", buf.String())
		}
	})
}

func TestHandler_WithGroup_ContextAttrsNestInGroup(t *testing.T) {
	var buf bytes.Buffer
	jsonLogger(&buf).WithGroup("g").InfoContext(WithJobID(context.Background(), "job-9"), "m", "k", "v")
	m := decode(t, &buf)
	g, ok := m["g"].(map[string]any)
	if !ok || g["k"] != "v" || g[KeyJobID] != "job-9" {
		t.Errorf("want {g:{k:v, job_id:job-9}}, got %v", m)
	}
	if _, top := m[KeyJobID]; top {
		t.Errorf("job_id must not be hoisted to the top level: %v", m)
	}
}

func TestHandler_WithGroup_TopLevelPresetSuppresses(t *testing.T) {
	var buf bytes.Buffer
	jsonLogger(&buf).With("job_id", "x").WithGroup("g").InfoContext(WithJobID(context.Background(), "job-9"), "m", "k", "v")
	m := decode(t, &buf)
	if m[KeyJobID] != "x" {
		t.Errorf("top-level job_id = %v, want x", m[KeyJobID])
	}
	if g, _ := m["g"].(map[string]any); g != nil {
		if _, dup := g[KeyJobID]; dup {
			t.Errorf("job_id duplicated inside the group: %v", m)
		}
	}
}

func TestHandler_WithGroupEmptyNameIsNoop(t *testing.T) {
	h := NewHandler(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	if got := h.WithGroup(""); got != slog.Handler(h) {
		t.Error("WithGroup(\"\") must return the same handler")
	}
}

func TestHandler_EnabledDelegates(t *testing.T) {
	h := NewHandler(slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	if h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("Info must be disabled by the wrapped handler's level")
	}
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Error("Error must be enabled")
	}
}

func TestNewHandler_NilPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewHandler(nil) must panic")
		}
	}()
	NewHandler(nil)
}

func TestAttrs(t *testing.T) {
	if got := Attrs(context.Background()); len(got) != 0 {
		t.Errorf("Attrs on an empty context = %v", got)
	}
	got := Attrs(WithJobID(context.Background(), "j"))
	if len(got) != 2 || got[0] != KeyJobID || got[1] != "j" {
		t.Errorf("Attrs = %v", got)
	}
}

func TestOr_NilFollowsLaterSetDefault(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	explicit := slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil))
	if Or(explicit) != explicit {
		t.Error("Or must return a non-nil logger unchanged")
	}

	var buf bytes.Buffer
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	Or(nil).Info("after set default")
	if !strings.Contains(buf.String(), "after set default") {
		t.Errorf("Or(nil) did not follow slog.SetDefault: %q", buf.String())
	}
}
