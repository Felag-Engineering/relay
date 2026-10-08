package main

import (
	"testing"
	"time"
)

func TestIntEnvOr(t *testing.T) {
	cases := []struct {
		name, env string
		want      int
	}{
		{"unset keeps fallback", "", 7},
		{"valid", "42", 42},
		{"zero is accepted", "0", 0},
		{"negative is accepted", "-3", -3},
		{"unparseable keeps fallback", "forty", 7},
		{"float keeps fallback", "1.5", 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RELAY_TEST_INT", tc.env)
			if got := intEnvOr("RELAY_TEST_INT", 7); got != tc.want {
				t.Errorf("intEnvOr(%q) = %d, want %d", tc.env, got, tc.want)
			}
		})
	}
}

func TestBoolEnvOr(t *testing.T) {
	cases := []struct {
		name, env string
		fallback  bool
		want      bool
	}{
		{"unset keeps true fallback", "", true, true},
		{"unset keeps false fallback", "", false, false},
		{"true", "true", false, true},
		{"1", "1", false, true},
		{"false overrides true fallback", "false", true, false},
		{"unparseable keeps fallback", "yes", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RELAY_TEST_BOOL", tc.env)
			if got := boolEnvOr("RELAY_TEST_BOOL", tc.fallback); got != tc.want {
				t.Errorf("boolEnvOr(%q, %v) = %v, want %v", tc.env, tc.fallback, got, tc.want)
			}
		})
	}
}

func TestDurationEnvOr(t *testing.T) {
	const fallback = 5 * time.Minute
	cases := []struct {
		name, env string
		want      time.Duration
	}{
		{"unset keeps fallback", "", fallback},
		{"valid", "90s", 90 * time.Second},
		{"zero is refused", "0s", fallback},
		{"negative is refused", "-1m", fallback},
		{"unparseable keeps fallback", "soon", fallback},
		{"bare number keeps fallback", "30", fallback},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RELAY_TEST_DUR", tc.env)
			if got := durationEnvOr("RELAY_TEST_DUR", fallback); got != tc.want {
				t.Errorf("durationEnvOr(%q) = %v, want %v", tc.env, got, tc.want)
			}
		})
	}
}
