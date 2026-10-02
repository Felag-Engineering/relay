package console

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/gleipnir-relay/relay/internal/accounts"
)

// TestConsole_AccentPairsClearAA holds the interactive accent to WCAG AA in
// both themes (#831).
//
// The issue found three failures in the terracotta accent it replaced: white
// on the dark primary button at 2.63:1, white on the light primary button at
// 3.78:1, and light link text on --bg-surface at 3.56:1. The accent is now the
// Relay brand teal (owner decision, 2026-10-01), split by role because one
// value cannot clear every pairing: the brand teal fills and rings, a darker
// step carries light-theme text, and --on-accent is the text drawn on a fill.
func TestConsole_AccentPairsClearAA(t *testing.T) {
	css := get(t, newTestHandler(renderableDeps(), accounts.RoleAdmin),
		"/console/assets/console.css").Body.String()

	dark, light := splitThemes(t, css)

	bgs := []string{"--bg-canvas", "--bg-surface", "--bg-elevated", "--bg-sidebar", "--bg-code", "--bg-subtle"}

	for _, theme := range []struct {
		name   string
		tokens map[string]string
	}{{"dark", dark}, {"light", light}} {
		check := func(fgName, bgName string, floor float64, what string) {
			t.Helper()
			fg := mustResolve(t, theme.name, theme.tokens, fgName)
			bg := mustResolve(t, theme.name, theme.tokens, bgName)
			if r := contrastRatio(fg, bg); r < floor {
				t.Errorf("%s: %s on %s is %.2f:1, below the %.1f:1 floor (%s)",
					theme.name, fgName, bgName, r, floor, what)
			}
		}

		for _, fg := range []string{"--accent-text", "--accent-hover"} {
			for _, bg := range bgs {
				check(fg, bg, 4.5, "accent as text")
			}
		}
		for _, fill := range []string{"--color-accent", "--accent-hover"} {
			check("--on-accent", fill, 4.5, "text on an accent fill")
		}
		for _, bg := range bgs {
			check("--color-accent", bg, 3.0, "WCAG 1.4.11 non-text: focus rings, borders, the nav bar, the live dot")
		}
	}
}

func mustResolve(t *testing.T, themeName string, tokens map[string]string, name string) string {
	t.Helper()
	v, ok := resolveToken(tokens, name)
	if !ok {
		t.Fatalf("%s theme declares no resolvable %s", themeName, name)
	}
	return v
}

// bareColor matches a `color:` property and not border-color: or
// background-color: (the character before it must not be part of a name).
// Group 1 is the value.
var bareColor = regexp.MustCompile(`(?:^|[;{\s])color:\s*([^;}]*)`)

// whiteText matches a bare `color:` whose value is white, with a word
// boundary so a longer hex such as #fff8e0 is not a false positive.
var whiteText = regexp.MustCompile(`(?i)(?:^|[;{\s])color:\s*(?:#fff\b|#ffffff\b|white\b)`)

// textFreeAccentFills are the accent fills that draw no text, and why. Every
// other accent fill must carry --on-accent.
var textFreeAccentFills = map[string]string{
	".pulse": "the 9px live dot draws no text",
}

// TestConsole_AccentIsUsedByRole keeps the role split from eroding: the
// contrast test measures tokens, this one checks the stylesheet spends each
// token on the role it was measured for.
func TestConsole_AccentIsUsedByRole(t *testing.T) {
	raw, err := assetsFS.ReadFile("assets/console.css")
	if err != nil {
		t.Fatalf("read console.css: %v", err)
	}
	css := cssCommentPattern.ReplaceAllString(string(raw), "")

	if strings.Contains(css, "--color-blue") {
		t.Error("console.css still uses --color-blue; the interactive accent is --color-accent")
	}

	for _, m := range bareColor.FindAllStringSubmatch(css, -1) {
		if strings.TrimSpace(m[1]) == "var(--color-accent)" {
			t.Error("a declaration colours text with --color-accent; text goes through --accent-text, " +
				"because the light accent fails AA as text")
		}
	}

	if whiteText.MatchString(css) {
		t.Error("a declaration colours text white; text on an accent fill goes through --on-accent, " +
			"because white fails on the dark accent fill")
	}

	seen := map[string]bool{}
	for _, m := range cssRulePattern.FindAllStringSubmatch(css, -1) {
		selector, decls := strings.TrimSpace(m[1]), m[2]

		if strings.Contains(decls, "background: var(--color-accent)") {
			if _, free := textFreeAccentFills[selector]; free {
				seen[selector] = true
				if bareColor.MatchString(decls) {
					t.Errorf("%s is exempt as a text-free accent fill but sets color:", selector)
				}
			} else if !declaresColor(decls, "var(--on-accent)") {
				t.Errorf("%s fills with --color-accent but does not declare color: var(--on-accent); "+
					"declare it, or, if the fill truly draws no text, add the selector to "+
					"textFreeAccentFills with a one-line reason", selector)
			}
		}

		if strings.Contains(decls, "background: var(--accent-hover)") {
			for _, c := range bareColor.FindAllStringSubmatch(decls, -1) {
				if strings.TrimSpace(c[1]) != "var(--on-accent)" {
					t.Errorf("%s fills with --accent-hover but sets color: %s; "+
						"text on a hover fill is --on-accent", selector, strings.TrimSpace(c[1]))
				}
			}
		}
	}
	for selector, reason := range textFreeAccentFills {
		if !seen[selector] {
			t.Errorf("textFreeAccentFills lists %s (%s) but no such accent fill exists; remove the entry",
				selector, reason)
		}
	}

	if strings.Contains(css, "var(--accent-muted)") {
		t.Error("--accent-muted is in use, but no tinted pair is measured; " +
			"add the pair to TestConsole_AccentPairsClearAA before using it")
	}
}

// declaresColor reports whether decls sets the bare color: property to value.
func declaresColor(decls, value string) bool {
	for _, m := range bareColor.FindAllStringSubmatch(decls, -1) {
		if strings.TrimSpace(m[1]) == value {
			return true
		}
	}
	return false
}
