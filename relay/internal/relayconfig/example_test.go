package relayconfig

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

var (
	commentedKey = regexp.MustCompile(`^#\s?([a-z][a-z0-9_]*\s*=\s.*)$`)
	sectionLine  = regexp.MustCompile(`^\[([a-z_]+)\]\s*$`)
)

func readExample(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(packageDir(t), "..", "..", "packaging", "relay.toml.example"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// uncomment activates every commented-out key for which keep("section.key")
// is true.
func uncomment(src string, keep func(key string) bool) string {
	var section string
	lines := strings.Split(src, "\n")
	for i, line := range lines {
		if m := sectionLine.FindStringSubmatch(line); m != nil {
			section = m[1]
			continue
		}
		if m := commentedKey.FindStringSubmatch(line); m != nil {
			key := section + "." + strings.TrimSpace(strings.SplitN(m[1], "=", 2)[0])
			if keep(key) {
				lines[i] = m[1]
			}
		}
	}
	return strings.Join(lines, "\n")
}

func TestExampleRelayTOML_MatchesConfig(t *testing.T) {
	example := readExample(t)

	t.Run("the shipped file loads with no warnings", func(t *testing.T) {
		_, warns, err := Load([]byte(example))
		if err != nil || len(warns) != 0 {
			t.Fatalf("warnings %v, error %v", warns, err)
		}
	})

	all := uncomment(example, func(string) bool { return true })

	t.Run("every key in the example is a schema key of the right type", func(t *testing.T) {
		var doc document
		if err := toml.NewDecoder(strings.NewReader(all)).DisallowUnknownFields().Decode(&doc); err != nil {
			t.Fatalf("the example does not decode strictly: %v", err)
		}
	})

	t.Run("every schema key is in the example", func(t *testing.T) {
		idx := keyLines([]byte(all))
		for _, key := range schemaKeys() {
			// The example carries no gate rule of its own: the packaged rules
			// are a separate decision, so it only describes the section.
			if key == "approval.rules" {
				continue
			}
			if _, ok := idx.lines[key]; !ok {
				t.Errorf("%s is a schema key missing from relay.toml.example", key)
			}
		}
	})

	t.Run("each commented value is the built-in default", func(t *testing.T) {
		// Keys whose default stands alone. The one that needs a companion key
		// (oauth.account_claim) is checked from the decoded document below.
		defaulted := map[string]bool{
			"control_plane.enabled": true, "control_plane.listen_address": true,
			"console.enabled": true, "console.session_idle": true,
			"log.level":            true,
			"reach.read_blast_cap": true, "reach.mutate_blast_cap": true,
			"enrollment.max_nodes": true,
		}
		shipped, _, err := Load([]byte(example))
		if err != nil {
			t.Fatal(err)
		}
		got, _, err := Load([]byte(uncomment(example, func(k string) bool { return defaulted[k] })))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(shipped, got) {
			t.Fatalf("a commented default differs from the built-in:\nbuilt-in %+v\nexample  %+v", shipped, got)
		}

		var doc document
		if err := toml.Unmarshal([]byte(all), &doc); err != nil {
			t.Fatal(err)
		}
		if *doc.OAuth.AccountClaim != defaultAccountClaim {
			t.Errorf("oauth.account_claim example = %q", *doc.OAuth.AccountClaim)
		}
	})
}
