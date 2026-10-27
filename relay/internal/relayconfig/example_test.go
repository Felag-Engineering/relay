package relayconfig

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/Felag-Engineering/relay/relay/internal/approvalnotify"
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
			if _, ok := idx.lines[key]; !ok {
				t.Errorf("%s is a schema key missing from relay.toml.example", key)
			}
		}
	})

	t.Run("each commented value is the built-in default", func(t *testing.T) {
		// Keys whose default stands alone. The two that need a companion key
		// (oauth.account_claim, approval.webhook_timeout) are checked from the
		// decoded document below.
		defaulted := map[string]bool{
			"control_plane.enabled": true, "control_plane.listen_address": true,
			"console.enabled": true, "console.session_max_age": true, "console.session_idle": true, "console.step_up_window": true,
			"log.level": true, "log.format": true,
			"reach.read_blast_cap": true, "reach.mutate_blast_cap": true, "reach.dispatch_concurrency": true,
			"enrollment.ip_rate_per_minute": true, "enrollment.ip_burst": true, "enrollment.global_rate_per_minute": true,
			"enrollment.global_burst": true, "enrollment.max_tracked_ips": true, "enrollment.max_nodes": true,
			"enrollment.cert_expiring_fraction": true,
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
		if d, err := time.ParseDuration(*doc.Approval.WebhookTimeout); err != nil || d != approvalnotify.DefaultTimeout {
			t.Errorf("approval.webhook_timeout example = %q", *doc.Approval.WebhookTimeout)
		}
	})
}
