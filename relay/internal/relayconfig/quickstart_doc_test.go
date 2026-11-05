package relayconfig

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The quickstart is the install path RC-45 names, so its two facts are held
// here as well as in scripts/check-docs.sh: spec-proof reads only Go and Rust
// tests. The checks stay loose on wording, as the shell check does.
var (
	installCommand  = regexp.MustCompile(`^\s*(\$ )?(sudo )?(apt-get|apt|dnf)\s+install\b`)
	relayPackageArg = regexp.MustCompile(`(^|[\s/])relay([_-]|\s|$)`)
	daemonPackage   = regexp.MustCompile(`relay-daemon\S*`)
	containerTerm   = regexp.MustCompile(`docker compose|docker-compose|container image|compose stack`)
	negation        = regexp.MustCompile(`(^|[^a-z])(not|no|never|unsupported|deprecated)([^a-z]|$)|n[^a-z ]{1,3}t([^a-z]|$)`)
	sentenceEnd     = regexp.MustCompile(`\.\s+`)
	whitespaceRun   = regexp.MustCompile(`\s+`)
)

func readRepoDoc(t *testing.T, parts ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(append([]string{packageDir(t), "..", "..", ".."}, parts...)...))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(parts...), err)
	}
	return string(raw)
}

// installsRelayPackage reports whether doc has an apt or dnf install command,
// backslash continuations joined and comments dropped, that names the relay
// package rather than only relay-daemon.
func installsRelayPackage(doc string) bool {
	var joined []string
	var buf strings.Builder
	for _, line := range strings.Split(doc, "\n") {
		trimmed := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmed, `\`) {
			buf.WriteString(strings.TrimSuffix(trimmed, `\`) + " ")
			continue
		}
		buf.WriteString(line)
		joined = append(joined, buf.String())
		buf.Reset()
	}
	for _, line := range joined {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		if i := strings.Index(line, " #"); i >= 0 {
			line = line[:i]
		}
		if !installCommand.MatchString(line) {
			continue
		}
		if relayPackageArg.MatchString(daemonPackage.ReplaceAllString(line, "")) {
			return true
		}
	}
	return false
}

// documentsContainerAsSupported reports whether a sentence of doc calls the
// container install supported, with no negation in that sentence.
func documentsContainerAsSupported(doc string) bool {
	for _, para := range strings.Split(doc, "\n\n") {
		p := whitespaceRun.ReplaceAllString(strings.ToLower(para), " ")
		for _, s := range sentenceEnd.Split(p, -1) {
			if containerTerm.MatchString(s) && strings.Contains(s, "supported") && !negation.MatchString(s) {
				return true
			}
		}
	}
	return false
}

// Proves RC-45.
func TestQuickstart_InstallsTheRelayFromItsOSPackageAndKeepsTheContainerSupported(t *testing.T) {
	quickstart := readRepoDoc(t, "docs", "quickstart.md")
	if !installsRelayPackage(quickstart) {
		t.Error("docs/quickstart.md installs the Relay from no OS package (apt-get, apt or dnf on the relay package)")
	}
	install := readRepoDoc(t, "docs", "operations", "relay-install.md")
	if !documentsContainerAsSupported(quickstart + "\n\n" + install) {
		t.Error("neither docs/quickstart.md nor docs/operations/relay-install.md documents the container install as supported")
	}
}

// The matchers refuse the shapes that would let the doc drift past them.
func TestQuickstartMatchers_RefuseLookalikes(t *testing.T) {
	for _, tc := range []struct {
		doc  string
		want bool
	}{
		{"$ sudo apt-get install ./relay_0.2.0_amd64.deb", true},
		{"sudo dnf install \\\n  ./relay-0.2.0-1.x86_64.rpm", true},
		{"sudo apt-get install ./relay-daemon_0.2.0_amd64.deb", false},
		{"# sudo apt-get install ./relay_0.2.0_amd64.deb", false},
		{"Do not run apt-get install relay here.", false},
	} {
		if got := installsRelayPackage(tc.doc); got != tc.want {
			t.Errorf("installsRelayPackage(%q) = %v, want %v", tc.doc, got, tc.want)
		}
	}
	for _, tc := range []struct {
		doc  string
		want bool
	}{
		{"The Docker Compose stack stays a supported install.", true},
		{"The container image is not a supported install.", false},
		{"Docker Compose isn't supported.", false},
		{"The OS package is supported.", false},
	} {
		if got := documentsContainerAsSupported(tc.doc); got != tc.want {
			t.Errorf("documentsContainerAsSupported(%q) = %v, want %v", tc.doc, got, tc.want)
		}
	}
}
