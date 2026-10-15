package console

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/jobs"
	"github.com/Felag-Engineering/relay/relay/internal/opvocab"
)

// vocab_contract_test.go is the cross-toolchain half of issue #461: vocab.go's
// shippedReadCatalog is a hand-kept Go mirror of
// daemon/packaging/templates.d/relay-read/catalog.toml, and nothing in the Go
// BUILD touches that file — it is a Node-side package artifact, not present
// on a Relay host, and vocab.go deliberately does not read it at runtime (see
// that file's doc comment for why: no precedent for the Relay reading daemon
// packaging, and //go:embed cannot reach outside this package's own
// directory). The only thing standing between the mirror and a silent drift
// like the one that shipped file.stat and pkg.query, two names in neither
// /proto nor daemon/, is a TEST that reads the packaged file directly — the
// same shape as registry/daemon_version_contract_test.go reading
// daemon/Cargo.toml.
//
// These tests are hermetic: they read one committed file and run no binary.

// repoRoot is this package's directory walked back up to the repository root
// (relay/internal/controlplane/console -> relay/internal/controlplane ->
// relay/internal -> relay -> .).
const repoRoot = "../../../.."

const packagedReadCatalogPath = "daemon/packaging/templates.d/relay-read/catalog.toml"

// parsedTemplate is one [[template]] table's name and declared risk_class, as
// catalog.toml states it.
type parsedTemplate struct {
	name      string
	riskClass string
}

// parsePackagedReadCatalog hand-parses catalog.toml well enough to recover
// each top-level template's name and risk_class. No TOML dependency lives in
// relay/go.mod, and none should be added for a single test — the registry
// precedent hand-parses Cargo.toml the same way.
//
// The one subtlety that makes a naive line scan wrong: a [[template.slots]]
// table ALSO carries a `name` key (the slot's own name, e.g. "unit" or
// "path"), so the parser tracks which table is currently open and captures
// name/risk_class only while inside a [[template]] table, never inside a
// [[template.slots]] one. Getting this wrong would silently admit slot names
// like "unit" as if they were Operation names.
func parsePackagedReadCatalog(t *testing.T) []parsedTemplate {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, packagedReadCatalogPath))
	if err != nil {
		t.Fatalf("read %s: %v", packagedReadCatalogPath, err)
	}

	var templates []parsedTemplate
	inTemplate := false
	for _, line := range strings.Split(string(raw), "\n") {
		field := strings.TrimSpace(line)
		switch {
		case field == "[[template]]":
			inTemplate = true
			templates = append(templates, parsedTemplate{})
		case field == "[[template.slots]]":
			inTemplate = false
		case strings.HasPrefix(field, "["):
			// Any other table header (there are none today, but a future one
			// must not be misread as still being inside [[template]]).
			inTemplate = false
		case !inTemplate:
			// Comments, blank lines, slot fields, and body strings that
			// happen to contain the word "name" all land here and are
			// ignored — they are not inside a [[template]] table.
		case strings.HasPrefix(field, "name"):
			templates[len(templates)-1].name = tomlStringValue(field)
		case strings.HasPrefix(field, "risk_class"):
			templates[len(templates)-1].riskClass = tomlStringValue(field)
		}
	}
	return templates
}

// tomlStringValue extracts the quoted right-hand side of a `key = "value"`
// line.
func tomlStringValue(line string) string {
	_, rhs, ok := strings.Cut(line, "=")
	if !ok {
		return ""
	}
	return strings.Trim(strings.TrimSpace(rhs), `"`)
}

// TestVocab_ShippedReadCatalogMatchesThePackagedCatalog is the anti-drift
// guard proper: it binds vocab.go's shippedReadCatalog to the packaged
// catalog.toml BIDIRECTIONALLY, so either side changing without the other
// fails this test rather than drifting silently the way the phantom
// file.stat/pkg.query names did.
//
// A test that only checked "today's seven names are all read-class" would
// pass forever after someone later added an eighth template to the pack and
// forgot the Console. Checking the reverse direction too — every name in
// shippedReadCatalog was actually parsed out of the file as read-class — is
// what catches a phantom name the way #461 found two of.
func TestVocab_ShippedReadCatalogMatchesThePackagedCatalog(t *testing.T) {
	templates := parsePackagedReadCatalog(t)

	// A guard that silently checks nothing is worse than no guard (see
	// TestConsole_NoDispatchOutsideCapabilityLayer): fail loudly if the
	// parser found nothing, or lost a name every reader of this file expects
	// to be there, rather than pass by accident against a reformatted or
	// emptied file.
	if len(templates) == 0 {
		t.Fatal("parsed zero templates from the packaged read catalog — the parser or the file moved")
	}
	foundAnchor := false
	for _, tpl := range templates {
		if tpl.name == "log.tail" && tpl.riskClass == "read" {
			foundAnchor = true
		}
	}
	if !foundAnchor {
		t.Fatal("did not parse log.tail as a read-class template — the anchor this vacuity guard " +
			"relies on is missing, which means the catalog's format changed under the parser")
	}

	for _, tpl := range templates {
		if tpl.riskClass != "read" {
			// VACUOUS TODAY, kept as future-proofing: catalog.toml lives under
			// templates.d/relay-read/ and, as of this writing, ships only
			// read-class templates, so no fixture in the real file currently
			// exercises this branch. This assertion is exercised only on the
			// day a non-read template lands in this pack; until then it is
			// asserted but not actually run against a failing case.
			if isReadOperation(tpl.name) {
				t.Errorf("packaged template %q is not read-class (risk_class=%q) but isReadOperation "+
					"reports it as read", tpl.name, tpl.riskClass)
			}
			continue
		}
		if !isReadOperation(tpl.name) {
			t.Errorf("packaged read-class template %q is missing from the Console's read vocabulary "+
				"— add it to vocab.go's shippedReadCatalog", tpl.name)
		}
	}

	for name := range shippedReadCatalog {
		found := false
		for _, tpl := range templates {
			if tpl.name == name && tpl.riskClass == "read" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("shippedReadCatalog names %q, which the packaged catalog does not ship as a "+
				"read-class template — this is exactly the file.stat/pkg.query phantom-name defect #461 found",
				name)
		}
	}
}

// TestVocab_NativeReadsFollowOpvocab pins the native half of readOperations as
// a DERIVATION rather than a second list: for every Operation opvocab knows,
// isReadOperation must agree with the declared Risk exactly, in both
// directions.
func TestVocab_NativeReadsFollowOpvocab(t *testing.T) {
	for _, d := range opvocab.Operations() {
		want := d.Risk == jobs.RiskClassRead
		if got := isReadOperation(d.Name); got != want {
			t.Errorf("isReadOperation(%q) = %v, want %v (opvocab declares %s)", d.Name, got, want, jobs.RiskClassName(d.Risk))
		}
	}
}

// TestVocab_NativeAndShippedCatalogsAreDisjoint guards against a name
// migrating between the native vocabulary and the shipped template pack
// without anyone noticing. Both halves are unioned into readOperations, so a
// name in both would still read correctly today — but silently double-listing
// it would hide the day one of the two facts about it (its native Risk, or
// its presence in the pack) changed and the other was never updated to match.
func TestVocab_NativeAndShippedCatalogsAreDisjoint(t *testing.T) {
	for _, d := range opvocab.Operations() {
		if shippedReadCatalog[d.Name] {
			t.Errorf("%q is in both opvocab's native vocabulary and shippedReadCatalog — "+
				"a name should live in exactly one", d.Name)
		}
	}
}
