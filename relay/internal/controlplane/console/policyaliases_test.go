package console

// policyaliases_test.go proves the Console's Policy alias display and write
// seam: an alias is drawn beside the full fingerprint it names, an unaliased
// fingerprint takes a neutral letter, the Edit alias control is offered to a
// human admin only, and the write is decided by the capability layer and never
// here.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/auditsink"
	"github.com/Felag-Engineering/relay/relay/internal/authz"
	"github.com/Felag-Engineering/relay/relay/internal/capability"
	"github.com/Felag-Engineering/relay/relay/internal/controlplane"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

// aliasSetCall and aliasClearCall are what fakeAliasWriter recorded: exactly
// what the handler passed, principal included.
type aliasSetCall struct {
	Principal   capability.Principal
	Fingerprint string
	Name        string
}

type aliasClearCall struct {
	Principal   capability.Principal
	Fingerprint string
}

// fakeAliasWriter records every call and decides nothing: the floor, the name
// rules and the audit record are the capability layer's, and a fake that
// refused a name would assert against its own implementation.
type fakeAliasWriter struct {
	mu     sync.Mutex
	sets   []aliasSetCall
	clears []aliasClearCall

	setErr   error
	clearErr error
}

func (f *fakeAliasWriter) SetPolicyAlias(_ context.Context, p capability.Principal, fingerprint, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets = append(f.sets, aliasSetCall{p, fingerprint, name})
	return f.setErr
}

func (f *fakeAliasWriter) ClearPolicyAlias(_ context.Context, p capability.Principal, fingerprint string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clears = append(f.clears, aliasClearCall{p, fingerprint})
	return f.clearErr
}

func (f *fakeAliasWriter) calls() (sets []aliasSetCall, clears []aliasClearCall) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]aliasSetCall(nil), f.sets...), append([]aliasClearCall(nil), f.clears...)
}

// mapAliasSource is a capability.PolicyAliasSource over a map.
type mapAliasSource map[string]string

func (m mapAliasSource) List(context.Context) (map[string]string, error) { return m, nil }

// kindVerifier is roleVerifier with a chosen Account kind, for the machine and
// unrecognised-kind cases the offered-to-a-human-admin-only rule is about.
type kindVerifier struct {
	role accounts.Role
	kind accounts.Kind
}

func (v kindVerifier) Verify(_ context.Context, credential string) (accounts.Account, accounts.APIToken, error) {
	if credential != testCredential {
		return accounts.Account{}, accounts.APIToken{}, accounts.ErrTokenInvalid
	}
	return accounts.Account{
		ID:      testAccountID(v.role),
		Name:    testAccountName(v.role),
		Kind:    v.kind,
		Role:    v.role,
		Enabled: true,
	}, accounts.APIToken{ID: "tok-test"}, nil
}

// newKindTestHandler is newTestHandler for an Account of the given kind.
func newKindTestHandler(d Deps, role accounts.Role, kind accounts.Kind) http.Handler {
	authn := controlplane.NewAuthenticator(kindVerifier{role: role, kind: kind})
	mux := http.NewServeMux()
	Register(mux, d)
	return authn.Middleware(Secure(mux, nil))
}

// newKindTestHandlerSkippingCSRF is newTestHandlerSkippingCSRF for a kind.
func newKindTestHandlerSkippingCSRF(d Deps, role accounts.Role, kind accounts.Kind) http.Handler {
	authn := controlplane.NewAuthenticator(kindVerifier{role: role, kind: kind})
	mux := http.NewServeMux()
	Register(mux, d)
	return authn.Middleware(mux)
}

// aliasNode is a Node reporting fp, healthy unless connected is false.
func aliasNode(id, fp string, connected bool) registry.Node {
	return registry.Node{
		NodeID:            id,
		NodeLabels:        map[string]string{"role": "web"},
		PolicyFingerprint: fp,
		DaemonVersion:     "0.6.0",
		LastSeen:          testNow,
		Connected:         connected,
	}
}

// aliasDeps is a Console over fakeQueries holding nodes and aliases, with a
// fake alias writer wired.
func aliasDeps(aliases map[string]string, nodes ...registry.Node) (Deps, *fakeQueries, *fakeAliasWriter) {
	w := &fakeAliasWriter{}
	q := &fakeQueries{nodes: nodes, aliases: aliases}
	d := renderableDeps()
	d.Queries = q
	d.AliasWriter = w
	return d, q, w
}

var (
	fpA = hexFP("a")
	fpB = hexFP("b")
	fpC = hexFP("c")

	aliasedPair = regexp.MustCompile(`<bdi class="fpalias">([^<]*)</bdi> <code class="fphash">([0-9a-f]{64})</code>`)
	letteredFP  = regexp.MustCompile(`<span class="fpletter"[^>]*>([A-Z]+)</span> <code class="fphash">([0-9a-f]{64})</code>`)
	editorFP    = regexp.MustCompile(`<input type="hidden" name="fingerprint" value="([^"]*)">`)
)

// Three screens, one fixture: a healthy and an offline Node on fpA, one on fpB
// (no alias) and one on fpC, so the headline, a facet and a table row all draw
// fingerprints.
func aliasScreenFixture() (Deps, *fakeAliasWriter) {
	d, _, w := aliasDeps(
		map[string]string{fpA: "web-hardened", fpC: "db-baseline"},
		aliasNode("node-1", fpA, true),
		aliasNode("node-2", fpA, true),
		aliasNode("node-3", fpB, false),
		aliasNode("node-4", fpC, true),
	)
	return d, w
}

const (
	aliasFleetPath   = "/console/?group=role"
	aliasNodePath    = "/console/nodes/node-1"
	aliasComparePath = "/console/compare?nodes=node-1,node-3,node-4"
)

// Proves QRY-33.
//
// Each alias is drawn immediately before the full hash it names, on Fleet's
// headline, facet and table, on Node detail and on Compare; the alias text
// appears nowhere else but an editor's value attribute; and no well-formed
// fingerprint is drawn in its short form.
func TestPolicyAliases_EveryAliasIsDrawnBesideItsFullFingerprint(t *testing.T) {
	d, _ := aliasScreenFixture()
	h := newTestHandler(d, accounts.RoleAdmin)
	want := map[string]string{fpA: "web-hardened", fpC: "db-baseline"}

	for _, tc := range []struct {
		path string
		min  map[string]int // alias draws expected at least, by hash
	}{
		{aliasFleetPath, map[string]int{fpA: 2, fpC: 3}}, // headline and facet; fpC also a table row
		{aliasNodePath, map[string]int{fpA: 1}},
		{aliasComparePath, map[string]int{fpA: 1, fpC: 1}},
	} {
		rec := get(t, h, tc.path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", tc.path, rec.Code)
		}
		body := rec.Body.String()

		drawn := map[string]int{}
		pairs := aliasedPair.FindAllStringSubmatch(body, -1)
		for _, m := range pairs {
			alias, hash := m[1], m[2]
			if want[hash] != alias {
				t.Errorf("%s: alias %q is drawn beside %s, which it does not name", tc.path, alias, hash)
			}
			drawn[hash]++
		}
		if n := strings.Count(body, `class="fpalias"`); n != len(pairs) {
			t.Errorf("%s: %d alias elements, %d of them directly before a full hash", tc.path, n, len(pairs))
		}
		for hash, atLeast := range tc.min {
			if drawn[hash] < atLeast {
				t.Errorf("%s: the alias of %s is drawn %d times, want at least %d", tc.path, hash, drawn[hash], atLeast)
			}
		}
		for hash, alias := range want {
			wanted := drawn[hash] + strings.Count(body, `value="`+alias+`"`)
			if got := strings.Count(body, alias); got != wanted {
				t.Errorf("%s: %q appears %d times, want %d (beside its hash, or an editor's value)", tc.path, alias, got, wanted)
			}
		}
		for _, hash := range []string{fpA, fpB, fpC} {
			if short := shortHash(hash); strings.Contains(body, short) {
				t.Errorf("%s: a well-formed fingerprint is drawn in its short form %q", tc.path, short)
			}
		}
	}
}

// fpLetters maps each hash to the distinct letters drawn beside it.
func fpLetters(body string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	for _, m := range letteredFP.FindAllStringSubmatch(body, -1) {
		if out[m[2]] == nil {
			out[m[2]] = map[string]bool{}
		}
		out[m[2]][m[1]] = true
	}
	return out
}

// onlyLetter returns the one letter drawn beside hash, failing the test when
// there is none or more than one.
func onlyLetter(t *testing.T, where string, letters map[string]map[string]bool, hash string) string {
	t.Helper()
	got := letters[hash]
	if len(got) != 1 {
		t.Errorf("%s: %s carries the letters %v, want exactly one", where, hash, got)
		return ""
	}
	for l := range got {
		return l
	}
	return ""
}

// tenGroups builds ten role groups of 15 down to 6 Nodes, one distinct
// fingerprint per group, all connected and reporting a daemon version, so that
// every card is large and healthy and renders closed. Group i's fingerprint is
// groupFP(i).
func tenGroups() []registry.Node {
	var nodes []registry.Node
	for g := 0; g < 10; g++ {
		for n := 0; n < 15-g; n++ {
			node := aliasNode(fmt.Sprintf("node-g%d-%d", g, n), groupFP(g), true)
			node.NodeLabels = map[string]string{"shard": fmt.Sprintf("shard-%d", g)}
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func groupFP(g int) string { return fmt.Sprintf("%064x", g+1) }

// Proves QRY-33.
//
// An unaliased fingerprint takes a letter in order of first appearance on the
// page. Past eight fingerprints the headline stops, and the remaining ones
// appear only in closed cards, which are in the page all the same.
func TestPolicyAliases_UnaliasedFingerprintsTakeLettersInOrderOfFirstAppearance(t *testing.T) {
	fleet := func(aliases map[string]string) (string, *fakeQueries) {
		d, q, _ := aliasDeps(aliases, tenGroups()...)
		rec := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/?group=shard")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET fleet = %d, want 200", rec.Code)
		}
		return rec.Body.String(), q
	}

	t.Run("letters follow the headline, then the closed cards", func(t *testing.T) {
		body, q := fleet(nil)
		if q.aliasReads != 1 {
			t.Errorf("the page made %d alias reads, want 1", q.aliasReads)
		}
		letters := fpLetters(body)
		for g := 0; g < 10; g++ {
			want := string(rune('A' + g))
			if got := onlyLetter(t, "fleet", letters, groupFP(g)); got != want {
				t.Errorf("group %d's fingerprint is lettered %q, want %q", g, got, want)
			}
		}
		// The 9th and 10th are in no headline entry, only in closed cards.
		headline := body[strings.Index(body, `class="ssfps"`):strings.Index(body, `class="sswallhead"`)]
		for _, g := range []int{8, 9} {
			if strings.Contains(headline, groupFP(g)) {
				t.Errorf("group %d's fingerprint is in the headline, which lists eight", g)
			}
		}
		cards := regexp.MustCompile(`<details class="group"[^>]*>`).FindAllString(body, -1)
		if len(cards) != 10 {
			t.Fatalf("%d cards, want 10", len(cards))
		}
		for i, c := range cards {
			if strings.Contains(c, " open") {
				t.Errorf("card %d renders open: %s", i, c)
			}
		}
	})

	t.Run("an alias on the third fingerprint shifts the letters and uses none", func(t *testing.T) {
		body, _ := fleet(map[string]string{groupFP(2): "baseline"})
		letters := fpLetters(body)
		if _, ok := letters[groupFP(2)]; ok {
			t.Error("the aliased fingerprint is also drawn with a letter")
		}
		for g, want := range map[int]string{0: "A", 1: "B", 3: "C", 4: "D", 9: "I"} {
			if got := onlyLetter(t, "fleet", letters, groupFP(g)); got != want {
				t.Errorf("group %d's fingerprint is lettered %q, want %q", g, got, want)
			}
		}
	})

	t.Run("a letter equal to a held alias is skipped", func(t *testing.T) {
		body, _ := fleet(map[string]string{groupFP(5): "B"})
		letters := fpLetters(body)
		for hash, ls := range letters {
			if ls["B"] {
				t.Errorf("%s is lettered B while another fingerprint is aliased B", hash)
			}
		}
		if got := onlyLetter(t, "fleet", letters, groupFP(1)); got != "C" {
			t.Errorf("the second fingerprint is lettered %q, want C (B is a held alias)", got)
		}
	})

	t.Run("letterAt counts A to Z, AA, AB", func(t *testing.T) {
		for i, want := range map[int]string{0: "A", 1: "B", 25: "Z", 26: "AA", 27: "AB", 51: "AZ", 52: "BA", 701: "ZZ", 702: "AAA"} {
			if got := letterAt(i); got != want {
				t.Errorf("letterAt(%d) = %q, want %q", i, got, want)
			}
		}
	})
}

// Proves QRY-33.
//
// Compare names each column's fingerprint with one namer: two Nodes on one
// fingerprint share its letter, and the difference is the hash's, not the name's.
func TestCompare_AFingerprintCarriesOneLetterInEveryColumn(t *testing.T) {
	d, _, _ := aliasDeps(nil,
		aliasNode("node-1", fpA, true), aliasNode("node-2", fpA, true), aliasNode("node-3", fpB, true))
	rec := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/compare?nodes=node-1,node-2,node-3&rows=all")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET compare = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	var got []string
	for _, m := range letteredFP.FindAllStringSubmatch(body, -1) {
		got = append(got, m[1])
	}
	if strings.Join(got, ",") != "A,A,B" {
		t.Errorf("Compare letters = %v, want [A A B]", got)
	}
	if !regexp.MustCompile(`<tr data-diff="1">\s*<th scope="row" class="cmpkey">Policy fingerprint</th>`).MatchString(body) {
		t.Error("the Policy fingerprint row is not marked as differing")
	}

	same, _, _ := aliasDeps(map[string]string{fpA: "web-hardened"},
		aliasNode("node-1", fpA, true), aliasNode("node-2", fpA, true))
	body = get(t, newTestHandler(same, accounts.RoleAdmin), "/console/compare?nodes=node-1,node-2&rows=all").Body.String()
	if regexp.MustCompile(`data-diff="1">\s*<th scope="row" class="cmpkey">Policy fingerprint`).MatchString(body) {
		t.Error("two Nodes on one fingerprint are marked as differing because of a name")
	}
}

var startTagOf = func(class string) *regexp.Regexp {
	return regexp.MustCompile(`<[a-z]+ class="` + class + `"[^>]*>`)
}

// Proves QRY-33.
//
// A name carries no colour and ranks nothing: the alias and letter elements
// hold no data attribute a stylesheet could colour by, and no screen calls a
// fingerprint a majority or an outlier.
func TestPolicyAliases_NoLetterOrAliasCarriesColourOrRanking(t *testing.T) {
	d, _ := aliasScreenFixture()
	h := newTestHandler(d, accounts.RoleAdmin)
	seen := map[string]int{}
	for _, path := range []string{aliasFleetPath, aliasNodePath, aliasComparePath} {
		body := get(t, h, path).Body.String()
		for _, class := range []string{"fpletter", "fpalias"} {
			for _, tag := range startTagOf(class).FindAllString(body, -1) {
				seen[class]++
				if strings.Contains(tag, "data-") || strings.Contains(tag, "style") {
					t.Errorf("%s: %s carries a data or style attribute: %s", path, class, tag)
				}
			}
		}
		lower := strings.ToLower(body)
		for _, word := range []string{"majority", "outlier"} {
			if strings.Contains(lower, word) {
				t.Errorf("%s: names a fingerprint with %q", path, word)
			}
		}
	}
	if seen["fpletter"] == 0 || seen["fpalias"] == 0 {
		t.Errorf("the fixture drew %v, want both letters and aliases", seen)
	}
}

// Proves QRY-35.
//
// Fleet, Node detail and Compare each read the aliases once, through the
// recorded lane, attributed to the signed-in Account.
func TestPolicyAliases_FleetNodeDetailAndCompareReadThroughTheRecordedLane(t *testing.T) {
	for _, path := range []string{aliasFleetPath, aliasNodePath, aliasComparePath} {
		trail := &recordingTrail{}
		reg := registry.NewInMemory()
		for _, n := range []struct{ id, fp string }{{"node-1", fpA}, {"node-3", fpB}, {"node-4", fpC}} {
			if _, err := reg.Upsert(registry.Report{NodeID: n.id, PolicyFingerprint: n.fp, DaemonVersion: "0.6.0"}); err != nil {
				t.Fatalf("seed %s: %v", n.id, err)
			}
		}
		svc := newCapService(capSeams{
			reg:     reg,
			audit:   auditsink.New(trail, auditsink.WithClock(func() time.Time { return testNow })),
			auditQ:  emptyAuditQuery{},
			jobQ:    emptyJobQuery{},
			aliases: mapAliasSource{fpA: "web-hardened"},
		})
		d := renderableDeps()
		d.Queries = svc.ReadLane
		d.AliasWriter = &fakeAliasWriter{}

		rec := get(t, newTestHandler(d, accounts.RoleAdmin), path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200: %s", path, rec.Code, rec.Body.String())
		}
		var reads []audit.Record
		for _, r := range trail.ofKind(audit.KindRead) {
			if r.OperationName == "list_policy_aliases" {
				reads = append(reads, r)
			}
		}
		if len(reads) != 1 {
			t.Fatalf("GET %s wrote %d list_policy_aliases records, want exactly 1", path, len(reads))
		}
		if got := reads[0].Attribution.Verified.AccountName; got != testAccountName(accounts.RoleAdmin) {
			t.Errorf("GET %s: the alias read is attributed to %q, want %q", path, got, testAccountName(accounts.RoleAdmin))
		}
		if !strings.Contains(rec.Body.String(), `<bdi class="fpalias">web-hardened</bdi>`) {
			t.Errorf("GET %s did not render the alias the lane returned", path)
		}
	}
}

// Proves QRY-35.
//
// A page whose alias read cannot be recorded is refused, and the alias is not
// rendered: the fail-closed rule the capability layer holds for every read.
func TestPolicyAliases_AnUnrecordableAliasReadRefusesThePage(t *testing.T) {
	for _, path := range []string{aliasFleetPath, aliasNodePath, aliasComparePath} {
		d, q, _ := aliasDeps(map[string]string{fpA: "web-hardened"},
			aliasNode("node-1", fpA, true), aliasNode("node-3", fpB, true), aliasNode("node-4", fpC, true))
		q.aliasesErr = capability.ErrReadUnaudited
		rec := get(t, newTestHandler(d, accounts.RoleAdmin), path)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("GET %s = %d, want 500", path, rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "could not be recorded on the audit trail") || !strings.Contains(body, "this Relay's Policy aliases") {
			t.Errorf("GET %s did not answer the unaudited refusal naming the aliases: %s", path, body)
		}
		if strings.Contains(body, "web-hardened") {
			t.Errorf("GET %s rendered the alias although its read was not recorded", path)
		}
	}
}

// Proves QRY-35.
//
// A failed alias read is named as the aliases on every screen, Compare
// included, never as another read.
func TestPolicyAliases_AnUnreadableAliasReadIsNamedAsTheAliases(t *testing.T) {
	for _, path := range []string{aliasFleetPath, aliasNodePath, aliasComparePath} {
		d, q, _ := aliasDeps(nil,
			aliasNode("node-1", fpA, true), aliasNode("node-3", fpB, true), aliasNode("node-4", fpC, true))
		q.aliasesErr = errors.New("alias store down")
		rec := get(t, newTestHandler(d, accounts.RoleAdmin), path)
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("GET %s = %d, want 500", path, rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, "this Relay's Policy aliases could not be read") {
			t.Errorf("GET %s did not name the aliases as unreadable: %s", path, body)
		}
		if strings.Contains(body, "the pinned Nodes&#39; registry records") || strings.Contains(body, "the pinned Nodes' registry records") {
			t.Errorf("GET %s reported the alias failure as the pinned Nodes' records: %s", path, body)
		}
	}
}

// editorsOn counts the Edit alias forms on a page, one per hidden fingerprint
// field, and returns the fingerprints they edit.
func editorsOn(body string) []string {
	var out []string
	for _, m := range editorFP.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	return out
}

// Proves QRY-35.
//
// The Edit alias control is offered to a human admin only: one per well-formed
// Policy fingerprint facet value on Fleet and one on Node detail, never in the
// headline, the deviation table or Compare, and not to a viewer, an operator, a
// machine Account at any role or one of an unrecognised kind. With the writer
// unwired nobody sees one. A human of any role is drawn the alias and the
// letters; a machine principal is drawn the letters only
// (TestPolicyAliases_AMachinePrincipalIsDrawnNoAliasName).
func TestPolicyAliases_TheEditControlIsOfferedToAHumanAdminOnly(t *testing.T) {
	d, _ := aliasScreenFixture()
	editors := func(h http.Handler, path string) int {
		rec := get(t, h, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, rec.Code)
		}
		return len(editorsOn(rec.Body.String()))
	}

	admin := newTestHandler(d, accounts.RoleAdmin)
	if got := editors(admin, aliasFleetPath); got != 3 {
		t.Errorf("a human admin sees %d editors on Fleet, want 3 (one per fingerprint in the facet)", got)
	}
	if got := editors(admin, aliasNodePath); got != 1 {
		t.Errorf("a human admin sees %d editors on Node detail, want 1", got)
	}
	if got := editors(admin, aliasComparePath); got != 0 {
		t.Errorf("a human admin sees %d editors on Compare, want none", got)
	}

	fleet := get(t, admin, aliasFleetPath).Body.String()
	headline := fleet[strings.Index(fleet, `class="ssfps"`):strings.Index(fleet, `class="sswallhead"`)]
	if strings.Contains(headline, "aliasedit") {
		t.Error("the headline carries an editor")
	}
	for _, table := range regexp.MustCompile(`(?s)<table class="cards">.*?</table>`).FindAllString(fleet, -1) {
		if strings.Contains(table, "aliasedit") {
			t.Error("a deviation table carries an editor")
		}
	}

	for _, tc := range []struct {
		name      string
		h         http.Handler
		wantAlias bool
	}{
		{"viewer", newTestHandler(d, accounts.RoleViewer), true},
		{"operator", newTestHandler(d, accounts.RoleOperator), true},
		{"machine admin", newKindTestHandler(d, accounts.RoleAdmin, accounts.KindMachine), false},
		{"admin of no recorded kind", newKindTestHandler(d, accounts.RoleAdmin, ""), false},
		{"admin of an unrecognised kind", newKindTestHandler(d, accounts.RoleAdmin, "Human"), false},
	} {
		for _, path := range []string{aliasFleetPath, aliasNodePath, aliasComparePath} {
			rec := get(t, tc.h, path)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: GET %s = %d, want 200", tc.name, path, rec.Code)
			}
			body := rec.Body.String()
			if strings.Contains(body, "Edit alias") || strings.Contains(body, policyAliasesAction) {
				t.Errorf("%s is offered an editor on %s", tc.name, path)
			}
			if got := strings.Contains(body, `<bdi class="fpalias">web-hardened</bdi>`); got != tc.wantAlias {
				t.Errorf("%s: %s draws the alias = %v, want %v", tc.name, path, got, tc.wantAlias)
			}
			// Node detail draws one fingerprint, which a human is shown by alias.
			if letterExpected := !tc.wantAlias || path != aliasNodePath; letterExpected && !strings.Contains(body, `class="fpletter"`) {
				t.Errorf("%s: %s draws no letter", tc.name, path)
			}
		}
	}

	unwired := d
	unwired.AliasWriter = nil
	for _, path := range []string{aliasFleetPath, aliasNodePath} {
		if got := editors(newTestHandler(unwired, accounts.RoleAdmin), path); got != 0 {
			t.Errorf("with the writer unwired an admin sees %d editors on %s", got, path)
		}
	}
}

// Proves QRY-33.
//
// A machine principal, an AI-agent among them, is read no alias and drawn none:
// Fleet, Node detail and Compare make no alias read for it (so no
// list_policy_aliases record), and every well-formed fingerprint is drawn with
// its neutral letter and its full hash, no name and no editor. A principal of
// no recorded or an unrecognised kind is treated the same way (Principal.Human
// is fail-closed), and a human of the same role is read the aliases.
func TestPolicyAliases_AMachinePrincipalIsDrawnNoAliasName(t *testing.T) {
	for _, tc := range []struct {
		name      string
		kind      accounts.Kind
		wantReads int
	}{
		{"machine admin", accounts.KindMachine, 0},
		{"admin of no recorded kind", "", 0},
		{"admin of an unrecognised kind", "Human", 0},
		{"human admin", accounts.KindHuman, 1},
	} {
		for _, path := range []string{aliasFleetPath, aliasNodePath, aliasComparePath} {
			d, q, _ := aliasDeps(map[string]string{fpA: "web-hardened", fpC: "db-baseline"},
				aliasNode("node-1", fpA, true),
				aliasNode("node-2", fpA, true),
				aliasNode("node-3", fpB, false),
				aliasNode("node-4", fpC, true),
			)
			rec := get(t, newKindTestHandler(d, accounts.RoleAdmin, tc.kind), path)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: GET %s = %d, want 200", tc.name, path, rec.Code)
			}
			body := rec.Body.String()
			if q.aliasReads != tc.wantReads {
				t.Errorf("%s: GET %s made %d alias reads, want %d", tc.name, path, q.aliasReads, tc.wantReads)
			}
			if tc.wantReads > 0 {
				continue
			}
			for _, name := range []string{"web-hardened", "db-baseline", `class="fpalias"`} {
				if strings.Contains(body, name) {
					t.Errorf("%s: %s draws %q to a machine principal", tc.name, path, name)
				}
			}
			if !strings.Contains(body, `class="fpletter"`) || !strings.Contains(body, `<code class="fphash">`+fpA+`</code>`) {
				t.Errorf("%s: %s is not drawn the letter and the full fingerprint", tc.name, path)
			}
		}
	}
}

// Proves QRY-35.
//
// policyAliasesOffered requires a wired writer, a human caller, and a role that
// reaches the route. Principal.Human is fail-closed, so an empty or
// mis-spelt kind is offered nothing.
func TestPolicyAliasesOffered_RequiresAWiredWriterAHumanAndTheAdminRoute(t *testing.T) {
	wired := Deps{AliasWriter: &fakeAliasWriter{}}
	for _, tc := range []struct {
		name string
		d    Deps
		role accounts.Role
		kind string
		want bool
	}{
		{"human admin", wired, accounts.RoleAdmin, "human", true},
		{"machine admin", wired, accounts.RoleAdmin, "machine", false},
		{"admin with no kind", wired, accounts.RoleAdmin, "", false},
		{"admin of kind Human", wired, accounts.RoleAdmin, "Human", false},
		{"admin of kind 'human '", wired, accounts.RoleAdmin, "human ", false},
		{"human operator", wired, accounts.RoleOperator, "human", false},
		{"human viewer", wired, accounts.RoleViewer, "human", false},
		{"human admin, writer unwired", Deps{}, accounts.RoleAdmin, "human", false},
	} {
		p := capability.Principal{Account: "someone", Role: string(tc.role), Kind: tc.kind}
		if got := policyAliasesOffered(tc.d, p); got != tc.want {
			t.Errorf("%s: policyAliasesOffered = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// aliasPost posts form to the alias route as role (a human), skipping CSRF the
// way the tags tests do.
func aliasPost(t *testing.T, d Deps, role accounts.Role, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	return postFormSkippingCSRF(t, newTestHandlerSkippingCSRF(d, role), policyAliasesAction, form)
}

// A viewer or an operator finds the write route absent, not refused.
func TestPolicyAliases_ANonAdminSessionFindsTheWriteRouteAbsent(t *testing.T) {
	for _, role := range []accounts.Role{accounts.RoleViewer, accounts.RoleOperator} {
		d, _, w := aliasDeps(nil, aliasNode("node-1", fpA, true))
		rec := aliasPost(t, d, role, url.Values{"fingerprint": {fpA}, "op": {"set"}, "alias": {"x"}})
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s: POST = %d, want the gated 404", role, rec.Code)
		}
		if sets, clears := w.calls(); len(sets)+len(clears) != 0 {
			t.Errorf("%s: the writer was called: %v %v", role, sets, clears)
		}
	}
}

// The Console decides nothing about who may write, so a machine admin's POST
// reaches the capability layer, which refuses and records it.
func TestPolicyAliases_AMachineAdminsPostReachesTheCapabilityLayerUndecided(t *testing.T) {
	d, _, w := aliasDeps(nil, aliasNode("node-1", fpA, true))
	w.setErr = fmt.Errorf("%w: only a human Account may do this", authz.ErrUnauthorized)
	h := newKindTestHandlerSkippingCSRF(d, accounts.RoleAdmin, accounts.KindMachine)

	rec := postFormSkippingCSRF(t, h, policyAliasesAction, url.Values{"fingerprint": {fpA}, "op": {"set"}, "alias": {"x"}})
	sets, _ := w.calls()
	if len(sets) != 1 {
		t.Fatalf("the writer was called %d times, want 1", len(sets))
	}
	if sets[0].Principal.Kind != "machine" || sets[0].Principal.Human() {
		t.Errorf("the writer saw the principal %+v, want a machine", sets[0].Principal)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("POST = %d, want the capability layer's refusal as 403", rec.Code)
	}
}

// A set passes the alias exactly as typed and a clear passes only the
// fingerprint; the form's origin decides where the redirect goes and the
// request's query string decides nothing.
func TestPolicyAliases_AWriteReachesTheCapabilityLayerAndReturnsToWhereItWasMade(t *testing.T) {
	post := func(form url.Values, target string) (*httptest.ResponseRecorder, *fakeAliasWriter) {
		d, _, w := aliasDeps(nil, aliasNode("node-1", fpA, true))
		req := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+testCredential)
		rec := httptest.NewRecorder()
		newTestHandlerSkippingCSRF(d, accounts.RoleAdmin).ServeHTTP(rec, req)
		return rec, w
	}

	t.Run("set from the Fleet view", func(t *testing.T) {
		rec, w := post(url.Values{
			"fingerprint": {fpA}, "op": {"set"}, "alias": {"  web hardened  "},
			"filter": {"node:role=web"}, "group": {"role"}, "pin": {"node-1,node-2"},
		}, policyAliasesAction+"?op=clear&fingerprint="+fpB)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("POST = %d, want 303: %s", rec.Code, rec.Body.String())
		}
		sets, clears := w.calls()
		if len(sets) != 1 || len(clears) != 0 {
			t.Fatalf("calls = %v %v, want one set", sets, clears)
		}
		if sets[0].Fingerprint != fpA || sets[0].Name != "  web hardened  " {
			t.Errorf("the writer got %q, %q: the alias is passed as typed and the query string is ignored", sets[0].Fingerprint, sets[0].Name)
		}
		if sets[0].Principal.Account != testAccountName(accounts.RoleAdmin) {
			t.Errorf("the writer saw %+v, want the signed-in Account", sets[0].Principal)
		}
		loc, err := url.Parse(rec.Header().Get("Location"))
		if err != nil || loc.Path != fleetPath {
			t.Fatalf("Location = %q, want the Fleet view", rec.Header().Get("Location"))
		}
		q := loc.Query()
		if q.Get("filter") != "node:role=web" || q.Get("group") != "role" || q.Get("pin") != "node-1,node-2" {
			t.Errorf("Location query = %v, want the filter, grouping and pin carried back", q)
		}
	})

	t.Run("clear from Node detail", func(t *testing.T) {
		rec, w := post(url.Values{"fingerprint": {fpA}, "op": {"clear"}, "alias": {"ignored"}, "node_id": {"node-1"}, "pin": {"node-2"}}, policyAliasesAction)
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("POST = %d, want 303", rec.Code)
		}
		sets, clears := w.calls()
		if len(sets) != 0 || len(clears) != 1 || clears[0].Fingerprint != fpA {
			t.Fatalf("calls = %v %v, want one clear of %s", sets, clears, fpA)
		}
		if got := rec.Header().Get("Location"); got != "/console/nodes/node-1?pin=node-2" {
			t.Errorf("Location = %q, want the Node with its pin", got)
		}
	})

	t.Run("the redirect is built by the server", func(t *testing.T) {
		rec, _ := post(url.Values{"fingerprint": {fpA}, "op": {"set"}, "alias": {"x"}, "node_id": {"../../evil?x=#"}}, policyAliasesAction)
		loc := rec.Header().Get("Location")
		if !strings.HasPrefix(loc, "/console/nodes/") || strings.Contains(loc, "?x=") || strings.Contains(loc, "#") || strings.Contains(loc, "//") {
			t.Errorf("Location = %q, want a path beneath the Console's Node pages", loc)
		}
	})

	t.Run("an unknown op is refused before any capability call", func(t *testing.T) {
		rec, w := post(url.Values{"fingerprint": {fpA}, "op": {"delete"}}, policyAliasesAction)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST = %d, want 400", rec.Code)
		}
		if sets, clears := w.calls(); len(sets)+len(clears) != 0 {
			t.Errorf("the writer was called for an unknown op: %v %v", sets, clears)
		}
	})
}

// A refusal is shown in the capability layer's own words, with the status its
// class carries, and says that nothing was changed; a failure that may follow a
// recorded change does not.
func TestPolicyAliases_RefusalsAreShownInTheServersWords(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		status   int
		contains []string
		not      string
	}{
		{"taken", capability.ErrPolicyAliasTaken, http.StatusConflict,
			[]string{"A Policy alias already names another Policy fingerprint", "Nothing was changed."}, ""},
		{"changed", capability.ErrPolicyAliasChanged, http.StatusConflict,
			[]string{"A Policy alias changed while this change was being made", "Nothing was changed."}, ""},
		{"empty", errors.Join(capability.ErrPolicyAliasEmpty, errors.New("store detail")), http.StatusBadRequest,
			[]string{"A Policy alias is empty after trimming.", "Nothing was changed."}, "store detail"},
		{"too long", capability.ErrPolicyAliasTooLong, http.StatusBadRequest,
			[]string{"longer than 64 characters", "Nothing was changed."}, ""},
		{"control character", capability.ErrPolicyAliasControlCharacter, http.StatusBadRequest,
			[]string{"control or format character"}, ""},
		{"invalid UTF-8", capability.ErrPolicyAliasInvalidUTF8, http.StatusBadRequest,
			[]string{"not valid UTF-8"}, ""},
		{"malformed fingerprint", capability.ErrPolicyFingerprintMalformed, http.StatusBadRequest,
			[]string{"well-formed Policy fingerprint"}, ""},
		{"unauthorized", errors.Join(fmt.Errorf("%w: only a human admin may do this", authz.ErrUnauthorized), errors.New("store detail")),
			http.StatusForbidden, []string{"The Relay refused this alias change: ", "only a human admin may do this", "Nothing was changed."}, "store detail"},
		{"unconfirmed", errors.New("disk on fire"), http.StatusInternalServerError,
			[]string{"The Relay could not confirm this alias change."}, "Nothing was changed"},
		{"unavailable", capability.ErrPolicyAliasesUnavailable, http.StatusInternalServerError,
			[]string{"was not wired into this Relay"}, ""},
	} {
		d, _, w := aliasDeps(nil, aliasNode("node-1", fpA, true))
		w.setErr = tc.err
		rec := aliasPost(t, d, accounts.RoleAdmin, url.Values{"fingerprint": {fpA}, "op": {"set"}, "alias": {"x"}})
		if rec.Code != tc.status {
			t.Errorf("%s: POST = %d, want %d", tc.name, rec.Code, tc.status)
		}
		body := rec.Body.String()
		for _, want := range tc.contains {
			if !strings.Contains(body, want) {
				t.Errorf("%s: the page does not say %q: %s", tc.name, want, body)
			}
		}
		if tc.not != "" && strings.Contains(body, tc.not) {
			t.Errorf("%s: the page says %q", tc.name, tc.not)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("%s: Cache-Control = %q, want no-store", tc.name, cc)
		}
	}
}

// With the writer unwired the route answers unavailable rather than 404, the
// same posture as every unwired write seam.
func TestPolicyAliases_AnUnwiredWriterAnswersUnavailable(t *testing.T) {
	d, _, _ := aliasDeps(nil, aliasNode("node-1", fpA, true))
	d.AliasWriter = nil
	rec := aliasPost(t, d, accounts.RoleAdmin, url.Values{"fingerprint": {fpA}, "op": {"set"}, "alias": {"x"}})
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "was not wired into this Relay") {
		t.Errorf("POST = %d %s, want the unavailable explanation", rec.Code, rec.Body.String())
	}
}

// Proves QRY-35.
//
// The form is the only place a name is typed: it carries the CSRF token, the
// fingerprint it edits and the alias it holds; Clear exists only where there is
// an alias to clear; and a malformed reported value carries neither a name nor
// a control.
func TestPolicyAliases_TheEditorCarriesWhatTheWriteNeeds(t *testing.T) {
	malformed := "aaaa111122223333"
	d, _, _ := aliasDeps(map[string]string{fpA: "web-hardened"},
		aliasNode("node-1", fpA, true), aliasNode("node-2", fpB, true), aliasNode("node-3", malformed, true))
	h := newTestHandler(d, accounts.RoleAdmin)

	fleet := get(t, h, "/console/?filter=node%3Arole%3Dweb&group=role&pin=node-2").Body.String()
	forms := formsTargeting(postForms(fleet), policyAliasesAction)
	if len(forms) != 2 {
		t.Fatalf("Fleet draws %d editors, want 2 (the malformed value gets none)", len(forms))
	}
	for _, f := range forms {
		for _, want := range []string{`name="csrf_token"`, `name="fingerprint"`, `name="alias"`, `name="filter" value="node:role=web"`, `name="group" value="role"`, `name="pin" value="node-2"`, `value="set">Save</button>`} {
			if !strings.Contains(f, want) {
				t.Errorf("an editor lacks %q: %s", want, f)
			}
		}
		if strings.Contains(f, `name="node_id"`) {
			t.Errorf("a Fleet editor carries a node_id: %s", f)
		}
		aliased := strings.Contains(f, `value="`+fpA+`"`)
		if has := strings.Contains(f, `value="clear">Clear</button>`); has != aliased {
			t.Errorf("Clear present = %v for an editor whose fingerprint is aliased = %v", has, aliased)
		}
		if aliased && !strings.Contains(f, `name="alias" value="web-hardened"`) {
			t.Errorf("the editor of an aliased fingerprint does not hold its alias: %s", f)
		}
		if strings.Contains(f, "maxlength") || strings.Contains(f, "required") {
			t.Errorf("the editor carries maxlength or required, which would disagree with the capability layer: %s", f)
		}
	}
	if !strings.Contains(fleet, `<code title="`+malformed+`">`+shortHash(malformed)+`</code>`) {
		t.Error("the malformed reported value is not drawn short, as before")
	}

	node := get(t, h, "/console/nodes/node-1?pin=node-2").Body.String()
	forms = formsTargeting(postForms(node), policyAliasesAction)
	if len(forms) != 1 || !strings.Contains(forms[0], `name="node_id" value="node-1"`) || !strings.Contains(forms[0], `name="pin" value="node-2"`) {
		t.Fatalf("Node detail's editor = %v, want one carrying node_id and the pin", forms)
	}

	bad := get(t, h, "/console/nodes/node-3").Body.String()
	if strings.Contains(bad, "aliasedit") || strings.Contains(bad, "fpletter") {
		t.Error("a malformed reported value on Node detail carries a name or control")
	}
}

// Proves QRY-35.
//
// A page that draws no well-formed fingerprint makes no alias read, and the
// unwired source is no aliases and no editor rather than an error.
func TestPolicyAliases_ReadsOnlyWhenTheyAreDrawn(t *testing.T) {
	d, q, _ := aliasDeps(nil, aliasNode("node-1", "aaaa111122223333", true), aliasNode("node-2", "", true))
	h := newTestHandler(d, accounts.RoleAdmin)
	for _, path := range []string{"/console/", "/console/nodes/node-1", "/console/nodes/node-2", "/console/compare?nodes=node-1,node-2", "/console/nodes/node-missing"} {
		get(t, h, path)
	}
	if q.aliasReads != 0 {
		t.Errorf("pages that draw no well-formed fingerprint made %d alias reads", q.aliasReads)
	}

	d, q, _ = aliasDeps(nil, aliasNode("node-1", fpA, true))
	get(t, newTestHandler(d, accounts.RoleAdmin), "/console/?filter=node%3Arole%3Dnone")
	if q.aliasReads != 0 {
		t.Errorf("a filter matching nothing made %d alias reads", q.aliasReads)
	}

	// An unwired source reads as no aliases and no editor.
	d, q, _ = aliasDeps(nil, aliasNode("node-1", fpA, true))
	q.aliasesErr = capability.ErrPolicyAliasesUnavailable
	rec := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/nodes/node-1")
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "aliasedit") {
		t.Errorf("an unwired alias source: %d, editor drawn = %v", rec.Code, strings.Contains(rec.Body.String(), "aliasedit"))
	}
}

// aliasSweepFixture is the sweep fixture with the four fleetFixture Nodes
// reporting well-formed fingerprints (node-web-1 and node-web-2 on fpA,
// node-web-3 on fpB, the offline node-db-1 on fpC), so the shell sweeps meet the
// alias and letter markup the malformed fixture fingerprints never draw. With
// editors, an alias is held on fpA and the writer is wired; without, neither is,
// which is the baseline the editors must add no prose to.
func aliasSweepFixture(editors bool) Deps {
	d := sweepFixture()
	nodes := append([]registry.Node(nil), fleetNodes(d)...)
	for i, fp := range []string{fpA, fpA, fpB, fpC} {
		nodes[i].PolicyFingerprint = fp
	}
	d = withFleet(d, nodes...)
	if editors {
		cp := fakeQueriesCopy(d)
		cp.aliases = map[string]string{fpA: "web-hardened"}
		d.Queries = cp
		d.AliasWriter = &fakeAliasWriter{}
	}
	return d
}

// aliasSweepPaths are the pages that draw a Policy fingerprint, with a filter,
// grouping and pin so the hidden fields an editor carries render.
var aliasSweepPaths = []string{
	"/console/?filter=node%3Arole%3Dweb&group=role&pin=node-web-1",
	"/console/?group=-",
	"/console/nodes/node-web-1?pin=node-web-2",
	"/console/compare?nodes=node-web-1,node-web-3",
}

// visibleWords is the page's budgeted prose, in words.
func visibleWords(t *testing.T, where, content string) int {
	t.Helper()
	elems, unclassified, err := proseOf(content)
	if err != nil {
		t.Fatalf("%s: the scanner cannot attribute this page's text: %v", where, err)
	}
	for _, u := range unclassified {
		t.Errorf("%s: %s", where, u)
	}
	words := 0
	for _, e := range elems {
		if e.Words > maxNoteWords {
			t.Errorf("%s: %s is over %d words", where, e, maxNoteWords)
		}
		if !e.Bounded {
			words += e.Words
		}
	}
	return words
}

// The new markup, rendered for a human admin with the writer wired, passes the
// same sweeps every other page does: no inline script or style, scoped headers,
// short attributes, only pinned POST targets, every control labelled and no more
// prose than the same page without the aliases.
func TestPolicyAliases_TheEditMarkupPassesTheShellSweeps(t *testing.T) {
	with := newTestHandler(aliasSweepFixture(true), accounts.RoleAdmin)
	without := newTestHandler(aliasSweepFixture(false), accounts.RoleAdmin)
	for _, path := range aliasSweepPaths {
		rec := get(t, with, path)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", path, rec.Code)
		}
		content := contentOf(rec.Body.String())
		forms := formsTargeting(postForms(content), policyAliasesAction)
		if strings.HasPrefix(path, "/console/compare") {
			if len(forms) != 0 {
				t.Errorf("%s: Compare carries %d alias editors, want none", path, len(forms))
			}
		} else if len(forms) == 0 {
			t.Fatalf("%s drew no editor, so this sweep proves nothing", path)
		}
		if !strings.Contains(content, "fphash") {
			t.Fatalf("%s drew no full fingerprint, so this sweep proves nothing", path)
		}

		assertCSPClean(t, path, rec.Body.String())
		checkA11yTags(t, path, rec.Body.String())
		for _, long := range longAttributes(content) {
			t.Errorf("%s: %s", path, long)
		}

		baseRec := get(t, without, path)
		if baseRec.Code != http.StatusOK {
			t.Fatalf("GET %s without aliases = %d, want 200", path, baseRec.Code)
		}
		got := visibleWords(t, path, content)
		if base := visibleWords(t, path+" (no aliases)", contentOf(baseRec.Body.String())); got != base {
			t.Errorf("%s: the editor and the names change the prose (%d words against %d)", path, got, base)
		}

		for _, form := range postForms(content) {
			m := formActionRe.FindStringSubmatch(form)
			if m == nil || !pinnedPostActions.MatchString(m[1]) {
				t.Errorf("%s: a POST form targets %v, which is not a known write route", path, m)
			}
			if !hasCSRFToken(form) {
				t.Errorf("%s: a POST form carries no CSRF token: %s", path, form)
			}
		}
		for _, form := range forms {
			if labelFieldRe.MatchString(form) {
				t.Errorf("%s: a tag label field appears in an alias editor: %s", path, form)
			}
			if !strings.Contains(form, "<label>Alias <input") {
				t.Errorf("%s: the alias field is not inside its label: %s", path, form)
			}
		}
	}
}
