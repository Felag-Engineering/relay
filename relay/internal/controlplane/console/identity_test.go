package console

// identity_test.go covers #835: a Node's self-reported hostname leads a Fleet
// row and the Node heading, always beside the verified Node ID, and the filter
// boxes take a name that is resolved once and then replaced by the verified ID.

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
	"github.com/Felag-Engineering/relay/relay/internal/registry"
)

func TestPrimaryHostname_OnlyHostnameCharactersBecomeAPrimary(t *testing.T) {
	long := strings.Repeat("a", maxHostnameBytes+1)
	tests := []struct {
		name, in, want string
	}{
		{"plain", "web-1", "web-1"},
		{"fqdn with trailing dot", "web-1.example.com.", "web-1.example.com."},
		{"underscore", "a_b-1", "a_b-1"},
		{"trimmed", " web-1 ", "web-1"},
		{"max length", strings.Repeat("a", maxHostnameBytes), strings.Repeat("a", maxHostnameBytes)},
		{"node-shaped, exact", "node-0123456789abcdef0123456789abcdef", ""},
		{"node-shaped, upper case", "NODE-0123456789ABCDEF0123456789ABCDEF", ""},
		{"node-shaped, shorter prefix", "node-4e05a1c9", ""},
		{"node-shaped, trailing dot", "node-0123456789abcdef0123456789abcdef.", ""},
		{"node-shaped, local suffix", "node-0123456789abcdef0123456789abcdef.local", ""},
		{"node-shaped, underscore", "node_0123456789abcdef0123456789abcdef", ""},
		{"node-shaped, doubled hyphen", "node--0123456789abcdef0123456789abcdef", ""},
		{"node-shaped, trailing hyphen", "node-0123456789abcdef0123456789abcdef-", ""},
		{"node- but not hex", "node-web-1", "node-web-1"},
		{"empty", "", ""},
		{"whitespace only", " \t ", ""},
		{"too long", long, ""},
		{"leading hyphen", "-web", ""},
		{"leading dot", ".web", ""},
		{"bidi override", "web\u202e1", ""},
		{"zero width space", "web\u200b1", ""},
		{"hangul filler", "web\u3164", ""},
		{"braille blank", "web\u2800", ""},
		{"cyrillic lookalike", "w\u0435b", ""},
		{"inner space", "web 1", ""},
		{"NUL", "web\x00", ""},
		{"invalid UTF-8", "web\xff", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := primaryHostname(tc.in); got != tc.want {
				t.Errorf("primaryHostname(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

var (
	h1Of       = regexp.MustCompile(`(?s)<h1>(.*?)</h1>`)
	titleOf    = regexp.MustCompile(`(?s)<title>(.*?)</title>`)
	nodeHeadOf = regexp.MustCompile(`(?s)class="nodehead">(.*?)</div>`)
)

func singleNodeDeps(id, hostname string) Deps {
	return withFleet(renderableDeps(), registry.Node{
		NodeID:    id,
		Facts:     registry.Facts{Hostname: hostname, OS: "debian"},
		LastSeen:  testNow,
		Connected: true,
	})
}

func TestNode_HostnameIsTheHeadingMarkedSelfReported(t *testing.T) {
	body := get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin), "/console/nodes/node-web-1").Body.String()

	h1 := h1Of.FindStringSubmatch(body)
	if h1 == nil {
		t.Fatal("no h1")
	}
	for _, want := range []string{`<span class="selfrep"`, ">web-1</span>", "self-reported", selfReportedTitleEscaped()} {
		if !strings.Contains(h1[1], want) {
			t.Errorf("the h1 lacks %q: %s", want, h1[1])
		}
	}
	if strings.Contains(h1[1], "node-web-1") {
		t.Errorf("the h1 holds the Node ID, which belongs beneath it: %s", h1[1])
	}
	head := nodeHeadOf.FindStringSubmatch(body)
	if head == nil || !strings.Contains(head[1], `<code class="nodeid" title="The identity this Node's certificate proves.">node-web-1</code>`) {
		t.Errorf("the node head does not carry the full verified Node ID: %v", head)
	}
	if tt := titleOf.FindStringSubmatch(body); tt == nil || !strings.Contains(tt[1], "(self-reported)") {
		t.Errorf("the document title does not say self-reported: %v", tt)
	}
}

func selfReportedTitleEscaped() string {
	return strings.NewReplacer("'", "&#39;").Replace(selfReportedTitle)
}

func TestNode_UnusableHostnameFallsBackToTheFullNodeID(t *testing.T) {
	const id = "node-4e05328a1b2c3d4e5f60718293a4b5c6"
	for name, hostname := range map[string]string{
		"empty":       "",
		"whitespace":  "   ",
		"bidi hijack": "web\u202e1",
	} {
		t.Run(name, func(t *testing.T) {
			body := get(t, newTestHandler(singleNodeDeps(id, hostname), accounts.RoleAdmin), "/console/nodes/"+id).Body.String()
			h1 := h1Of.FindStringSubmatch(body)
			if h1 == nil || h1[1] != id {
				t.Errorf("the h1 = %v, want exactly the full Node ID %q (never shortHash)", h1, id)
			}
			if strings.Contains(body, `class="selfrep"`) || strings.Contains(body, "(self-reported)") {
				t.Error("an unusable hostname was drawn as a self-reported heading")
			}
			if head := nodeHeadOf.FindStringSubmatch(body); head == nil || strings.Contains(head[1], `class="nodeid"`) {
				t.Errorf("the node head repeats the Node ID under a heading that already is the ID: %v", head)
			}
			if hostname == "web\u202e1" && !strings.Contains(body, hostname) {
				t.Error("the Facts panel no longer lists the raw self-report")
			}
		})
	}
}

func rowAnchor(t *testing.T, body, nodeID string) string {
	t.Helper()
	re := regexp.MustCompile(`(?s)<a href="/console/nodes/` + regexp.QuoteMeta(nodeID) + `[^"]*" class="noderef">.*?</a>`)
	m := re.FindString(body)
	if m == "" {
		t.Fatalf("no fleet row anchor for %s:\n%s", nodeID, contentOf(body))
	}
	return m
}

func TestFleet_RowLeadsWithSelfReportedHostnameAboveTheVerifiedID(t *testing.T) {
	body := get(t, newTestHandler(fleetFixture(), accounts.RoleAdmin), "/console/").Body.String()
	a := rowAnchor(t, body, "node-web-1")

	host, id := strings.Index(a, `<span class="selfrep"`), strings.Index(a, `<code class="nodeid">node-web-1</code>`)
	if host < 0 || id < 0 || host > id {
		t.Errorf("the hostname must precede the verified ID in the row:\n%s", a)
	}
	if !strings.Contains(a, ">web-1<") || !strings.Contains(a, "(self-reported)") {
		t.Errorf("the row's accessible name lacks the hostname or self-reported:\n%s", a)
	}
	if !strings.Contains(body, `<th scope="col">Node <span class="selfreptag">hostname self-reported</span></th>`) {
		t.Error("the Node column header does not say the hostname is self-reported")
	}
	// Under 600px the header is hidden and the cell shows its data-label, so
	// the label must carry the word too or phone users never see it.
	if !strings.Contains(body, `data-label="Node · hostname self-reported"><a href=`) {
		t.Error("the Node cell's phone-layout label does not say the hostname is self-reported")
	}
	if !strings.Contains(a, "(self-reported)</span></span> <code") {
		t.Errorf("no space between the hidden self-reported text and the Node ID:\n%s", a)
	}
}

func TestFleet_TwoNodesClaimingOneHostnameStayDistinguishable(t *testing.T) {
	d := withFleet(renderableDeps(),
		registry.Node{NodeID: "node-aaa", Facts: registry.Facts{Hostname: "web-1"}, LastSeen: testNow, Connected: true},
		registry.Node{NodeID: "node-bbb", Facts: registry.Facts{Hostname: "web-1"}, LastSeen: testNow, Connected: true},
	)
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String()
	a, b := rowAnchor(t, body, "node-aaa"), rowAnchor(t, body, "node-bbb")
	if a == b || !strings.Contains(a, "node-aaa") || !strings.Contains(b, "node-bbb") {
		t.Errorf("two Nodes with one hostname are not told apart:\n%s\n%s", a, b)
	}
}

func TestFleet_RowWithoutAHostnameLeadsWithTheID(t *testing.T) {
	d := withFleet(renderableDeps(),
		registry.Node{NodeID: "node-anon", Facts: registry.Facts{Hostname: "bad name"}, LastSeen: testNow, Connected: true})
	body := get(t, newTestHandler(d, accounts.RoleAdmin), "/console/").Body.String()
	a := rowAnchor(t, body, "node-anon")
	if strings.Contains(a, "selfrep") || strings.Count(a, `class="nodeid"`) != 1 {
		t.Errorf("a Node with no usable hostname must lead with its ID alone:\n%s", a)
	}
}

func TestConsole_FilterPlaceholdersAreHints(t *testing.T) {
	viewbar := regexp.MustCompile(`(?s)<form class="viewbar".*?</form>`)
	placeholder := regexp.MustCompile(`placeholder="([^"]*)"`)
	for _, tc := range []struct {
		role accounts.Role
		path string
	}{
		{accounts.RoleAdmin, "/console/"},
		{accounts.RoleAdmin, "/console/activity"},
		{accounts.RoleAdmin, "/console/access"},
		{accounts.RoleViewer, "/console/activity"},
	} {
		d := fleetFixture()
		d.Accounts = &fakeAccounts{}
		body := get(t, newTestHandler(d, tc.role), tc.path).Body.String()
		form := viewbar.FindString(body)
		if form == "" {
			t.Fatalf("%s as %s: no viewbar form", tc.path, tc.role)
		}
		ps := placeholder.FindAllStringSubmatch(form, -1)
		if len(ps) == 0 {
			t.Fatalf("%s as %s: the guard saw no placeholder", tc.path, tc.role)
		}
		for _, p := range ps {
			if !strings.HasPrefix(p[1], "e.g. ") {
				t.Errorf("%s as %s: placeholder %q reads as a filled value; it must start with \"e.g. \"", tc.path, tc.role, p[1])
			}
		}
	}
}
