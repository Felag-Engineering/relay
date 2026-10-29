//go:build integration

package main

// RC-21 on the shippable binary: every test here starts the real Relay as the separate uid
// (relaytest.RelayLayout), rewrites its configuration file as root, and sends it a real SIGHUP.
// The reload's audit records are read from a copy of the store taken after the Relay exits.
// Without the separate uid each test records a skip in make verify's skip ledger and skips.

import (
	"context"
	"encoding/json"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Felag-Engineering/relay/relay/internal/audit"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest"
	"github.com/Felag-Engineering/relay/relay/internal/store"
)

const (
	reloadedMsg = "configuration reloaded"
	refusedMsg  = "configuration reload refused; the running configuration is unchanged"
)

// reloadRelay is one running Relay started from a rewritable relay.toml.
type reloadRelay struct {
	t      *testing.T
	layout *relaytest.RelayLayout
	proc   *relaytest.RelayProcess
	addr   string
	path   string
}

// reloadBody is the configuration a reload test writes: the layout's minimal one, with the
// pieces a bind-time test changes held in fields.
type reloadBody struct {
	addr         string
	nodeExtra    string // lines inside [node_plane]
	caDir        string // empty: the layout's
	storePath    string // empty: the layout's
	hostname     string // empty: localhost
	sections     string // further sections
	controlPlane string // a [control_plane] table, or ""
}

func (r *reloadRelay) body(b reloadBody) string {
	if b.addr == "" {
		b.addr = r.addr
	}
	if b.caDir == "" {
		b.caDir = filepath.Join(r.layout.StateDir(), "ca")
	}
	if b.storePath == "" {
		b.storePath = filepath.Join(r.layout.StateDir(), "relay.db")
	}
	if b.hostname == "" {
		b.hostname = "localhost"
	}
	return "[node_plane]\nlisten_address = \"" + b.addr + "\"\n" + b.nodeExtra +
		"\n[ca]\ndir = \"" + b.caDir + "\"\n\n[store]\npath = \"" + b.storePath + "\"\n\n" +
		"[tls]\nhostname = \"" + b.hostname + "\"\n\n" + b.controlPlane + b.sections
}

func startReloadable(t *testing.T, sections string) *reloadRelay {
	t.Helper()
	bin, layout := shippableLayout(t)
	r := &reloadRelay{t: t, layout: layout, addr: freeAddr(t)}
	r.path = layout.WriteFile(t, "relay.toml", r.body(reloadBody{sections: sections}), "root", relaytest.TestUser, "0640")
	r.proc = startShippable(t, layout, bin, "--config", r.path)
	waitForRelayLog(t, r.proc, "relay listening")
	return r
}

// rewrite replaces relay.toml as owner:group with mode, as an operator's config management does.
func (r *reloadRelay) rewrite(body, owner, group, mode string) {
	r.t.Helper()
	r.layout.WriteFile(r.t, "relay.toml", body, owner, group, mode)
}

// rewriteRoot is rewrite as the file the Relay accepts: root:relaytest 0640.
func (r *reloadRelay) rewriteRoot(body string) {
	r.t.Helper()
	r.rewrite(body, "root", relaytest.TestUser, "0640")
}

func (r *reloadRelay) hup() {
	r.t.Helper()
	if err := r.proc.Signal(syscall.SIGHUP); err != nil {
		r.t.Fatal(err)
	}
}

// waitForLogCount blocks until the Relay's log holds want at least n times.
func (r *reloadRelay) waitForLogCount(want string, n int) {
	r.t.Helper()
	deadline := time.After(15 * time.Second)
	for strings.Count(r.proc.Log(), want) < n {
		select {
		case <-r.proc.Done():
			r.t.Fatalf("relay exited while waiting for %q x%d: %v\n%s", want, n, r.proc.Err(), r.proc.Log())
		case <-deadline:
			r.t.Fatalf("relay did not log %q x%d within 15s\n%s", want, n, r.proc.Log())
		case <-time.After(25 * time.Millisecond):
		}
	}
}

// settle waits until the log has stopped growing, so no queued reload is still to run.
func (r *reloadRelay) settle() {
	r.t.Helper()
	last, stable := len(r.proc.Log()), 0
	for stable < 10 {
		time.Sleep(50 * time.Millisecond)
		if n := len(r.proc.Log()); n != last {
			last, stable = n, 0
		} else {
			stable++
		}
	}
}

// requireAlive fails unless the Relay is running and its node-plane listener accepts.
func (r *reloadRelay) requireAlive() {
	r.t.Helper()
	select {
	case <-r.proc.Done():
		r.t.Fatalf("the Relay exited\n%s", r.proc.Log())
	default:
	}
	conn, err := net.DialTimeout("tcp", r.addr, 2*time.Second)
	if err != nil {
		r.t.Fatalf("the node-plane listener on %s does not accept: %v\n%s", r.addr, err, r.proc.Log())
	}
	conn.Close()
}

// lastJSONLine returns the last log line carrying msg, parsed as JSON.
func (r *reloadRelay) lastJSONLine(msg string) map[string]any {
	r.t.Helper()
	lines := strings.Split(r.proc.Log(), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if !strings.Contains(lines[i], msg) {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(lines[i]), &m); err != nil {
			r.t.Fatalf("the %q line is not JSON (the log handler was not swapped?): %q", msg, lines[i])
		}
		return m
	}
	r.t.Fatalf("no %q line in the log:\n%s", msg, r.proc.Log())
	return nil
}

func changedKeys(t *testing.T, line map[string]any) []string {
	t.Helper()
	raw, _ := line["changed"].([]any)
	var out []string
	for _, k := range raw {
		out = append(out, k.(string))
	}
	slices.Sort(out)
	return out
}

// records ends the Relay if it still runs, copies its store out and returns the audit records of kind.
func (r *reloadRelay) records(kind string) []audit.Record {
	r.t.Helper()
	select {
	case <-r.proc.Done():
	default:
		if err := r.proc.Kill(); err != nil {
			r.t.Fatal(err)
		}
		<-r.proc.Done()
	}
	st, err := store.Open(r.layout.CopyOutStore(r.t, filepath.Join(r.layout.StateDir(), "relay.db")))
	if err != nil {
		r.t.Fatalf("open the copied store: %v", err)
	}
	defer st.Close() //nolint:errcheck
	all, err := st.Audit().List(context.Background())
	if err != nil {
		r.t.Fatal(err)
	}
	var out []audit.Record
	for _, rec := range all {
		if rec.Kind == kind {
			out = append(out, rec)
		}
	}
	return out
}

// Proves RC-21.
func TestReload_ValidChangeAppliedAndAudited(t *testing.T) {
	r := startReloadable(t, "[reach]\nmutate_blast_cap = 5\n\n[log]\nlevel = \"info\"\n")

	r.rewriteRoot(r.body(reloadBody{sections: "[reach]\nmutate_blast_cap = 7\n\n[log]\nlevel = \"debug\"\n"}))
	r.hup()
	r.waitForLogCount(reloadedMsg, 1)

	line := r.lastJSONLine(reloadedMsg)
	if got, want := changedKeys(t, line), []string{"log.level", "reach.mutate_blast_cap"}; !slices.Equal(got, want) {
		t.Errorf("changed = %v, want %v", got, want)
	}
	r.requireAlive()

	reloads := r.records(audit.KindConfigReload)
	if len(reloads) != 1 {
		t.Fatalf("config_reload records = %d, want 1", len(reloads))
	}
	rec := reloads[0]
	if rec.Principal != audit.PrincipalLocalHost || rec.Attribution.Verified.AccountID != "" {
		t.Errorf("attribution = %q, %+v; want local-host with no AccountID", rec.Principal, rec.Attribution.Verified)
	}
	for _, k := range []string{"log.level", "reach.mutate_blast_cap"} {
		if !strings.Contains(rec.Reason, k) {
			t.Errorf("Reason %q does not name %s", rec.Reason, k)
		}
	}
	if refused := r.records(audit.KindConfigReloadRefused); len(refused) != 0 {
		t.Errorf("config_reload_refused records = %d, want 0", len(refused))
	}
}

// Proves RC-21.
func TestReload_InvalidValueRefusedConfigIntact(t *testing.T) {
	r := startReloadable(t, "[reach]\nmutate_blast_cap = 5\n\n[log]\nlevel = \"info\"\n")

	r.rewriteRoot(r.body(reloadBody{sections: "[reach]\nmutate_blast_cap = 0\n\n[log]\nlevel = \"debug\"\n"}))
	r.hup()
	r.waitForLogCount(refusedMsg, 1)
	log := r.proc.Log()
	if !strings.Contains(log, "reach.mutate_blast_cap") {
		t.Errorf("the refusal does not name reach.mutate_blast_cap:\n%s", log)
	}
	if strings.Contains(log, reloadedMsg) {
		t.Errorf("a refused reload logged %q", reloadedMsg)
	}

	// The refused reload applied nothing: log.level is still a change for the next one.
	r.rewriteRoot(r.body(reloadBody{sections: "[reach]\nmutate_blast_cap = 5\n\n[log]\nlevel = \"debug\"\n"}))
	r.hup()
	r.waitForLogCount(reloadedMsg, 1)
	if got, want := changedKeys(t, r.lastJSONLine(reloadedMsg)), []string{"log.level"}; !slices.Equal(got, want) {
		t.Errorf("changed = %v, want %v", got, want)
	}

	refused := r.records(audit.KindConfigReloadRefused)
	if len(refused) != 1 || !strings.Contains(refused[0].Reason, "the configuration file was refused") {
		t.Fatalf("config_reload_refused records = %+v, want one naming the file refusal", refused)
	}
	if strings.Contains(refused[0].Reason, "mutate_blast_cap") {
		t.Errorf("the refusal Reason names a setting the file refusal does not know: %q", refused[0].Reason)
	}
	if n := len(r.records(audit.KindConfigReload)); n != 1 {
		t.Errorf("config_reload records = %d, want 1", n)
	}
}

// Proves RC-21.
func TestReload_BindTimeChangeRefusedRestartRequired(t *testing.T) {
	r := startReloadable(t, "")
	state := r.layout.StateDir()
	cp := func() string { return "[control_plane]\nenabled = true\nlisten_address = \"" + freeAddr(t) + "\"\n\n" }
	oauth := "[oauth]\nissuer = \"https://idp.example.test\"\naudience = \"https://relay.example.test/mcp\"\npublic_url = \"https://relay.example.test\"\n"

	for _, tc := range []struct {
		key  string
		body reloadBody
	}{
		{"node_plane.listen_address", reloadBody{addr: freeAddr(t)}},
		{"node_plane.advertised_address", reloadBody{nodeExtra: "advertised_address = \"localhost:7999\"\n"}},
		{"ca.dir", reloadBody{caDir: filepath.Join(state, "ca-elsewhere")}},
		{"store.path", reloadBody{storePath: filepath.Join(state, "elsewhere.db")}},
		{"tls.hostname", reloadBody{hostname: "other.example.test"}},
		{"control_plane.enabled", reloadBody{controlPlane: cp()}},
		{"console.enabled", reloadBody{controlPlane: cp(), sections: "[console]\nenabled = true\n"}},
		{"oauth.issuer", reloadBody{controlPlane: cp(), sections: oauth}},
	} {
		t.Run(tc.key, func(t *testing.T) {
			before := strings.Count(r.proc.Log(), refusedMsg)
			mark := len(r.proc.Log())
			r.rewriteRoot(r.body(tc.body))
			r.hup()
			r.waitForLogCount(refusedMsg, before+1)

			if out := r.proc.Log()[mark:]; !strings.Contains(out, "configuration reload refused: restart required") || !strings.Contains(out, `"setting":"`+tc.key+`"`) {
				t.Errorf("no restart-required refusal naming %s:\n%s", tc.key, out)
			}
			r.requireAlive()
		})
	}

	if n := len(r.records(audit.KindConfigReload)); n != 0 {
		t.Errorf("config_reload records = %d, want 0: no bind-time change may apply", n)
	}
	refused := r.records(audit.KindConfigReloadRefused)
	if len(refused) != 8 {
		t.Fatalf("config_reload_refused records = %d, want 8", len(refused))
	}
	for i, key := range []string{"node_plane.listen_address", "node_plane.advertised_address", "ca.dir", "store.path", "tls.hostname", "control_plane.enabled", "console.enabled", "oauth.issuer"} {
		if !strings.Contains(refused[i].Reason, key) {
			t.Errorf("refusal %d Reason = %q, want it to name %s", i, refused[i].Reason, key)
		}
	}
}

// malformedGateRule is a gate rule the loader refuses at the value stage, after the file check.
const malformedGateRule = "[[approval.rules]]\nname = \"a\"\nchannel = \"in-band\"\n"

// Proves RC-21.
func TestReload_FailedReloadProcessSurvives(t *testing.T) {
	r := startReloadable(t, "")

	r.rewriteRoot("this is [not toml")
	r.hup()
	r.waitForLogCount(refusedMsg, 1)
	r.requireAlive()

	r.rewriteRoot(r.body(reloadBody{sections: malformedGateRule}))
	r.hup()
	r.waitForLogCount(refusedMsg, 2)
	r.requireAlive()

	for range 5 {
		r.hup()
	}
	r.waitForLogCount(refusedMsg, 3)
	r.settle()
	r.requireAlive()

	// The watcher is still alive: a valid file reloads.
	r.rewriteRoot(r.body(reloadBody{sections: "[reach]\nmutate_blast_cap = 9\n"}))
	r.hup()
	r.waitForLogCount(reloadedMsg, 1)
	r.requireAlive()
}

// Proves RC-21.
func TestReload_RechecksFileFirst(t *testing.T) {
	r := startReloadable(t, "")
	bad := r.body(reloadBody{sections: malformedGateRule + "\n[reach]\nmutate_blast_cap = 0\n"})

	for _, tc := range []struct{ name, owner, group, mode, want string }{
		{"owned by the Relay", relaytest.TestUser, relaytest.TestUser, "0640", "the Relay owns it on a filesystem mounted writable"},
		{"world-readable", "root", relaytest.TestUser, "0644", r.path},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := strings.Count(r.proc.Log(), refusedMsg)
			mark := len(r.proc.Log())
			r.rewrite(bad, tc.owner, tc.group, tc.mode)
			r.hup()
			r.waitForLogCount(refusedMsg, before+1)

			out := r.proc.Log()[mark:]
			wantInOutput(t, out, r.path, tc.want)
			// The file check ran before decode, validation and the files the configuration names.
			for _, notYet := range []string{"mutate_blast_cap", "approval.rules"} {
				if strings.Contains(out, notYet) {
					t.Errorf("the refusal names %q, so something past the file check ran first:\n%s", notYet, out)
				}
			}
			r.requireAlive()
		})
	}

	r.rewriteRoot(r.body(reloadBody{sections: "[reach]\nmutate_blast_cap = 9\n"}))
	r.hup()
	r.waitForLogCount(reloadedMsg, 1)
}

// TestReload_AuditNamesSecretKeyNotValue is RC-18's reload clause: a rotated webhook URL and
// secret appear on the log and the trail by key, never by value. A secret file rewritten in
// place, under the same path, is a change as well.
func TestReload_AuditNamesSecretKeyNotValue(t *testing.T) {
	banned := []string{"hook-token", "s3cr3t", "127.0.0.1:1"}
	// The mode and owner the file check accepts, as the daemon's secrets are placed.
	place := func(r *reloadRelay, name, body string) string {
		return r.layout.WriteFile(r.t, name, body, "root", relaytest.TestUser, "0640")
	}
	bin, layout := shippableLayout(t)
	r := &reloadRelay{t: t, layout: layout, addr: freeAddr(t)}
	urlA := place(r, "webhook-url-a", "http://127.0.0.1:1/hook-token-A\n")
	secretA := place(r, "webhook-secret-a", "s3cr3t-A\n")
	files := func(url, secret string) string {
		return "[approval]\nwebhook_url_file = \"" + url + "\"\nwebhook_secret_file = \"" + secret + "\"\n"
	}
	r.path = layout.WriteFile(t, "relay.toml", r.body(reloadBody{sections: files(urlA, secretA)}), "root", relaytest.TestUser, "0640")
	r.proc = startShippable(t, layout, bin, "--config", r.path)
	waitForRelayLog(t, r.proc, "relay listening")

	urlB := place(r, "webhook-url-b", "http://127.0.0.1:1/hook-token-B\n")
	secretB := place(r, "webhook-secret-b", "s3cr3t-B\n")
	r.rewriteRoot(r.body(reloadBody{sections: files(urlB, secretB)}))
	r.hup()
	r.waitForLogCount(reloadedMsg, 1)
	if got, want := changedKeys(t, r.lastJSONLine(reloadedMsg)), []string{"approval.webhook_secret_file", "approval.webhook_url_file"}; !slices.Equal(got, want) {
		t.Errorf("changed = %v, want %v", got, want)
	}

	// The secrets agent rewrites the secret file in place: same path, new content.
	place(r, "webhook-secret-b", "s3cr3t-C\n")
	r.hup()
	r.waitForLogCount(reloadedMsg, 2)
	if got, want := changedKeys(t, r.lastJSONLine(reloadedMsg)), []string{"approval.webhook_secret_file"}; !slices.Equal(got, want) {
		t.Errorf("in-place rewrite: changed = %v, want %v", got, want)
	}

	log := r.proc.Log()
	for _, b := range banned {
		if strings.Contains(log, b) {
			t.Errorf("the log carries %q:\n%s", b, log)
		}
	}
	reloads := r.records(audit.KindConfigReload)
	if len(reloads) != 2 {
		t.Fatalf("config_reload records = %d, want 2", len(reloads))
	}
	for _, rec := range reloads {
		if !strings.Contains(rec.Reason, "approval.webhook_secret_file") {
			t.Errorf("Reason %q does not name approval.webhook_secret_file", rec.Reason)
		}
	}
	for _, kind := range []string{audit.KindConfigReload, audit.KindConfigReloadRefused} {
		for _, rec := range r.records(kind) {
			for _, b := range banned {
				if strings.Contains(rec.Reason, b) {
					t.Errorf("a %s record carries %q: %q", kind, b, rec.Reason)
				}
			}
		}
	}
}
