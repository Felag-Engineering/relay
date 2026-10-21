package relayconfig

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	fqdnLine         = `hostname = "@FQDN@"`
	noFQDNHostnameLn = `# hostname = "relay.example.internal"`
)

// renderPackaged applies the rendering rule the Relay package's postinst applies to
// packaging/relay.toml.in: the one hostname line becomes the host's fully qualified name, or
// is commented out when none was found.
func renderPackaged(t *testing.T, fqdn string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(packageDir(t), "..", "..", "packaging", "relay.toml.in"))
	if err != nil {
		t.Fatalf("read the packaged template: %v", err)
	}
	tmpl := string(raw)
	if n := strings.Count(tmpl, fqdnLine); n != 1 {
		t.Fatalf("the template holds %q %d times, want exactly once", fqdnLine, n)
	}
	if n := strings.Count(tmpl, "@"); n != strings.Count(fqdnLine, "@") {
		t.Fatalf("the template holds an @ outside %q", fqdnLine)
	}
	line := noFQDNHostnameLn
	if fqdn != "" {
		line = `hostname = "` + fqdn + `"`
	}
	return strings.Replace(tmpl, fqdnLine, line, 1)
}

// The configuration the package writes at first install loads, with no warning, and holds
// the settings the package promises: the CA and the store inside the state directory, the
// control plane and the Admin Console on, the control-plane listener on loopback, and the
// host's name as the certificate hostname (RC-25).
func TestPackagedRelayTOML_FirstInstallSettings(t *testing.T) {
	cfg, warns, err := Load([]byte(renderPackaged(t, "relay.example.com")))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(warns) != 0 {
		t.Errorf("warnings: %v", warns)
	}
	if !strings.HasPrefix(cfg.CA.Dir, "/var/lib/relay/") {
		t.Errorf("ca.dir = %q, want inside /var/lib/relay", cfg.CA.Dir)
	}
	if !strings.HasPrefix(cfg.Store.Path, "/var/lib/relay/") {
		t.Errorf("store.path = %q, want inside /var/lib/relay", cfg.Store.Path)
	}
	if !cfg.ControlPlane.Enabled {
		t.Error("control_plane.enabled is false")
	}
	if !cfg.Console.Enabled {
		t.Error("console.enabled is false")
	}
	host, _, err := net.SplitHostPort(cfg.ControlPlane.ListenAddress)
	if err != nil {
		t.Fatalf("control_plane.listen_address %q: %v", cfg.ControlPlane.ListenAddress, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		t.Errorf("control_plane.listen_address host %q is not a loopback address", host)
	}
	if cfg.TLS.Hostname != "relay.example.com" {
		t.Errorf("tls.hostname = %q, want relay.example.com", cfg.TLS.Hostname)
	}
}

// With no fully qualified name the package comments the hostname out, and the Relay refuses
// to load the file, naming tls.hostname (RC-19, RC-25).
func TestPackagedRelayTOML_WithoutFQDNRefusesNamingTLSHostname(t *testing.T) {
	_, _, err := Load([]byte(renderPackaged(t, "")))
	if err == nil {
		t.Fatal("Load accepted a configuration with no tls.hostname")
	}
	var e *Error
	if !errors.As(err, &e) || e.Key != "tls.hostname" {
		t.Errorf("no refusal for tls.hostname in: %v", err)
	}
	if !strings.Contains(err.Error(), "tls.hostname") {
		t.Errorf("the refusal does not name tls.hostname: %v", err)
	}
}
