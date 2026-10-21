package main

import (
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// unitDirectives parses a systemd unit file into section -> key -> values, in
// file order. It supports no line continuation and fails closed on one, so a
// directive cannot be hidden from the assertions below by a trailing backslash.
func unitDirectives(t *testing.T, file string) map[string]map[string][]string {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	out := map[string]map[string][]string{}
	section := ""
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";"):
			continue
		case strings.HasSuffix(line, "\\"):
			t.Fatalf("%s:%d: line continuation is not parsed; keep the unit one directive per line", file, i+1)
		case strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]"):
			section = line[1 : len(line)-1]
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("%s:%d: not a directive: %q", file, i+1, raw)
		}
		if out[section] == nil {
			out[section] = map[string][]string{}
		}
		key = strings.TrimSpace(key)
		out[section][key] = append(out[section][key], strings.TrimSpace(value))
	}
	return out
}

// TestRelayUnit_UnprivilegedNoCapsReadOnly is RC-6: the shipped relay.service
// runs as an unprivileged account with an empty capability set and a read-only
// filesystem outside its state directory.
//
// It reads the unit as text; there is no systemd, root or Docker here. Each
// check is on the directive's presence and shape, so a later assignment that
// would add privilege back (a second CapabilityBoundingSet, a "+" Exec prefix,
// a ReadWritePaths) fails rather than being modelled.
func TestRelayUnit_UnprivilegedNoCapsReadOnly(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	unit := filepath.Join(filepath.Dir(thisFile), "..", "..", "packaging", "relay.service")
	svc := unitDirectives(t, unit)["Service"]
	if len(svc) == 0 {
		t.Fatalf("%s has no [Service] directives (RC-6)", unit)
	}

	only := func(key string) (string, bool) {
		v := svc[key]
		if len(v) != 1 {
			t.Errorf("%s= occurs %d times, want exactly once (RC-6)", key, len(v))
			return "", false
		}
		return v[0], true
	}
	absent := func(keys ...string) {
		for _, key := range keys {
			if v, present := svc[key]; present {
				t.Errorf("%s=%q is set; the unit must not carry it (RC-6)", key, v)
			}
		}
	}
	equals := func(key, want string) {
		if v, ok := only(key); ok && v != want {
			t.Errorf("%s=%q, want %q (RC-6)", key, v, want)
		}
	}

	// An unprivileged account.
	for _, key := range []string{"User", "Group"} {
		if v, ok := only(key); ok && (v == "" || v == "root" || v == "0") {
			t.Errorf("%s=%q is not an unprivileged account (RC-6)", key, v)
		}
	}
	absent("SupplementaryGroups", "PermissionsStartOnly")
	for key, values := range svc {
		if !strings.HasPrefix(key, "Exec") {
			continue
		}
		for _, v := range values {
			prefix, _, _ := strings.Cut(v, "/")
			if strings.ContainsAny(prefix, "+!") {
				t.Errorf("%s=%q runs with full privileges or outside the sandbox (RC-6)", key, v)
			}
		}
	}
	if start, ok := only("ExecStart"); ok {
		command := strings.TrimLeft(start, "@-:")
		fields := strings.Fields(command)
		switch {
		case len(fields) == 0 || !strings.HasPrefix(fields[0], "/"):
			t.Errorf("ExecStart=%q does not start with an absolute path (RC-6)", start)
		default:
			switch base := path.Base(fields[0]); base {
			case "sudo", "su", "doas", "runuser", "setpriv", "capsh":
				t.Errorf("ExecStart=%q runs through %s, which changes identity or capabilities (RC-6)", start, base)
			}
		}
	}

	// An empty capability set.
	equals("CapabilityBoundingSet", "")
	if _, present := svc["AmbientCapabilities"]; present {
		equals("AmbientCapabilities", "")
	}
	equals("NoNewPrivileges", "yes")

	// A read-only filesystem outside the state directory.
	equals("ProtectSystem", "strict")
	equals("StateDirectory", "relay")
	absent("ReadWritePaths", "ReadWriteDirectories", "BindPaths", "TemporaryFileSystem",
		"RuntimeDirectory", "CacheDirectory", "LogsDirectory", "ConfigurationDirectory")
	for _, key := range []string{"ProtectHome", "PrivateTmp", "PrivateDevices", "ProtectKernelTunables", "ProtectControlGroups"} {
		equals(key, "yes")
	}
}
