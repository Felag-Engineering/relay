package relayconfig

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestValidate_EachRequiredSettingNamed(t *testing.T) {
	required := []struct{ key, section, name string }{
		{"ca.dir", "ca", "dir"},
		{"store.path", "store", "path"},
		{"tls.hostname", "tls", "hostname"},
	}
	full := map[string]string{
		"ca.dir":       `"/var/lib/relay/ca"`,
		"store.path":   `"/var/lib/relay/relay.db"`,
		"tls.hostname": `"relay.example.internal"`,
	}
	build := func(override map[string]string) string {
		var b strings.Builder
		for _, r := range required {
			val, ok := full[r.key], true
			if o, set := override[r.key]; set {
				val, ok = o, o != "<absent>"
			}
			b.WriteString("[" + r.section + "]\n")
			if ok {
				b.WriteString(r.name + " = " + val + "\n")
			}
		}
		return b.String()
	}

	for _, r := range required {
		t.Run(r.key+" dropped", func(t *testing.T) {
			got := loadErr(t, build(map[string]string{r.key: "<absent>"}))
			if !strings.Contains(got, r.key+": must be set") {
				t.Fatalf("error = %q", got)
			}
		})
		t.Run(r.key+" empty", func(t *testing.T) {
			got := loadErr(t, build(map[string]string{r.key: `""`}))
			if !strings.Contains(got, r.key+" (line") || !strings.Contains(got, "must not be empty") {
				t.Fatalf("error = %q", got)
			}
		})
	}
	t.Run("an empty document names all three", func(t *testing.T) {
		got := loadErr(t, "")
		for _, r := range required {
			if !strings.Contains(got, r.key) {
				t.Errorf("error does not name %s: %q", r.key, got)
			}
		}
	})
}

// Proves RC-22.
func TestValidate_InvalidValueRefusedNamingSetting(t *testing.T) {
	cases := []struct{ section, key, value string }{
		{"node_plane", "listen_address", `":0"`},
		{"node_plane", "listen_address", `":70000"`},
		{"node_plane", "listen_address", `"7654"`},
		{"control_plane", "listen_address", `":http"`},
		{"ca", "dir", `"relative/ca"`},
		{"ca", "dir", `"/var/lib/relay/../relay/ca"`},
		{"store", "path", `"/var/lib/relay/"`},
		{"tls", "hostname", `"-bad.example"`},
		{"tls", "hostname", `"relay.example.internal:7654"`},
		{"console", "session_idle", `"-5m"`},
		{"approval", "gate_rules_path", `"gates.json"`},
		{"approval", "webhook_url_file", `"relative"`},
		{"log", "level", `"verbose"`},
		{"reach", "read_blast_cap", `0`},
		{"reach", "mutate_blast_cap", `-1`},
		{"reach", "min_daemon_version", `"latest"`},
		{"enrollment", "max_nodes", `-1`},
	}
	for _, tc := range cases {
		name := tc.section + "." + tc.key + "=" + tc.value
		t.Run(name, func(t *testing.T) {
			src := minimal
			if tc.section == "ca" || tc.section == "store" || tc.section == "tls" {
				src = "[" + tc.section + "]\n" + tc.key + " = " + tc.value + "\n" + missingOthers(tc.section)
			} else {
				src += "[" + tc.section + "]\n" + tc.key + " = " + tc.value + "\n"
			}
			got := loadErr(t, src)
			if !strings.Contains(got, tc.section+"."+tc.key+" (line") {
				t.Fatalf("error does not name the setting and line: %q", got)
			}
		})
	}

	t.Run("oauth issuer and scope", func(t *testing.T) {
		got := loadErr(t, minimal+"[control_plane]\nenabled = true\n[oauth]\nissuer = \"ftp://idp.example.com\"\nrequired_scope = \"a b\"\naudience = \"relay\"\npublic_url = \"https://r.example\"\n")
		for _, want := range []string{"oauth.issuer (line 10)", "oauth.required_scope (line 11)"} {
			if !strings.Contains(got, want) {
				t.Errorf("error does not contain %q: %q", want, got)
			}
		}
	})
}

// missingOthers supplies the required sections other than the one under test.
func missingOthers(section string) string {
	parts := map[string]string{
		"ca":    "[ca]\ndir = \"/var/lib/relay/ca\"\n",
		"store": "[store]\npath = \"/var/lib/relay/relay.db\"\n",
		"tls":   "[tls]\nhostname = \"relay.example.internal\"\n",
	}
	var b strings.Builder
	for _, k := range []string{"ca", "store", "tls"} {
		if k != section {
			b.WriteString(parts[k])
		}
	}
	return b.String()
}

// Proves RC-20.
func TestValidate_ConsoleWithoutControlPlaneRefused(t *testing.T) {
	got := loadErr(t, minimal+"[console]\nenabled = true\n")
	if !strings.Contains(got, "console.enabled (line 8)") || !strings.Contains(got, "control_plane.enabled") {
		t.Fatalf("error = %q", got)
	}
	cfg := mustLoad(t, minimal+"[control_plane]\nenabled = true\n[console]\nenabled = true\n")
	if !cfg.Console.Enabled || !cfg.ControlPlane.Enabled {
		t.Fatal("console and control plane were not both enabled")
	}
}

const controlOn = "[control_plane]\nenabled = true\n"

// Proves RC-20.
func TestValidate_OAuthWithoutIssuerRefused(t *testing.T) {
	for _, key := range []string{"audience", "account_claim", "required_scope", "public_url"} {
		t.Run(key, func(t *testing.T) {
			got := loadErr(t, minimal+controlOn+"[oauth]\n"+key+" = \"x\"\n")
			if !strings.Contains(got, "oauth."+key+" (line 10)") || !strings.Contains(got, "oauth.issuer") {
				t.Fatalf("error = %q", got)
			}
		})
	}
}

// Proves RC-10.
func TestValidate_OAuthIssuerNeedsAudienceAndPublicURL(t *testing.T) {
	const issuer = "[oauth]\nissuer = \"https://idp.example.com\"\n"
	// Each missing key is refused on its own, and the error names only that key.
	for _, tc := range []struct {
		name, tail   string
		wantNamed    []string
		wantNotNamed []string
	}{
		{"no audience", "public_url = \"https://relay.example.internal:9443\"\n",
			[]string{"oauth.audience: must be set when oauth.issuer is set"}, []string{"oauth.public_url"}},
		{"no public URL", "audience = \"relay\"\n",
			[]string{"oauth.public_url: must be set when oauth.issuer is set"}, []string{"oauth.audience"}},
		{"neither", "",
			[]string{"oauth.audience", "oauth.public_url"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := loadErr(t, minimal+controlOn+issuer+tc.tail)
			for _, want := range tc.wantNamed {
				if !strings.Contains(got, want) {
					t.Errorf("error does not name %s: %q", want, got)
				}
			}
			for _, not := range tc.wantNotNamed {
				if strings.Contains(got, not) {
					t.Errorf("error names %s, which is set: %q", not, got)
				}
			}
		})
	}
	cfg := mustLoad(t, minimal+controlOn+"[oauth]\nissuer = \"https://idp.example.com\"\naudience = \"relay\"\npublic_url = \"https://relay.example.internal:9443\"\n")
	if cfg.OAuth.Issuer == "" || cfg.OAuth.AccountClaim != "email" {
		t.Fatalf("OAuth = %+v", cfg.OAuth)
	}
}

func TestValidate_OAuthWithoutControlPlaneRefused(t *testing.T) {
	got := loadErr(t, minimal+"[oauth]\nissuer = \"https://idp.example.com\"\naudience = \"relay\"\npublic_url = \"https://r.example\"\n")
	if !strings.Contains(got, "oauth.issuer (line 8)") || !strings.Contains(got, "control_plane.enabled") {
		t.Fatalf("error = %q", got)
	}
}

func TestValidate_OAuthIssuerRequiresHTTPSUnlessLoopback(t *testing.T) {
	const reason = "must be an https URL; http is accepted only for a loopback host"
	const tail = "audience = \"relay\"\npublic_url = \"https://r.example\"\n"
	cfgFor := func(issuer string) string {
		return minimal + controlOn + "[oauth]\nissuer = \"" + issuer + "\"\n" + tail
	}
	ok := []string{
		"https://idp.example.com",
		"https://idp.example.com:8443/realms/x",
		"https://10.0.0.1/realm",
		"http://127.0.0.1",
		"http://127.0.0.1:8180/realms/x",
		"http://127.5.6.7",
		"http://[::1]",
		"http://[::1]:8080",
		"http://localhost",
		"http://localhost:8180",
	}
	for _, issuer := range ok {
		t.Run("ok "+issuer, func(t *testing.T) {
			if cfg := mustLoad(t, cfgFor(issuer)); cfg.OAuth.Issuer != issuer {
				t.Fatalf("Issuer = %q", cfg.OAuth.Issuer)
			}
		})
	}

	const sentinel = "zq9sentinel"
	refused := []struct {
		name, issuer string
		wantReason   bool
	}{
		{"http example.com", "http://" + sentinel + ".example.com", true},
		{"http 10.0.0.1", "http://10.0.0.1:8180/" + sentinel, true},
		{"http 128.0.0.1", "http://128.0.0.1/" + sentinel, true},
		{"localhost suffix", "http://localhost." + sentinel + ".example.com", true},
		{"127.0.0.1 suffix", "http://127.0.0.1." + sentinel + ".example.com", true},
		{"ftp", "ftp://" + sentinel + ".example.com", false},
		{"ws", "ws://" + sentinel + ".example.com", false},
		{"scheme-less", sentinel + ".example.com/realm", false},
	}
	for _, tc := range refused {
		t.Run("refused "+tc.name, func(t *testing.T) {
			got := loadErr(t, cfgFor(tc.issuer))
			if !strings.Contains(got, "oauth.issuer (line 10)") {
				t.Errorf("error does not name oauth.issuer and its line: %q", got)
			}
			for _, leak := range []string{sentinel, "10.0.0.1", "128.0.0.1", "127.0.0.1"} {
				if strings.Contains(got, leak) {
					t.Errorf("error carries part of the value (%s): %q", leak, got)
				}
			}
			if tc.wantReason && !strings.Contains(got, reason) {
				t.Errorf("error lacks %q: %q", reason, got)
			}
		})
	}
}

func TestValidate_WebhookSecretFileWithoutURLRefused(t *testing.T) {
	got := loadErr(t, minimal+"[approval]\nwebhook_secret_file = \"/etc/relay/s\"\n")
	if !strings.Contains(got, "approval.webhook_secret_file (line 8)") || !strings.Contains(got, "approval.webhook_url_file") {
		t.Fatalf("error = %q", got)
	}
}

// Proves RC-20.
func TestValidate_MutateCapAboveReadCapWarns(t *testing.T) {
	_, warns, err := Load([]byte(minimal + "[reach]\nread_blast_cap = 10\nmutate_blast_cap = 20\n"))
	if err != nil {
		t.Fatalf("a mutate cap above the read cap is a warning, not a refusal: %v", err)
	}
	if len(warns) != 1 || warns[0].Key != "reach.mutate_blast_cap" || warns[0].Line != 9 {
		t.Fatalf("warnings = %v", warns)
	}
	if !strings.Contains(warns[0].String(), "reach.mutate_blast_cap (line 9)") {
		t.Fatalf("warning text = %q", warns[0])
	}

	_, warns, err = Load([]byte(minimal + "[reach]\nread_blast_cap = 10\nmutate_blast_cap = 10\n"))
	if err != nil || len(warns) != 0 {
		t.Fatalf("equal caps: warns %v, err %v", warns, err)
	}
}

func TestValidate_AdvertisedHostIsANamedCertificateName(t *testing.T) {
	t.Run("another host is refused without naming either", func(t *testing.T) {
		got := loadErr(t, minimal+"[node_plane]\nadvertised_address = \"other.example.org:7654\"\n")
		for _, want := range []string{"node_plane.advertised_address (line 8)", "tls.hostname", "tls.extra_names"} {
			if !strings.Contains(got, want) {
				t.Fatalf("error does not contain %q: %q", want, got)
			}
		}
		for _, host := range []string{"other.example.org", "relay.example.internal"} {
			if strings.Contains(got, host) {
				t.Errorf("error names the host %q: %q", host, got)
			}
		}
	})
	t.Run("a host named in extra_names is accepted", func(t *testing.T) {
		for _, tc := range []struct{ extra, advertised string }{
			{`"NAT.example.org"`, "nat.example.org:7654"},
			{`"203.0.113.7"`, "203.0.113.7:7654"},
			{`"2001:DB8::7"`, "[2001:db8::7]:7654"},
		} {
			src := minimal + "extra_names = [" + tc.extra + "]\n[node_plane]\nadvertised_address = \"" + tc.advertised + "\"\n"
			if got := mustLoad(t, src).EffectiveAdvertisedAddress(); got != tc.advertised {
				t.Errorf("advertised %s with extra_names %s: address = %q", tc.advertised, tc.extra, got)
			}
		}
	})
	t.Run("a host a certificate cannot carry is refused by shape", func(t *testing.T) {
		for _, host := range []string{"*.example.org", "0.0.0.0", "[::]", "bad_host", "224.0.0.1", "010.0.0.1", "[::ffff:192.0.2.1]", "[::ffff:c000:201]", "0.1.2.3"} {
			got := loadErr(t, minimal+"[node_plane]\nadvertised_address = \""+host+":7654\"\n")
			if !strings.Contains(got, "node_plane.advertised_address (line 8)") {
				t.Errorf("%s: error does not name the setting: %q", host, got)
			}
			if strings.Contains(got, strings.Trim(host, "[]")) {
				t.Errorf("%s: error names the host: %q", host, got)
			}
		}
	})
	t.Run("a mapped advertised host is refused by shape even when its IPv4 form is named", func(t *testing.T) {
		got := loadErr(t, minimal+"extra_names = [\"192.0.2.1\"]\n[node_plane]\nadvertised_address = \"[::ffff:192.0.2.1]:7654\"\n")
		for _, want := range []string{"node_plane.advertised_address (line 9)", "not an IPv4-mapped IPv6 one"} {
			if !strings.Contains(got, want) {
				t.Errorf("error does not contain %q: %q", want, got)
			}
		}
		if strings.Contains(got, "192.0.2.1") {
			t.Errorf("error names the host: %q", got)
		}
	})
	t.Run("a bad extra_names gives no second error", func(t *testing.T) {
		got := loadErr(t, minimal+"extra_names = [\"*.example.org\"]\n[node_plane]\nadvertised_address = \"other.example.org:7654\"\n")
		if !strings.Contains(got, "tls.extra_names") || strings.Contains(got, "node_plane.advertised_address") {
			t.Fatalf("error = %q", got)
		}
	})
	t.Run("the same host in another case is accepted", func(t *testing.T) {
		cfg := mustLoad(t, minimal+"[node_plane]\nadvertised_address = \"Relay.Example.Internal:8443\"\n")
		if cfg.EffectiveAdvertisedAddress() != "Relay.Example.Internal:8443" {
			t.Fatalf("address = %q", cfg.EffectiveAdvertisedAddress())
		}
	})
	t.Run("no port is refused", func(t *testing.T) {
		got := loadErr(t, minimal+"[node_plane]\nadvertised_address = \"relay.example.internal\"\n")
		if !strings.Contains(got, "node_plane.advertised_address (line 8)") {
			t.Fatalf("error = %q", got)
		}
	})
	t.Run("unset falls back to the hostname on the listen port", func(t *testing.T) {
		if got := mustLoad(t, minimal).EffectiveAdvertisedAddress(); got != "relay.example.internal:7654" {
			t.Fatalf("address = %q", got)
		}
		cfg := mustLoad(t, minimal+"[node_plane]\nlisten_address = \"0.0.0.0:8443\"\n")
		if got := cfg.EffectiveAdvertisedAddress(); got != "relay.example.internal:8443" {
			t.Fatalf("address = %q", got)
		}
	})
}

// The join string carries tls.hostname when no address is advertised, so
// tls.hostname must pass the whole rule a certificate name does.
func TestValidate_HostnameIsACertificateName(t *testing.T) {
	cases := []struct {
		reason string
		value  string
	}{
		{"must not be a wildcard address", "0.0.0.0"},
		{"must not be a wildcard", "*.example.internal"},
		{"must be written as an IPv4 address, not an IPv4-mapped IPv6 one", "::ffff:192.0.2.1"},
		{"must not end in a numeric label", "10.0.0"},
		{reasonNotDialable, "fe80::1"},
		{reasonNotDialable, "224.0.0.1"},
		{"must be a DNS name or an IP address", "-bad.example"},
	}
	for _, tc := range cases {
		t.Run(tc.value, func(t *testing.T) {
			src := "[tls]\nhostname = " + strconv.Quote(tc.value) + "\n" + missingOthers("tls")
			got := loadErr(t, src)
			for _, want := range []string{"tls.hostname (line 2)", tc.reason} {
				if !strings.Contains(got, want) {
					t.Errorf("error does not contain %q: %q", want, got)
				}
			}
			if strings.Contains(got, tc.value) {
				t.Errorf("error carries the value: %q", got)
			}
		})
	}

	t.Run("an address or a name a daemon can dial is accepted", func(t *testing.T) {
		for _, host := range []string{"relay.example.internal", "localhost", "203.0.113.7", "2001:db8::7", "127.0.0.1"} {
			src := "[tls]\nhostname = " + strconv.Quote(host) + "\n" + missingOthers("tls")
			if got := mustLoad(t, src).TLS.Hostname; got != host {
				t.Errorf("hostname %q loaded as %q", host, got)
			}
		}
	})
}

// Proves RC-47.
func TestValidate_ExtraNamesEachEntryChecked(t *testing.T) {
	list := func(entries ...string) string {
		quoted := make([]string, len(entries))
		for i, e := range entries {
			quoted[i] = strconv.Quote(e)
		}
		return minimal + "extra_names = [" + strings.Join(quoted, ", ") + "]\n"
	}

	t.Run("accepted entries load unchanged and in order", func(t *testing.T) {
		in := []string{
			"lb.example.internal", "203.0.113.10", "2001:db8::9", "LB.Example.Internal",
			"127.0.0.1", "lb.example.internal", "3com.example.test", "10.example.test",
			"xn--bcher-kva.example",
		}
		if got := mustLoad(t, list(in...)).TLS.ExtraNames; !slices.Equal(got, in) {
			t.Fatalf("ExtraNames = %v, want %v", got, in)
		}
	})

	refused := []struct {
		reason  string
		entries []string
	}{
		{"must not be empty", []string{""}},
		{"must not be a wildcard", []string{"*.example.internal", "relay.*.internal", "*"}},
		{"must not be a wildcard address", []string{"0.0.0.0", "::"}},
		{reasonNotDialable, []string{"224.0.0.1", "ff02::1", "fe80::1", "255.255.255.255", "0.1.2.3"}},
		{"must be written as an IPv4 address, not an IPv4-mapped IPv6 one", []string{"::ffff:192.0.2.1", "::ffff:c000:201", "::FFFF:10.0.0.1"}},
		{"must not end in a numeric label", []string{"010.0.0.1", "10.0.0", "1.2.3.4.5", "0x7f.0.0.1", "0x7f000001", "4294967295"}},
		{"must be a DNS name or an IP address", []string{
			"fe80::1%eth0", "10.0.0.0/8", "lb.example.internal:7654", "[2001:db8::1]",
			"https://lb.example.internal", "bad_name.example", "lb.example.internal.",
			strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63) + ".example",
		}},
	}
	for _, tc := range refused {
		for _, entry := range tc.entries {
			t.Run(tc.reason+"/"+entry, func(t *testing.T) {
				got := loadErr(t, list("ok.example.internal", entry))
				for _, want := range []string{"tls.extra_names (line 7)", "entry 2 ", tc.reason} {
					if !strings.Contains(got, want) {
						t.Errorf("error does not contain %q: %q", want, got)
					}
				}
				if entry != "" && strings.Contains(got, entry) {
					t.Errorf("error carries the entry's text: %q", got)
				}
			})
		}
	}

	t.Run("every bad entry is reported by position", func(t *testing.T) {
		got := loadErr(t, list("*.a.example", "ok.example.internal", "bad_name"))
		for _, want := range []string{"entry 1 ", "entry 3 "} {
			if !strings.Contains(got, want) {
				t.Errorf("error does not contain %q: %q", want, got)
			}
		}
		if strings.Contains(got, "entry 2 ") {
			t.Errorf("error refuses the good entry: %q", got)
		}
	})
	t.Run("an empty list is refused", func(t *testing.T) {
		got := loadErr(t, minimal+"extra_names = []\n")
		if !strings.Contains(got, "tls.extra_names (line 7)") || !strings.Contains(got, reasonEmpty) {
			t.Fatalf("error = %q", got)
		}
	})
	t.Run("a wrong type is refused without its value", func(t *testing.T) {
		for _, body := range []string{"extra_names = [1]\n", "extra_names = \"secret-lb.example\"\n"} {
			got := loadErr(t, minimal+body)
			if !strings.Contains(got, "tls.extra_names") || strings.Contains(got, "secret-lb") {
				t.Errorf("%s: error = %q", strings.TrimSpace(body), got)
			}
		}
	})
}

// Proves RC-47.
func TestValidate_ExtraNamesCappedAt32(t *testing.T) {
	list := func(n int) string {
		entries := make([]string, n)
		for i := range entries {
			entries[i] = `"n` + strconv.Itoa(i) + `.example.internal"`
		}
		return minimal + "extra_names = [" + strings.Join(entries, ", ") + "]\n"
	}
	if got := mustLoad(t, list(32)).TLS.ExtraNames; len(got) != 32 {
		t.Fatalf("loaded %d entries, want 32", len(got))
	}
	got := loadErr(t, list(33))
	for _, want := range []string{"tls.extra_names", "at most 32"} {
		if !strings.Contains(got, want) {
			t.Errorf("error does not contain %q: %q", want, got)
		}
	}
}
