package relayconfig

import (
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
		{"console", "session_max_age", `"0s"`},
		{"console", "session_idle", `"-5m"`},
		{"console", "step_up_window", `"16m"`},
		{"console", "step_up_window", `"soon"`},
		{"approval", "webhook_timeout", `"0s"`},
		{"approval", "gate_rules_path", `"gates.json"`},
		{"approval", "webhook_url_file", `"relative"`},
		{"log", "level", `"verbose"`},
		{"log", "format", `"xml"`},
		{"reach", "read_blast_cap", `0`},
		{"reach", "mutate_blast_cap", `-1`},
		{"reach", "dispatch_concurrency", `0`},
		{"reach", "min_daemon_version", `"latest"`},
		{"enrollment", "ip_rate_per_minute", `0`},
		{"enrollment", "ip_burst", `0`},
		{"enrollment", "global_rate_per_minute", `0`},
		{"enrollment", "global_burst", `0`},
		{"enrollment", "max_tracked_ips", `0`},
		{"enrollment", "max_nodes", `-1`},
		{"enrollment", "cert_expiring_fraction", `0.0`},
		{"enrollment", "cert_expiring_fraction", `1.5`},
		{"enrollment", "cert_expiring_fraction", `nan`},
		{"enrollment", "cert_expiring_fraction", `inf`},
		{"enrollment", "cert_expiring_fraction", `-inf`},
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

func TestValidate_CertExpiringFractionAcceptsIntegerOne(t *testing.T) {
	// 1 is inside (0, 1]; the TOML integer spelling decodes into the float.
	cfg := mustLoad(t, minimal+"[enrollment]\ncert_expiring_fraction = 1\n")
	if cfg.Enrollment.CertExpiringFraction != 1 {
		t.Fatalf("fraction = %v", cfg.Enrollment.CertExpiringFraction)
	}
}

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

func TestValidate_OAuthIssuerNeedsAudienceAndPublicURL(t *testing.T) {
	got := loadErr(t, minimal+controlOn+"[oauth]\nissuer = \"https://idp.example.com\"\n")
	for _, want := range []string{"oauth.audience", "oauth.public_url"} {
		if !strings.Contains(got, want) {
			t.Errorf("error does not name %s: %q", want, got)
		}
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

func TestValidate_WebhookSettingsWithoutURLRefused(t *testing.T) {
	for _, key := range []string{"webhook_secret = \"v\"", "webhook_secret_file = \"/etc/relay/s\"", "webhook_timeout = \"3s\""} {
		t.Run(key, func(t *testing.T) {
			got := loadErr(t, minimal+"[approval]\n"+key+"\n")
			name := "approval." + strings.Fields(key)[0]
			if !strings.Contains(got, name+" (line 8)") || !strings.Contains(got, "approval.webhook_url") {
				t.Fatalf("error = %q", got)
			}
		})
	}
}

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

func TestValidate_AdvertisedHostMustBeCertificateHostname(t *testing.T) {
	t.Run("another host is refused without naming either", func(t *testing.T) {
		got := loadErr(t, minimal+"[node_plane]\nadvertised_address = \"other.example.org:7654\"\n")
		if !strings.Contains(got, "node_plane.advertised_address (line 8)") || !strings.Contains(got, "tls.hostname") {
			t.Fatalf("error = %q", got)
		}
		for _, host := range []string{"other.example.org", "relay.example.internal"} {
			if strings.Contains(got, host) {
				t.Errorf("error names the host %q: %q", host, got)
			}
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
