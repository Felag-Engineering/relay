package relayconfig

import (
	"bytes"
	"errors"
	"reflect"

	toml "github.com/pelletier/go-toml/v2"
)

// document is the decode target: the file's schema, one struct per section.
// Every leaf is a pointer so an absent key is told from a present one (an
// empty value is never a quiet "off"). Durations stay strings and are parsed in
// validation, so a bad one is reported in this package's words.
type document struct {
	NodePlane    nodePlaneDoc    `toml:"node_plane"`
	ControlPlane controlPlaneDoc `toml:"control_plane"`
	Console      consoleDoc      `toml:"console"`
	CA           caDoc           `toml:"ca"`
	Store        storeDoc        `toml:"store"`
	TLS          tlsDoc          `toml:"tls"`
	OAuth        oauthDoc        `toml:"oauth"`
	Approval     approvalDoc     `toml:"approval"`
	Log          logDoc          `toml:"log"`
	Reach        reachDoc        `toml:"reach"`
	Enrollment   enrollmentDoc   `toml:"enrollment"`
}

type nodePlaneDoc struct {
	ListenAddress     *string `toml:"listen_address"`
	AdvertisedAddress *string `toml:"advertised_address"`
}

type controlPlaneDoc struct {
	Enabled       *bool   `toml:"enabled"`
	ListenAddress *string `toml:"listen_address"`
}

type consoleDoc struct {
	Enabled       *bool   `toml:"enabled"`
	SessionMaxAge *string `toml:"session_max_age"`
	SessionIdle   *string `toml:"session_idle"`
	StepUpWindow  *string `toml:"step_up_window"`
}

type caDoc struct {
	Dir *string `toml:"dir"`
}

type storeDoc struct {
	Path *string `toml:"path"`
}

type tlsDoc struct {
	Hostname   *string   `toml:"hostname"`
	ExtraNames *[]string `toml:"extra_names"`
}

type oauthDoc struct {
	Issuer        *string `toml:"issuer"`
	Audience      *string `toml:"audience"`
	AccountClaim  *string `toml:"account_claim"`
	RequiredScope *string `toml:"required_scope"`
	PublicURL     *string `toml:"public_url"`
}

type approvalDoc struct {
	GateRulesPath     *string `toml:"gate_rules_path"`
	WebhookURL        *string `toml:"webhook_url"`
	WebhookURLFile    *string `toml:"webhook_url_file"`
	WebhookSecret     *string `toml:"webhook_secret"`
	WebhookSecretFile *string `toml:"webhook_secret_file"`
	WebhookTimeout    *string `toml:"webhook_timeout"`
}

type logDoc struct {
	Level  *string `toml:"level"`
	Format *string `toml:"format"`
}

type reachDoc struct {
	ReadBlastCap        *int    `toml:"read_blast_cap"`
	MutateBlastCap      *int    `toml:"mutate_blast_cap"`
	DispatchConcurrency *int    `toml:"dispatch_concurrency"`
	MinDaemonVersion    *string `toml:"min_daemon_version"`
}

type enrollmentDoc struct {
	IPRatePerMinute      *int     `toml:"ip_rate_per_minute"`
	IPBurst              *int     `toml:"ip_burst"`
	GlobalRatePerMinute  *int     `toml:"global_rate_per_minute"`
	GlobalBurst          *int     `toml:"global_burst"`
	MaxTrackedIPs        *int     `toml:"max_tracked_ips"`
	MaxNodes             *int     `toml:"max_nodes"`
	CertExpiringFraction *float64 `toml:"cert_expiring_fraction"`
}

// decode parses data strictly: an unknown key is refused. The library's own
// error text embeds values and source lines, so it is never used; each failure
// is mapped to a key, a line and a Reason this package wrote.
func decode(data []byte) (document, []*Error) {
	var doc document
	err := toml.NewDecoder(bytes.NewReader(data)).DisallowUnknownFields().Decode(&doc)
	if err == nil {
		return doc, nil
	}
	var strict *toml.StrictMissingError
	if errors.As(err, &strict) {
		errs := make([]*Error, 0, len(strict.Errors))
		for i := range strict.Errors {
			line, _ := strict.Errors[i].Position()
			parts := strict.Errors[i].Key()
			key, ok := safeKey(parts)
			reason := "is not a setting the Relay reads"
			if !ok {
				reason = unrecognised(parts, "is not a setting the Relay reads")
			}
			errs = append(errs, &Error{Key: key, Line: line, Reason: reason})
		}
		return doc, errs
	}
	var derr *toml.DecodeError
	if errors.As(err, &derr) {
		line, _ := derr.Position()
		key, ok := safeKey(derr.Key())
		if full, ok := safeKey(keyLines(data).repeats[line]); ok {
			return doc, []*Error{{Key: full, Line: line, Reason: "is set twice"}}
		}
		switch {
		case ok:
			return doc, []*Error{{Key: key, Line: line, Reason: "is malformed or has the wrong type"}}
		case len(derr.Key()) == 0:
			return doc, []*Error{{Line: line, Reason: "is not valid TOML"}}
		default:
			return doc, []*Error{{Line: line, Reason: unrecognised(derr.Key(), "is malformed or has the wrong type")}}
		}
	}
	return doc, []*Error{{Reason: "the configuration could not be decoded"}}
}

// sections is the set of section names the schema has.
var sections = func() map[string]bool {
	set := map[string]bool{}
	dt := reflect.TypeFor[document]()
	for i := range dt.NumField() {
		set[dt.Field(i).Tag.Get("toml")] = true
	}
	return set
}()

// schemaKeySet is schemaKeys as a set.
var schemaKeySet = func() map[string]bool {
	set := map[string]bool{}
	for _, k := range schemaKeys() {
		set[k] = true
	}
	return set
}()

// schemaKeys returns "section.key" for every leaf of the schema, in
// declaration order.
func schemaKeys() []string {
	var keys []string
	dt := reflect.TypeFor[document]()
	for i := range dt.NumField() {
		section := dt.Field(i)
		st := section.Type
		for j := range st.NumField() {
			keys = append(keys, section.Tag.Get("toml")+"."+st.Field(j).Tag.Get("toml"))
		}
	}
	return keys
}
