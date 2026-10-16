package hostfile

import (
	"strings"
	"testing"
)

const statusFixture = `Name:	relay
Umask:	0022
State:	S (sleeping)
Uid:	990	990	990	990
CapInh:	0000000000000010
CapPrm:	0000000000000000
CapEff:	00000000a80425fb
CapBnd:	000001ffffffffff
CapAmb:	0000000000000400
NoNewPrivs:	0
`

func TestParseCapabilities(t *testing.T) {
	inh, prm, eff, amb, err := parseCapabilities(strings.NewReader(statusFixture))
	if err != nil {
		t.Fatal(err)
	}
	if inh != 0x10 || prm != 0 || eff != 0xa80425fb || amb != 0x400 {
		t.Fatalf("got %x %x %x %x", inh, prm, eff, amb)
	}
}

func TestParseCapabilities_Refuses(t *testing.T) {
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		var kept []string
		for _, l := range strings.Split(statusFixture, "\n") {
			if !strings.HasPrefix(l, key+":") {
				kept = append(kept, l)
			}
		}
		if _, _, _, _, err := parseCapabilities(strings.NewReader(strings.Join(kept, "\n"))); err == nil {
			t.Errorf("missing %s: want an error", key)
		}
		bad := strings.Replace(statusFixture, key+":\t", key+":\tzz", 1)
		if _, _, _, _, err := parseCapabilities(strings.NewReader(bad)); err == nil {
			t.Errorf("bad hex in %s: want an error", key)
		}
	}
}
