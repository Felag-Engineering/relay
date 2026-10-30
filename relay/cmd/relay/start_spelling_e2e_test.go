//go:build integration

package main

import (
	"strings"
	"testing"
)

// TestStart_RefusesCaseVariantKey is RC-54 on the shippable binary: a key spelled in another
// case than the schema's refuses start, naming the key as written and never its value.
//
// Proves RC-54.
func TestStart_RefusesCaseVariantKey(t *testing.T) {
	bin, layout := shippableLayout(t)
	cfg := layout.WriteConfig(t, layoutTOML(layout, freeAddr(t), "\n[oauth]\nIssuer = \"https://CANARY.example\"\n"))
	out := refusedStart(t, layout, bin, cfg)
	wantInOutput(t, out, "it is written oauth.Issuer")
	if strings.Contains(out, "CANARY") {
		t.Errorf("the refusal echoes the value:\n%s", out)
	}
}
