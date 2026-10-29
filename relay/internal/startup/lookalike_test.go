package startup

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The look-alike literals a production file could write: Go assigns an unnamed struct literal
// to a named struct type with the same fields, without naming or importing it. Each is built
// as a package main outside the startup and ca trees, through an overlay, so nothing is
// written into the source tree.
const lookalikeHeader = `package main

import (
	"crypto/ecdsa"

	"github.com/Felag-Engineering/relay/relay/internal/ca"
	"github.com/Felag-Engineering/relay/relay/internal/startup"
)

var (
	_ *ecdsa.PrivateKey
	_ *ca.CA
	_ startup.Files
)

func main() {
`

var lookalikes = map[string]string{
	"ca.FromMaterial": `	_, _ = ca.FromMaterial(struct {
		Key     *ecdsa.PrivateKey
		CertDER []byte
	}{})
`,
	"ca.FromMaterial with a blank field": `	_, _ = ca.FromMaterial(struct {
		Key     *ecdsa.PrivateKey
		CertDER []byte
		_       struct{}
	}{})
`,
	"startup.FromSealed": `	_, _ = startup.FromSealed(struct {
		CA           *ca.CA
		StorePath    string
		RecheckStore func() error
	}{StorePath: "/x", RecheckStore: func() error { return nil }})
`,
	"startup.FromSealed with a blank field": `	_, _ = startup.FromSealed(struct {
		CA           *ca.CA
		StorePath    string
		RecheckStore func() error
		_            struct{}
	}{StorePath: "/x", RecheckStore: func() error { return nil }})
`,
}

// buildWithOverlay builds a package main at <module>/cmd/zz-lookalike holding body, with the
// given files of the module replaced by new contents, and returns the build's output and error.
func buildWithOverlay(t *testing.T, body string, replace map[string]string) (string, error) {
	t.Helper()
	module, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	overlay := map[string]string{}
	add := func(target, content string) {
		src := filepath.Join(tmp, strings.ReplaceAll(strings.TrimPrefix(target, module), "/", "_"))
		if err := os.WriteFile(src, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		overlay[target] = src
	}
	add(filepath.Join(module, "cmd", "zz-lookalike", "main.go"), lookalikeHeader+body+"}\n")
	for rel, content := range replace {
		add(filepath.Join(module, rel), content)
	}
	data, err := json.Marshal(map[string]any{"Replace": overlay})
	if err != nil {
		t.Fatal(err)
	}
	overlayFile := filepath.Join(tmp, "overlay.json")
	if err := os.WriteFile(overlayFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("this test builds the module and needs go on PATH: %v", err)
	}
	cmd := exec.Command(goBin, "build", "-overlay", overlayFile,
		"-o", os.DevNull, "./cmd/zz-lookalike")
	cmd.Dir = module
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestLookalikeLiteralsDoNotCompile: outside the startup and ca trees, no struct literal can
// stand in for sealed.Files or material.Material, so startup.FromSealed and ca.FromMaterial
// can be handed only a zero value from production code. The positive control removes the
// non-exported field that seals each type and shows the look-alike then compiles, so the test
// fails if the seal goes.
func TestLookalikeLiteralsDoNotCompile(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the module")
	}
	for name, body := range lookalikes {
		t.Run(name, func(t *testing.T) {
			out, err := buildWithOverlay(t, body, nil)
			if err == nil {
				t.Fatalf("a look-alike literal for %s compiled outside its package", name)
			}
			if !strings.Contains(out, "cannot use") {
				t.Fatalf("the build failed, but not on the literal's type:\n%s", out)
			}
		})
	}

	unseal := func(t *testing.T, rel string) map[string]string {
		t.Helper()
		module := filepath.Join("..", "..")
		data, err := os.ReadFile(filepath.Join(module, rel))
		if err != nil {
			t.Fatal(err)
		}
		const field = "\t_ struct{}\n"
		if !strings.Contains(string(data), field) {
			t.Fatalf("%s has no sealing field", rel)
		}
		return map[string]string{rel: strings.Replace(string(data), field, "", 1)}
	}
	for name, rel := range map[string]string{
		"ca.FromMaterial":    "internal/ca/internal/material/material.go",
		"startup.FromSealed": "internal/startup/internal/sealed/sealed.go",
	} {
		t.Run("positive control: "+name+" unsealed", func(t *testing.T) {
			if out, err := buildWithOverlay(t, lookalikes[name], unseal(t, rel)); err != nil {
				t.Fatalf("with the seal removed the look-alike still did not compile, so this test proves nothing:\n%s", out)
			}
		})
	}
}
