package console

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Felag-Engineering/relay/relay/internal/accounts"
)

func TestAssets_HashedURLIsServedImmutable(t *testing.T) {
	h := newTestHandler(Deps{}, accounts.RoleAdmin)

	for _, tc := range []struct{ name, sentinel string }{
		{"console.css", ".navitem"},
		{"fonts/ibm-plex-sans-400.woff2", "wOF2"},
		{"accounts.js", "dialog"},
	} {
		rec := get(t, h, assetURL(tc.name))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", assetURL(tc.name), rec.Code)
		}
		if !strings.Contains(rec.Body.String(), tc.sentinel) {
			t.Errorf("%s: body does not contain %q", tc.name, tc.sentinel)
		}
		if got := rec.Header().Get("Cache-Control"); got != immutableCache {
			t.Errorf("%s: Cache-Control = %q, want %q", tc.name, got, immutableCache)
		}
	}
}

func TestAssets_UnhashedURLStaysNoStore(t *testing.T) {
	h := newTestHandler(Deps{}, accounts.RoleAdmin)

	rec := get(t, h, "/console/assets/console.css")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), ".navitem") {
		t.Fatalf("status = %d, body is not the stylesheet: %.100s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

func TestAssets_StaleHashIsNotFound(t *testing.T) {
	h := newTestHandler(Deps{}, accounts.RoleAdmin)

	const stale = "0000000000000000"
	if assetHash == stale {
		t.Fatal("the fixture hash equals the real one")
	}
	rec := get(t, h, AssetsPrefix+stale+"/console.css")
	if rec.Code != http.StatusNotFound {
		t.Errorf("stale hash: status = %d, want 404", rec.Code)
	}
	if strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Errorf("stale hash: Cache-Control = %q, must not be immutable", rec.Header().Get("Cache-Control"))
	}

	// A listing under the hash (trailing slash) is never immutable content. The
	// hashed root without its slash is not a directory the FileServer can map,
	// so it is a 404 from the unhashed branch.
	for _, p := range []string{AssetsPrefix + assetHash, AssetsPrefix + assetHash + "/", AssetsPrefix + assetHash + "/fonts/"} {
		rec := get(t, h, p)
		if strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
			t.Errorf("GET %s: Cache-Control = %q, must not be immutable", p, rec.Header().Get("Cache-Control"))
		}
	}
}

func TestAssets_MissingFileUnderCurrentHashIsNotImmutable(t *testing.T) {
	h := newTestHandler(Deps{}, accounts.RoleAdmin)

	rec := get(t, h, assetURL("nope.css"))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", rec.Code)
	}
	if strings.Contains(rec.Header().Get("Cache-Control"), "immutable") {
		t.Errorf("Cache-Control = %q, must not be immutable", rec.Header().Get("Cache-Control"))
	}
}

// A hashed directory without its slash is canonicalised by a redirect, which
// is fixed per hash and so may carry the immutable header.
func TestAssets_HashedDirectoryWithoutSlashRedirects(t *testing.T) {
	h := newTestHandler(Deps{}, accounts.RoleAdmin)

	rec := get(t, h, assetURL("fonts"))
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("status = %d, want 301", rec.Code)
	}
	if got, want := rec.Header().Get("Location"), "fonts/"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

func TestHashAssets_ChangesWithAnyByteOrName(t *testing.T) {
	hash := func(files map[string]string) string {
		t.Helper()
		m := fstest.MapFS{}
		for name, body := range files {
			m[name] = &fstest.MapFile{Data: []byte(body)}
		}
		got, err := hashAssets(m)
		if err != nil {
			t.Fatalf("hashAssets: %v", err)
		}
		return got
	}

	base := hash(map[string]string{"a.css": "body{}", "f/b.js": "x"})
	if again := hash(map[string]string{"a.css": "body{}", "f/b.js": "x"}); again != base {
		t.Errorf("the same files hash to %s and %s", base, again)
	}
	for name, other := range map[string]map[string]string{
		"one byte changed": {"a.css": "body{ }", "f/b.js": "x"},
		"file renamed":     {"z.css": "body{}", "f/b.js": "x"},
		"file added":       {"a.css": "body{}", "f/b.js": "x", "c": ""},
	} {
		if got := hash(other); got == base {
			t.Errorf("%s: the hash did not change", name)
		}
	}

	if hash(map[string]string{"a": "ab", "b": "c"}) == hash(map[string]string{"a": "a", "b": "bc"}) {
		t.Error("moving a byte across a file boundary did not change the hash")
	}

	if !regexp.MustCompile(`^[0-9a-f]{16}$`).MatchString(assetHash) {
		t.Errorf("assetHash = %q, want 16 lowercase hex characters", assetHash)
	}
}

// assertOnlyHashedAssetRefs fails on any "/console/assets/" not followed by the
// current hash, and on a shell that carries fewer than min references, so a
// template that lost its links cannot pass vacuously.
func assertOnlyHashedAssetRefs(t *testing.T, where, body string, min int) {
	t.Helper()
	count := 0
	for from := 0; ; {
		i := strings.Index(body[from:], AssetsPrefix)
		if i < 0 {
			break
		}
		at := from + i + len(AssetsPrefix)
		count++
		if !strings.HasPrefix(body[at:], assetHash+"/") {
			t.Errorf("%s: asset reference without the content hash: %.60s", where, body[at-len(AssetsPrefix):])
		}
		from = at
	}
	if count < min {
		t.Errorf("%s: %d asset references, want at least %d", where, count, min)
	}
}

func TestAssets_ShellsReferenceOnlyHashedAssets(t *testing.T) {
	shell := httptest.NewRecorder()
	Render(shell, Page{Title: "t", Scripts: []string{accountsScript}})
	assertOnlyHashedAssetRefs(t, "layout", shell.Body.String(), 5)

	f := newLoginFixture(t)
	page := f.do(t, httptest.NewRequest(http.MethodGet, LoginPath, nil)).Body.String()
	assertOnlyHashedAssetRefs(t, "sign-in page", page, 4)
}

func TestAssets_FontFacesResolveUnderTheHash(t *testing.T) {
	h := newTestHandler(Deps{}, accounts.RoleAdmin)

	cssURL := assetURL("console.css")
	css := get(t, h, cssURL).Body.String()
	if strings.Contains(css, "url('/") {
		t.Fatal("the stylesheet has an absolute url(), which escapes the content hash")
	}
	refs := regexp.MustCompile(`url\('([^']+)'\)`).FindAllStringSubmatch(css, -1)
	if len(refs) == 0 {
		t.Fatal("the stylesheet has no url() references")
	}
	base, err := url.Parse(cssURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range refs {
		ref, err := url.Parse(m[1])
		if err != nil {
			t.Fatalf("url(%q): %v", m[1], err)
		}
		resolved := base.ResolveReference(ref).Path
		rec := get(t, h, resolved)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", resolved, rec.Code)
			continue
		}
		if !strings.HasPrefix(rec.Body.String(), "wOF2") {
			t.Errorf("%s is not a woff2 font", resolved)
		}
		if got := rec.Header().Get("Cache-Control"); got != immutableCache {
			t.Errorf("%s: Cache-Control = %q, want %q", resolved, got, immutableCache)
		}
	}
}
