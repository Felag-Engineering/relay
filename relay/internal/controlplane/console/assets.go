package console

// Content-addressed static assets for the Console.
//
// assetHash is a digest of every embedded asset byte and name, computed once at
// start. Every URL the Console's pages emit carries it, so a URL names exactly
// those bytes: that is what makes the immutable cache header safe, because any
// change to an embedded file changes the URL. The unhashed path stays served,
// always no-store, so it can never go stale.

import (
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed assets/*
var assetsFS embed.FS

// assetHash names the embedded assets' current content.
var assetHash = mustHashAssets()

func mustHashAssets() string {
	h, err := hashAssets(assetsFS)
	if err != nil {
		// An embedded FS cannot fail to walk; serving under an empty hash
		// would be worse than not starting.
		panic(fmt.Sprintf("console: hashing embedded assets: %v", err))
	}
	return h
}

// hashAssets digests every regular file in fsys, in lexical order. Each file
// contributes its path, a separator, its length and its content, so neither a
// rename nor a shift of bytes between two files leaves the digest unchanged.
func hashAssets(fsys fs.FS) (string, error) {
	sum := sha256.New()
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		body, err := fs.ReadFile(fsys, path)
		if err != nil {
			return err
		}
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(body)))
		sum.Write([]byte(path))
		sum.Write([]byte{0})
		sum.Write(size[:])
		sum.Write(body)
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)[:8]), nil
}

// assetURL is the content-addressed URL of an embedded asset; name is relative
// to assets/, for example "console.css" or "brand/relay-icon.svg".
func assetURL(name string) string {
	return AssetsPrefix + assetHash + "/" + name
}

const immutableCache = "public, max-age=31536000, immutable"

// assetHandler serves the Console's own static assets. It exists because the
// content security policy admits styles, scripts and fonts only from this
// origin and nothing inline, so none of them can live in the layout.
//
// Files under the current hash are immutable, and so are the canonicalising
// redirects FileServer issues there, which are fixed per hash. Directory
// listings (a trailing slash) are not: a listing is not content-addressed
// bytes. Any other path, the unhashed one included, is no-store, and a stale
// hash finds no file and is a 404 rather than current bytes under an old name.
//
// StripPrefix is load-bearing rather than tidy: the FileServer is rooted at
// the embedded "assets/" directory, so it must see "/console.css", not the
// request path; otherwise it 404s and every Console page renders unstyled.
//
// TestConsole_StylesheetIsActuallyServed is the regression guard, and it
// asserts the BODY rather than the status, because a 404 page is also a 200-
// shaped thing to a careless assertion.
func assetHandler(Deps) http.HandlerFunc {
	sub, err := fs.Sub(assetsFS, "assets")
	if err != nil {
		panic(fmt.Sprintf("console: embedded assets: %v", err))
	}
	files := http.FileServer(http.FS(sub))
	hashedPrefix := AssetsPrefix + assetHash + "/"
	hashed := http.StripPrefix(strings.TrimSuffix(hashedPrefix, "/"), files)
	plain := http.StripPrefix(strings.TrimSuffix(AssetsPrefix, "/"), files)
	return func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, hashedPrefix) {
			w.Header().Set("Cache-Control", "no-store")
			plain.ServeHTTP(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/") {
			w.Header().Set("Cache-Control", "no-store")
		} else {
			w.Header().Set("Cache-Control", immutableCache)
		}
		hashed.ServeHTTP(w, r)
	}
}
