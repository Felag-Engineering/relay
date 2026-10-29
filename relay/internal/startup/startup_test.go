package startup

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/startup/internal/sealed"
)

// TestCheckExistingStore_AbsentDirectoryCreatesNothing: a store directory that does not exist
// is ErrStoreAbsent, and the check leaves it absent, unlike Open. The present-directory paths
// are proven over the harness (TestInit_RefusesAbsentStore), since the check refuses every
// directory a test can make in-process.
func TestCheckExistingStore_AbsentDirectoryCreatesNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	err := CheckExistingStore(filepath.Join(dir, "relay.db"))
	if !errors.Is(err, ErrStoreAbsent) {
		t.Fatalf("CheckExistingStore = %v, want ErrStoreAbsent", err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the store directory exists after the check (err %v); it must create nothing", err)
	}
}

// The zero value — all that code outside the startup tree can make without Open — is not
// valid, and FromSealed refuses anything incomplete.
func TestFiles_ZeroAndIncompleteRefused(t *testing.T) {
	if (Files{}).Valid() {
		t.Error("the zero Files is valid")
	}
	if f, err := FromSealed(sealed.Files{}); err == nil || f.Valid() {
		t.Errorf("FromSealed(zero) = %v, %v; want a refusal", f, err)
	}
}
