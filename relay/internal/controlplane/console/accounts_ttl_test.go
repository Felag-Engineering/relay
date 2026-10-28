package console

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Felag-Engineering/relay/relay/internal/capability"
)

func TestAccountsWrite_AHumanMintFormDefaultsToSevenDays(t *testing.T) {
	body := accountsWriteBody(t, accountPagePath("ana"))
	form := formWithAction(t, body, mintAPITokenAction(targetViewerID))

	first := strings.Index(form, `<option value="default" selected>7 days (default)</option>`)
	if first < 0 {
		t.Fatalf("the human form does not preselect the 7-day default:\n%s", form)
	}
	if other := strings.Index(form, "<option value=\"30d\""); other < first {
		t.Errorf("the default is not the first option:\n%s", form)
	}
	if n := strings.Count(form, " selected"); n != 1 {
		t.Errorf("%d options are selected, want only the default", n)
	}

	x := newWriteFix(t, nil)
	rec := x.post(t, mintAPITokenAction(targetViewerID), url.Values{
		"name": {"laptop"}, "ttl": {"default"}, "password": {"whatever the fake accepts"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if len(x.admin.mints) != 1 {
		t.Fatalf("mint calls = %d, want 1", len(x.admin.mints))
	}
	if got := x.admin.mints[0].TTL; got != capability.DefaultAPITokenLifetime() {
		t.Errorf("lifetime = %+v, want the capability layer's default", got)
	}
}

func TestAccountsWrite_AMachineMintFormHasNoDefault(t *testing.T) {
	body := accountsWriteBody(t, accountPagePath("gleipnir-prod"))
	form := formWithAction(t, body, mintAPITokenAction(targetOperatorID))
	if strings.Contains(form, `value="default"`) {
		t.Errorf("a machine Account's form offers a default lifetime:\n%s", form)
	}
}
