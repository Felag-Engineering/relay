package capability

import (
	"errors"
	"testing"
)

func TestFirstRefusal(t *testing.T) {
	refusal := errors.New("refused")
	record := errors.New("record failed")
	plain := errors.New("plain")

	if got := FirstRefusal(errors.Join(refusal, record)); got != refusal {
		t.Errorf("joined: got %v, want the refusal", got)
	}
	if got := FirstRefusal(plain); got != plain {
		t.Errorf("not joined: got %v, want err itself", got)
	}
	if got := FirstRefusal(nil); got != nil {
		t.Errorf("nil: got %v, want nil", got)
	}
}
