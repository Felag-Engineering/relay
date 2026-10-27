package installguard

import (
	"reflect"
	"testing"
)

func TestHits_Flags(t *testing.T) {
	for _, tc := range []struct {
		name string
		want []string
	}{
		{"upgrade_daemon", []string{"upgrade", "daemon"}},
		{"POST /api/v1/nodes/{node_id}/install", []string{"install"}},
		{"InstallDaemon", []string{"install", "daemon"}},
		{"relay.v1.Daemon/PushBinary", []string{"daemon", "binary"}},
		{"run_operation", nil},
		{"GET /api/v1/approval-grants/{id}", nil},
		{"Enroll", nil},
		{"task_cancel", nil},
	} {
		if got := Hits(tc.name); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("Hits(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}
