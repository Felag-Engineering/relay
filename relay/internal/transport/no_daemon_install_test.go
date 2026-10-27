package transport_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	relayv1 "github.com/Felag-Engineering/relay/relay/internal/relay/v1"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest/installguard"
	"github.com/Felag-Engineering/relay/relay/internal/relaytest/protowalk"
)

// TestNodePlane_NoRPCInstallsADaemon is DI-18 for the Node transport, an absence
// asserted over the wire contract and the servers the Relay registers. Nothing the
// Relay can say to a daemon installs, configures or upgrades it: the services are a
// closed set, the Relay-to-daemon payloads are a closed set, no field reachable from
// what the Relay sends or from the enrollment artifacts is named for an install, and the
// Relay registers no gRPC server beyond the two. Invariant 14: the Relay never pushes
// binaries and a daemon is upgraded only by the customer's config management.
//
// Proves DI-18.
func TestNodePlane_NoRPCInstallsADaemon(t *testing.T) {
	t.Run("the services and RPCs are a closed set", func(t *testing.T) {
		got := map[string]bool{}
		services := relayv1.File_relay_v1_relay_proto.Services()
		for i := 0; i < services.Len(); i++ {
			svc := services.Get(i)
			methods := svc.Methods()
			for j := 0; j < methods.Len(); j++ {
				got[string(svc.Name())+"/"+string(methods.Get(j).Name())] = true
			}
		}
		want := map[string]bool{"Enrollment/Enroll": true, "Enrollment/Renew": true, "Tunnel/Open": true}
		if !sameSet(got, want) {
			t.Errorf("the Node plane's RPCs are %v, want exactly %v; classify a new RPC here: one that installs, configures or upgrades a daemon is never added (DI-18, invariant 14)", keys(got), keys(want))
		}
		for rpc := range got {
			if hits := installguard.Hits(rpc); len(hits) > 0 {
				t.Errorf("RPC %q is named for %v (DI-18, invariant 14)", rpc, hits)
			}
		}
	})

	t.Run("what the Relay sends a daemon is a closed set", func(t *testing.T) {
		msg := (&relayv1.RelayMessage{}).ProtoReflect().Descriptor()
		assertOneof(t, msg, "body", map[string]string{
			"ping":         "liveness",
			"task":         "an Operation or Raw Exec, gated by the Node's Policy",
			"task_cancel":  "stop an in-flight Task",
			"policy_query": "a read-only probe of the Node's own Policy",
		})
		task := (&relayv1.TaskRequest{}).ProtoReflect().Descriptor()
		assertOneof(t, task, "action", map[string]string{
			"operation": "a typed Operation the Node's Policy allows",
			"raw_exec":  "caller-supplied argv, regex-gated by the Node's Policy",
		})
	})

	t.Run("no reachable field is named for an install", func(t *testing.T) {
		starts := []protoreflect.MessageDescriptor{
			(&relayv1.RelayMessage{}).ProtoReflect().Descriptor(),
			(&relayv1.EnrollResponse{}).ProtoReflect().Descriptor(),
			(&relayv1.RenewResponse{}).ProtoReflect().Descriptor(),
			// The pasteable enrollment artifact: relay_address, a CA fingerprint and an
			// Enrollment Token, nothing a daemon could install from.
			(&relayv1.JoinString{}).ProtoReflect().Descriptor(),
		}
		visited := 0
		for _, start := range starts {
			protowalk.WalkReachableMessageFields(start, func(field string) {
				visited++
				if hits := installguard.Hits(field); len(hits) > 0 {
					t.Errorf("field %q reachable from %s is named for %v (DI-18, invariant 14)", field, start.FullName(), hits)
				}
			})
		}
		if visited <= 10 {
			t.Errorf("the walk visited %d fields; it is not seeing the real messages", visited)
		}
	})

	t.Run("the Relay registers no gRPC server beyond the two", func(t *testing.T) {
		_, thisFile, _, ok := runtime.Caller(0)
		if !ok {
			t.Fatal("runtime.Caller failed")
		}
		relayRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
		register := regexp.MustCompile(`\bRegister(\w+)Server\(`)
		got := map[string]bool{}
		for _, root := range []string{"cmd", "internal"} {
			err := filepath.WalkDir(filepath.Join(relayRoot, root), func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				name := d.Name()
				if d.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || strings.HasSuffix(name, ".pb.go") {
					return nil
				}
				src, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				for _, m := range register.FindAllStringSubmatch(string(src), -1) {
					got[m[1]] = true
				}
				return nil
			})
			if err != nil {
				t.Fatalf("walk %s: %v", root, err)
			}
		}
		want := map[string]bool{"Tunnel": true, "Enrollment": true}
		if !sameSet(got, want) {
			t.Errorf("the Relay registers gRPC servers %v, want exactly %v; a server that installs, configures or upgrades a daemon is never added (DI-18, invariant 14)", keys(got), keys(want))
		}
	})
}

// assertOneof fails t unless the named oneof of md has exactly the fields in want, each
// kept with the reason it is not an install.
func assertOneof(t *testing.T, md protoreflect.MessageDescriptor, name string, want map[string]string) {
	t.Helper()
	oneof := md.Oneofs().ByName(protoreflect.Name(name))
	if oneof == nil {
		t.Fatalf("%s has no oneof %q; the contract changed shape", md.FullName(), name)
	}
	got := map[string]bool{}
	fields := oneof.Fields()
	for i := 0; i < fields.Len(); i++ {
		got[string(fields.Get(i).Name())] = true
	}
	wantSet := map[string]bool{}
	for field := range want {
		wantSet[field] = true
	}
	if !sameSet(got, wantSet) {
		t.Errorf("%s.%s is %v, want exactly %v; a new variant must be classified here, and one that installs, configures or upgrades a daemon is never added (DI-18, invariant 14)", md.FullName(), name, keys(got), keys(wantSet))
	}
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
