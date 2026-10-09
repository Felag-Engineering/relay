package jobs

import "testing"

func TestRequestDigest_StableAcrossArgOrderAndDistinctAcrossFields(t *testing.T) {
	base := Action{
		Kind: ActionOperation, OperationName: "service.restart",
		OperationArgs:  map[string]string{"service": "nginx", "mode": "graceful"},
		TimeoutSeconds: 30,
	}
	want := RequestDigest("node:role=web", base)

	same := base
	same.OperationArgs = map[string]string{"mode": "graceful", "service": "nginx"}
	same.RiskClass = RiskClassMutate // derived by the capability layer; not part of the request
	if got := RequestDigest("node:role=web", same); got != want {
		t.Error("the digest changed with map order or the derived RiskClass")
	}

	with := func(mutate func(*Action)) Action {
		a := base
		a.OperationArgs = map[string]string{"service": "nginx", "mode": "graceful"}
		mutate(&a)
		return a
	}
	variants := map[string]struct {
		sel string
		act Action
	}{
		"selector":  {"node:role=db", base},
		"kind":      {"node:role=web", Action{Kind: ActionRawExec, RawExecArgv: []string{"service.restart"}, TimeoutSeconds: 30}},
		"name":      {"node:role=web", with(func(a *Action) { a.OperationName = "service.stop" })},
		"arg value": {"node:role=web", with(func(a *Action) { a.OperationArgs["service"] = "php-fpm" })},
		"arg key":   {"node:role=web", with(func(a *Action) { delete(a.OperationArgs, "service"); a.OperationArgs["unit"] = "nginx" })},
		"timeout":   {"node:role=web", with(func(a *Action) { a.TimeoutSeconds = 31 })},
	}
	for name, v := range variants {
		if RequestDigest(v.sel, v.act) == want {
			t.Errorf("changing the %s did not change the digest", name)
		}
	}

	// Length-prefixing: moving a byte across a field boundary is a different request.
	a := Action{Kind: ActionRawExec, RawExecArgv: []string{"ab", "c"}}
	b := Action{Kind: ActionRawExec, RawExecArgv: []string{"a", "bc"}}
	if RequestDigest("", a) == RequestDigest("", b) {
		t.Error("argv [ab c] and [a bc] share a digest")
	}
}
