package remediation

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

func TestApplyOperations(t *testing.T) {
	doc := map[string]any{"a": map[string]any{"b": 1.0}, "list": []any{"x", "y"}, "k/e~y": true}
	out, err := Apply(doc, []Op{
		{Op: "test", Path: "/a/b", Value: 1},
		{Op: "replace", Path: "/a/b", Value: 2},
		{Op: "add", Path: "/a/c", Value: map[string]any{"d": "e"}},
		{Op: "remove", Path: "/list/0"},
		{Op: "add", Path: "/list/-", Value: "z"},
		{Op: "remove", Path: "/k~1e~0y"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"a": map[string]any{"b": 2, "c": map[string]any{"d": "e"}}, "list": []any{"y", "z"}}
	if !jsonEqual(out, want) {
		t.Errorf("got %v, want %v", out, want)
	}
	if !jsonEqual(doc["list"], []any{"x", "y"}) {
		t.Error("Apply mutated its input")
	}
	for name, ops := range map[string][]Op{
		"failed test":     {{Op: "test", Path: "/a/b", Value: 9}},
		"missing replace": {{Op: "replace", Path: "/nope", Value: 1}},
		"missing parent":  {{Op: "add", Path: "/x/y", Value: 1}},
		"bad index":       {{Op: "remove", Path: "/list/5"}},
		"root":            {{Op: "remove", Path: ""}},
	} {
		if _, err := Apply(doc, ops); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParsePath(t *testing.T) {
	cases := map[string][]string{
		"spec.template.spec.containers[0].securityContext.privileged":              {"spec", "template", "spec", "containers", "0", "securityContext", "privileged"},
		"metadata.annotations[container.apparmor.security.beta.kubernetes.io/web]": {"metadata", "annotations", "container.apparmor.security.beta.kubernetes.io/web"},
	}
	for in, want := range cases {
		if got := ParsePath(in); !reflect.DeepEqual(got, want) {
			t.Errorf("ParsePath(%q) = %q", in, got)
		}
	}
}

func deployment(t *testing.T) *resource.Inventory {
	t.Helper()
	inv, err := resource.Load([]string{"-"}, strings.NewReader(`apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop, resourceVersion: "42"}
spec:
  template:
    spec:
      containers:
        - name: a
          image: x:1
          securityContext: {privileged: true}
        - name: b
          image: x:1
`))
	if err != nil {
		t.Fatal(err)
	}
	return inv
}

func fixer(value any, risk Risk) Fixer {
	return func(_ *resource.Object, f finding.Finding) (*Change, string) {
		return &Change{Description: "set", Risk: risk, Set: []Assignment{{Path: ParsePath(f.Path), Value: value}}}, ""
	}
}

func fnd(rule, container, path string) finding.Finding {
	f := finding.Finding{RuleID: rule, Path: path, Resource: finding.Resource{Kind: "Deployment", Namespace: "shop", Name: "web", Container: container}}
	f.ComputeFingerprint()
	return f
}

func TestBuildCombinesFixesAndInverts(t *testing.T) {
	inv := deployment(t)
	fs := []finding.Finding{
		fnd("HX-A", "a", "spec.template.spec.containers[0].securityContext.privileged"),
		// Both of these create the same missing securityContext on container b;
		// the second must not overwrite the first.
		fnd("HX-B", "b", "spec.template.spec.containers[1].securityContext.allowPrivilegeEscalation"),
		fnd("HX-C", "b", "spec.template.spec.containers[1].securityContext.readOnlyRootFilesystem"),
		fnd("HX-HIGH", "a", "spec.template.spec.containers[0].securityContext.runAsNonRoot"),
		fnd("HX-NOFIX", "a", "spec.template.spec.containers[0].image"),
	}
	plan, err := Build(inv, fs, map[string]Fixer{
		"HX-A": fixer(false, Low), "HX-B": fixer(false, Low), "HX-C": fixer(true, Medium), "HX-HIGH": fixer(true, High),
	}, Options{MaxRisk: Medium, GuardResourceVersion: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Objects) != 1 || len(plan.Objects[0].Fixes) != 3 {
		t.Fatalf("plan = %+v", plan)
	}
	o := plan.Objects[0]
	if o.Patch[0].Op != "test" || o.Patch[0].Path != "/metadata/resourceVersion" {
		t.Error("resourceVersion guard missing")
	}
	sc, _ := Get(o.Patched, "/spec/template/spec/containers/1/securityContext")
	if !jsonEqual(sc, map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}) {
		t.Errorf("container b securityContext = %v", sc)
	}
	if o.Risk != Medium {
		t.Errorf("risk = %s, want medium", o.Risk)
	}
	restored, err := Apply(o.Patched, o.Inverse)
	if err != nil || !jsonEqual(restored, o.Original) {
		t.Fatalf("inverse does not restore original: %v", err)
	}
	reasons := map[string]string{}
	for _, s := range plan.Skipped {
		reasons[s.RuleID] = s.Reason
	}
	if !strings.Contains(reasons["HX-HIGH"], "risk high") || !strings.Contains(reasons["HX-NOFIX"], "no automatic fix") {
		t.Errorf("skips = %v", reasons)
	}
}

func TestPatchRefusesChangedObject(t *testing.T) {
	inv := deployment(t)
	plan, _ := Build(inv, []finding.Finding{fnd("HX-A", "a", "spec.template.spec.containers[0].securityContext.privileged")},
		map[string]Fixer{"HX-A": fixer(false, Low)}, Options{GuardResourceVersion: true})
	changed := DeepCopy(inv.Objects[0].Raw).(map[string]any)
	changed["metadata"].(map[string]any)["resourceVersion"] = "43"
	if _, err := Apply(changed, plan.Objects[0].Patch); err == nil {
		t.Fatal("patch applied to an object that changed since planning")
	}
	// The inverse refuses to undo a value someone else has since changed.
	tampered, _ := Apply(plan.Objects[0].Patched, []Op{{Op: "replace", Path: "/spec/template/spec/containers/0/securityContext/privileged", Value: "other"}})
	if _, err := Apply(tampered, plan.Objects[0].Inverse); err == nil {
		t.Fatal("inverse overwrote a third-party change")
	}
}

func TestApplyAllRollsBackOnFailure(t *testing.T) {
	inv := deployment(t)
	plan, _ := Build(inv, []finding.Finding{fnd("HX-A", "a", "spec.template.spec.containers[0].securityContext.privileged")},
		map[string]Fixer{"HX-A": fixer(false, Low)}, Options{})
	objs := []ObjectPlan{plan.Objects[0], plan.Objects[0]}
	objs[1].Target.Name = "second"

	b, err := NewBackup(t.TempDir(), "ctx", "https://k8s", objs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	patch := func(_ context.Context, tg Target, ops []Op) error {
		kind := "forward"
		if ops[0].Op == "test" && ops[0].Value == false {
			kind = "inverse"
		}
		calls = append(calls, kind+":"+tg.Name)
		if tg.Name == "second" && kind == "forward" {
			return errors.New("admission denied")
		}
		return nil
	}
	res := ApplyAll(context.Background(), b, patch)
	if res.Err == nil || len(res.RolledBack) != 1 || res.RollbackErr != nil {
		t.Fatalf("result = %+v", res)
	}
	want := []string{"forward:web", "forward:second", "inverse:web"}
	if !reflect.DeepEqual(calls, want) {
		t.Errorf("calls = %v, want %v", calls, want)
	}
	reloaded, err := LoadBackup(b.Path())
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.Objects[0].Applied || !reloaded.Objects[0].RolledBack || reloaded.Objects[1].Applied {
		t.Errorf("backup state not recorded: %+v", reloaded.Objects)
	}
}
