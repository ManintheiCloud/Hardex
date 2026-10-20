package remediation

import (
	"context"
	"errors"
	"fmt"
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

// fakeCluster applies JSON patches (test operations included) to stored
// objects, like the API server. Each call can be made to fail before or
// after the server applies it.
type fakeCluster struct {
	objs map[string]map[string]any
	// failForward makes the forward patch of a target fail: "reject" (the
	// server refuses it) or "lost" (the server applies it, the response is
	// lost: a timeout).
	failForward map[string]string
	calls       []string
}

func newFakeCluster(plans []ObjectPlan) *fakeCluster {
	c := &fakeCluster{objs: map[string]map[string]any{}, failForward: map[string]string{}}
	for _, p := range plans {
		c.objs[p.Target.Name] = DeepCopy(p.Original).(map[string]any)
	}
	return c
}

func (c *fakeCluster) patch(ctx context.Context, t Target, ops []Op) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Forward patches start with the resourceVersion guard (the plans here
	// use GuardResourceVersion); inverse patches never test it.
	kind := "inverse"
	switch {
	case len(testsOnly(ops)) == len(ops):
		kind = "probe"
	case ops[0].Path == "/metadata/resourceVersion":
		kind = "forward"
	}
	c.calls = append(c.calls, kind+":"+t.Name)
	if kind == "forward" && c.failForward[t.Name] == "reject" {
		return errors.New("admission webhook denied the request")
	}
	out, err := Apply(c.objs[t.Name], ops)
	if err != nil {
		return err
	}
	if kind != "probe" {
		// The API server bumps resourceVersion on every change.
		out["metadata"].(map[string]any)["resourceVersion"] = fmt.Sprint(len(c.calls) + 100)
	}
	c.objs[t.Name] = out
	if kind == "forward" && c.failForward[t.Name] == "lost" {
		return context.DeadlineExceeded
	}
	return nil
}

// twoObjects plans the same fix for two objects, "web" and "second".
func twoObjects(t *testing.T) []ObjectPlan {
	t.Helper()
	inv := deployment(t)
	plan, err := Build(inv, []finding.Finding{fnd("HX-A", "a", "spec.template.spec.containers[0].securityContext.privileged")},
		map[string]Fixer{"HX-A": fixer(false, Low)}, Options{GuardResourceVersion: true})
	if err != nil || len(plan.Objects) != 1 {
		t.Fatalf("plan: %v %+v", err, plan)
	}
	second := plan.Objects[0]
	second.Target.Name = "second"
	return []ObjectPlan{plan.Objects[0], second}
}

func privileged(c *fakeCluster, name string) any {
	v, _ := Get(c.objs[name], "/spec/template/spec/containers/0/securityContext/privileged")
	return v
}

func TestApplyAllRollsBackOnFailure(t *testing.T) {
	objs := twoObjects(t)
	c := newFakeCluster(objs)
	c.failForward["second"] = "reject"
	b, err := NewBackup(t.TempDir(), "ctx", "https://k8s", objs, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	res := ApplyAll(context.Background(), b, c.patch)
	if res.Err == nil || len(res.RolledBack) != 1 || res.RollbackErr != nil {
		t.Fatalf("result = %+v", res)
	}
	// second was rejected: its outcome is checked (inverse fails, probe
	// passes), then web is undone.
	want := []string{"forward:web", "forward:second", "inverse:second", "probe:second", "inverse:web"}
	if !reflect.DeepEqual(c.calls, want) {
		t.Errorf("calls = %v, want %v", c.calls, want)
	}
	if privileged(c, "web") != true || privileged(c, "second") != true {
		t.Error("cluster not restored")
	}
	reloaded, err := LoadBackup(b.Path())
	if err != nil {
		t.Fatal(err)
	}
	if o := reloaded.Objects; !o[0].Applied || !o[0].RolledBack || o[1].Applied || !o[1].NotApplied {
		t.Errorf("backup state not recorded: %+v", reloaded.Objects)
	}
}

// A request whose response is lost (timeout) may have been applied: it
// must be undone, not forgotten.
func TestApplyAllUndoesPatchWithLostResponse(t *testing.T) {
	objs := twoObjects(t)
	c := newFakeCluster(objs)
	c.failForward["second"] = "lost"
	b, _ := NewBackup(t.TempDir(), "ctx", "https://k8s", objs, time.Now())
	res := ApplyAll(context.Background(), b, c.patch)
	if res.Err == nil || res.RollbackErr != nil || len(res.RolledBack) != 2 {
		t.Fatalf("result = %+v", res)
	}
	if privileged(c, "web") != true || privileged(c, "second") != true {
		t.Errorf("cluster not restored: web=%v second=%v", privileged(c, "web"), privileged(c, "second"))
	}
}

// The process dies after the server applied a patch but before the backup
// recorded it. The journal says "attempted"; hardex rollback must undo it.
func TestRollbackAfterCrash(t *testing.T) {
	for _, landed := range []bool{true, false} {
		objs := twoObjects(t)
		c := newFakeCluster(objs)
		dir := t.TempDir()
		b, _ := NewBackup(dir, "ctx", "https://k8s", objs, time.Now())
		// web applied and recorded; second attempted, then the crash.
		b.Objects[0].Attempted = true
		if err := c.patch(context.Background(), b.Objects[0].Target, b.Objects[0].Patch); err != nil {
			t.Fatal(err)
		}
		b.Objects[0].Applied = true
		b.Objects[1].Attempted = true
		if err := b.save(); err != nil {
			t.Fatal(err)
		}
		if landed {
			if err := c.patch(context.Background(), b.Objects[1].Target, b.Objects[1].Patch); err != nil {
				t.Fatal(err)
			}
		}

		loaded, err := LoadBackup(b.Path())
		if err != nil {
			t.Fatal(err)
		}
		applied, uncertain := loaded.Pending()
		if len(applied) != 1 || len(uncertain) != 1 {
			t.Fatalf("pending = %v / %v", applied, uncertain)
		}
		res := Rollback(context.Background(), loaded, c.patch)
		if res.Err != nil {
			t.Fatalf("landed=%v: %v", landed, res.Err)
		}
		if privileged(c, "web") != true || privileged(c, "second") != true {
			t.Errorf("landed=%v: cluster not restored", landed)
		}
		if landed && len(res.RolledBack) != 2 || !landed && (len(res.RolledBack) != 1 || len(res.NotApplied) != 1) {
			t.Errorf("landed=%v: result = %+v", landed, res)
		}
		if a, u := loaded.Pending(); len(a)+len(u) != 0 {
			t.Errorf("landed=%v: still pending after rollback: %v %v", landed, a, u)
		}
	}
}

// Ctrl-C during apply cancels the context; the rollback must still run.
func TestRollbackRunsAfterCancellation(t *testing.T) {
	objs := twoObjects(t)
	c := newFakeCluster(objs)
	ctx, cancel := context.WithCancel(context.Background())
	b, _ := NewBackup(t.TempDir(), "ctx", "https://k8s", objs, time.Now())
	n := 0
	patch := func(pctx context.Context, tg Target, ops []Op) error {
		n++
		err := c.patch(pctx, tg, ops)
		if n == 1 {
			cancel() // interrupted right after the first patch
		}
		return err
	}
	res := ApplyAll(ctx, b, patch)
	if res.Err == nil || !errors.Is(res.Err, context.Canceled) || res.RollbackErr != nil || len(res.RolledBack) != 1 {
		t.Fatalf("result = %+v", res)
	}
	if privileged(c, "web") != true {
		t.Error("first object not restored after cancellation")
	}
	if b.Objects[1].Attempted {
		t.Error("second object attempted after cancellation")
	}
}

// Other updates (a controller writing status) move resourceVersion without
// touching the fields Hardex patches: an unconfirmed patch whose fields are
// all still original needs no undo.
func TestRollbackIgnoresUnrelatedUpdatesOnUncertainObject(t *testing.T) {
	objs := twoObjects(t)
	c := newFakeCluster(objs)
	b, _ := NewBackup(t.TempDir(), "ctx", "https://k8s", objs, time.Now())
	b.Objects[0].Attempted = true
	c.objs["web"]["metadata"].(map[string]any)["resourceVersion"] = "999"
	c.objs["web"]["status"] = map[string]any{"readyReplicas": 3.0}
	res := Rollback(context.Background(), b, c.patch)
	if res.Err != nil || len(res.NotApplied) != 1 {
		t.Fatalf("result = %+v", res)
	}
}

// An object whose patched field someone changed to a third value after an
// uncertain attempt is neither original nor patched: report it, change
// nothing.
func TestRollbackReportsConflictOnUncertainObject(t *testing.T) {
	objs := twoObjects(t)
	c := newFakeCluster(objs)
	b, _ := NewBackup(t.TempDir(), "ctx", "https://k8s", objs, time.Now())
	b.Objects[0].Attempted = true
	c.objs["web"], _ = Apply(c.objs["web"], []Op{{Op: "replace", Path: "/spec/template/spec/containers/0/securityContext/privileged", Value: "someone-else"}})
	before := DeepCopy(c.objs["web"])
	res := Rollback(context.Background(), b, c.patch)
	if res.Err == nil || !strings.Contains(res.Err.Error(), "unknown whether the patch was applied") {
		t.Fatalf("err = %v", res.Err)
	}
	if !jsonEqual(c.objs["web"], before) {
		t.Error("rollback changed an object in an unknown state")
	}
	if _, u := b.Pending(); len(u) != 1 {
		t.Error("conflicting object no longer pending")
	}
}
