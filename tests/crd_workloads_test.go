package tests

import (
	"os"
	"path/filepath"
	"testing"
)

// Custom resources that embed a pod template are assessed like the built-in
// workloads: their controllers create the pods, so a manifest scan sees the
// template or nothing.
func TestCustomResourceWorkloads(t *testing.T) {
	dir := t.TempDir()
	priv := `{name: c, image: x, securityContext: {privileged: true}}`
	y := `apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata: {name: rollout, namespace: crd}
spec: {template: {spec: {containers: [` + priv + `]}}}
---
apiVersion: serving.knative.dev/v1
kind: Service
metadata: {name: ksvc, namespace: crd}
spec: {template: {spec: {containers: [` + priv + `]}}}
---
apiVersion: serving.knative.dev/v1
kind: Revision
metadata: {name: rev, namespace: crd}
spec: {containers: [` + priv + `]}
---
apiVersion: keda.sh/v1alpha1
kind: ScaledJob
metadata: {name: sj, namespace: crd}
spec: {jobTargetRef: {template: {spec: {containers: [` + priv + `]}}}}
---
apiVersion: apps.kruise.io/v1alpha1
kind: CloneSet
metadata: {name: cs, namespace: crd}
spec: {template: {spec: {containers: [` + priv + `]}}}
---
apiVersion: v1
kind: Service
metadata: {name: core, namespace: crd}
spec: {template: {spec: {containers: [` + priv + `]}}}
---
apiVersion: example.com/v1
kind: Rollout
metadata: {name: other-group, namespace: crd}
spec: {template: {spec: {containers: [` + priv + `]}}}
`
	if err := os.WriteFile(filepath.Join(dir, "crd.yaml"), []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	r := scan(t, "restricted", dir)
	got := map[string]string{}
	for _, f := range r.Findings {
		if f.RuleID == "HX-WL-001" {
			got[f.Resource.Name] = f.Path
		}
	}
	for name, path := range map[string]string{
		"rollout": "spec.template.spec.containers[0].securityContext.privileged",
		"ksvc":    "spec.template.spec.containers[0].securityContext.privileged",
		"rev":     "spec.containers[0].securityContext.privileged",
		"sj":      "spec.jobTargetRef.template.spec.containers[0].securityContext.privileged",
		"cs":      "spec.template.spec.containers[0].securityContext.privileged",
	} {
		if got[name] != path {
			t.Errorf("%s: HX-WL-001 at %q, want %q", name, got[name], path)
		}
	}
	for _, name := range []string{"core", "other-group"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s is not a workload but was assessed as one", name)
		}
	}
}
