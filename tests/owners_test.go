package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Owned objects (a Deployment's ReplicaSet and Pods) report a problem once,
// on the owner, but only when the owner is verified and the problem is the
// same; ownerReferences are not trusted blindly.
func TestOwnedObjectsDeduplicatedAgainstVerifiedOwners(t *testing.T) {
	priv := `{name: c, image: x, securityContext: {privileged: true}}`
	plain := `{name: c, image: x}`
	ref := func(kind, name, uid string) string {
		return `ownerReferences: [{apiVersion: apps/v1, kind: ` + kind + `, name: ` + name + `, uid: ` + uid + `, controller: true}]`
	}
	docs := []string{
		// A Deployment, its ReplicaSet and Pod, all privileged: one finding.
		`apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop, uid: d1}
spec: {replicas: 1, selector: {matchLabels: {app: web}}, template: {metadata: {labels: {app: web}}, spec: {containers: [` + priv + `]}}}`,
		`apiVersion: apps/v1
kind: ReplicaSet
metadata: {name: web-1, namespace: shop, uid: r1, ` + ref("Deployment", "web", "d1") + `}
spec: {replicas: 1, selector: {matchLabels: {app: web}}, template: {metadata: {labels: {app: web, pod-template-hash: "1"}}, spec: {containers: [` + priv + `]}}}`,
		`apiVersion: v1
kind: Pod
metadata: {name: web-1-a, namespace: shop, uid: p1, ` + ref("ReplicaSet", "web-1", "r1") + `}
spec: {containers: [` + priv + `]}
status: {phase: Running}`,
		// A Pod claiming an owner that does not exist.
		`apiVersion: v1
kind: Pod
metadata: {name: spoofed, namespace: shop, uid: p2, ` + ref("ReplicaSet", "nonexistent", "x") + `}
spec: {containers: [` + priv + `]}`,
		// A Pod naming a real ReplicaSet with the wrong UID.
		`apiVersion: v1
kind: Pod
metadata: {name: wrong-uid, namespace: shop, uid: p3, ` + ref("ReplicaSet", "web-1", "not-r1") + `}
spec: {containers: [` + priv + `]}`,
		// A clean Deployment whose ReplicaSet template was edited to be
		// privileged: the ReplicaSet is reported, its Pod once (as the RS).
		`apiVersion: apps/v1
kind: Deployment
metadata: {name: api, namespace: shop, uid: d2}
spec: {replicas: 1, selector: {matchLabels: {app: api}}, template: {metadata: {labels: {app: api}}, spec: {containers: [` + plain + `]}}}`,
		`apiVersion: apps/v1
kind: ReplicaSet
metadata: {name: api-1, namespace: shop, uid: r2, ` + ref("Deployment", "api", "d2") + `}
spec: {replicas: 1, selector: {matchLabels: {app: api}}, template: {metadata: {labels: {app: api}}, spec: {containers: [` + priv + `]}}}`,
		`apiVersion: v1
kind: Pod
metadata: {name: api-1-a, namespace: shop, uid: p4, ` + ref("ReplicaSet", "api-1", "r2") + `}
spec: {containers: [` + priv + `]}
status: {phase: Running}`,
		// A kubectl debug container on a clean Deployment's Pod.
		`apiVersion: v1
kind: Pod
metadata: {name: api-1-b, namespace: shop, uid: p5, ` + ref("ReplicaSet", "api-1", "r2") + `}
spec: {containers: [` + priv + `], ephemeralContainers: [{name: dbg, image: busybox, securityContext: {privileged: true}}]}
status: {phase: Running}`,
		// An old ReplicaSet scaled to zero, from before the template was
		// fixed: it runs nothing.
		`apiVersion: apps/v1
kind: ReplicaSet
metadata: {name: api-0, namespace: shop, uid: r3, ` + ref("Deployment", "api", "d2") + `}
spec: {replicas: 0, selector: {matchLabels: {app: api}}, template: {metadata: {labels: {app: api}}, spec: {containers: [{name: c, image: x, securityContext: {capabilities: {add: [SYS_ADMIN]}}}]}}}`,
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cluster.yaml"), []byte(strings.Join(docs, "\n---\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	r := scan(t, "minimal", dir)
	got := map[string]int{}
	for _, f := range r.Findings {
		if f.RuleID == "HX-WL-001" || f.RuleID == "HX-WL-006" {
			got[f.RuleID+" "+f.Resource.Kind+"/"+f.Resource.Name+"["+f.Resource.Container+"]"]++
		}
	}
	want := map[string]int{
		"HX-WL-001 Deployment/web[c]":   1, // reported once, on the owner
		"HX-WL-001 Pod/spoofed[c]":      1, // owner missing: not trusted
		"HX-WL-001 Pod/wrong-uid[c]":    1, // UID mismatch: not trusted
		"HX-WL-001 ReplicaSet/api-1[c]": 1, // edited template: differs from the Deployment
		"HX-WL-001 Pod/api-1-b[dbg]":    1, // debug container: only in the Pod
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("%s: %d, want %d", k, got[k], n)
		}
	}
	for k, n := range got {
		if want[k] == 0 {
			t.Errorf("unexpected %s (%d)", k, n)
		}
	}
	found := false
	for _, w := range r.Warnings {
		found = found || strings.Contains(w, "controller-owned objects")
	}
	if !found {
		t.Errorf("no warning about omitted duplicates: %v", r.Warnings)
	}
}
