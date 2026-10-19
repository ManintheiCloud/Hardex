package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/ManintheiCloud/Hardex"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// synthetic builds a large, realistic-shaped inventory: namespaces with
// deployments (a mix of hardened and insecure), service accounts, network
// policies, roles and bindings, plus cluster-wide roles.
func synthetic(namespaces, perNamespace int) *resource.Inventory {
	inv := resource.NewInventory()
	add := func(raw map[string]any) {
		o, err := resource.NewObject(raw, "synthetic", 0)
		if err != nil {
			panic(err)
		}
		inv.Add(o)
	}
	meta := func(ns, name string) map[string]any { return map[string]any{"name": name, "namespace": ns} }
	for n := 0; n < namespaces; n++ {
		ns := fmt.Sprintf("team-%03d", n)
		add(map[string]any{"apiVersion": "v1", "kind": "Namespace", "metadata": map[string]any{"name": ns}})
		add(map[string]any{"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": meta(ns, "deny"),
			"spec": map[string]any{"podSelector": map[string]any{}, "policyTypes": []any{"Ingress"}}})
		add(map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": meta(ns, "deployer"),
			"rules": []any{map[string]any{"apiGroups": []any{"apps"}, "resources": []any{"deployments"}, "verbs": []any{"create", "update"}}}})
		for i := 0; i < perNamespace; i++ {
			sa := fmt.Sprintf("app-%d", i)
			add(map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": meta(ns, sa)})
			add(map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": meta(ns, sa),
				"roleRef":  map[string]any{"kind": "Role", "name": "deployer"},
				"subjects": []any{map[string]any{"kind": "ServiceAccount", "name": sa, "namespace": ns}}})
			sc := map[string]any{"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true}
			if i%10 == 0 {
				sc = map[string]any{"privileged": true}
			}
			add(map[string]any{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": meta(ns, fmt.Sprintf("svc-%d", i)),
				"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
					"serviceAccountName": sa,
					"containers": []any{map[string]any{"name": "app", "image": "registry.example.com/app:1.0", "securityContext": sc,
						"resources": map[string]any{"limits": map[string]any{"memory": "256Mi", "cpu": "1"}}}},
				}}}})
		}
	}
	for i := 0; i < 200; i++ {
		add(map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": map[string]any{"name": fmt.Sprintf("viewer-%d", i)},
			"rules": []any{map[string]any{"apiGroups": []any{""}, "resources": []any{"configmaps"}, "verbs": []any{"get"}}}})
	}
	return inv
}

// TestScaleLargeCluster checks that a cluster of ~20,000 objects is assessed
// with every rule well within the time budget of a CI job or an admission
// controller's background scan. Skipped with -short.
func TestScaleLargeCluster(t *testing.T) {
	if testing.Short() {
		t.Skip("scale test")
	}
	inv := synthetic(200, 25)
	start := time.Now()
	r, _, err := hardex.Scan(hardex.ScanOptions{Inventory: inv, Profile: "restricted", Now: fixedNow})
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	t.Logf("%d objects, %d rules, %d findings in %s", r.ObjectsEvaluated, len(r.RulesEvaluated), r.Summary.Total, elapsed)
	if !r.Complete() {
		t.Fatal(r.Errors)
	}
	budget := 15 * time.Second
	if raceEnabled {
		budget *= 4
	}
	if elapsed > budget {
		t.Errorf("assessment took %s; budget is %s", elapsed, budget)
	}
}

func BenchmarkScan(b *testing.B) {
	for _, size := range []struct{ ns, per int }{{10, 10}, {50, 20}, {200, 25}} {
		inv := synthetic(size.ns, size.per)
		b.Run(fmt.Sprintf("%d-objects", len(inv.Objects)), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				if _, _, err := hardex.Scan(hardex.ScanOptions{Inventory: inv, Profile: "restricted", Now: fixedNow}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
