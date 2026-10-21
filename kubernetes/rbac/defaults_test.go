package rbac

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/resource"
)

func loadPolicy(t *testing.T) []*resource.Object {
	t.Helper()
	files, _ := filepath.Glob("testdata/bootstrappolicy-1.37/*.yaml")
	files = append(files, "../../tools/rbac-defaults/kubeadm.yaml")
	var objs []*resource.Object
	for _, f := range files {
		inv, err := resource.Load([]string{f}, nil)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		objs = append(objs, inv.Objects...)
	}
	return objs
}

// Every genuine default is recognised, and adding one subject or one
// permission to any of them makes it an ordinary object.
func TestDefaultsRecognisedByContent(t *testing.T) {
	objs := loadPolicy(t)
	if len(objs) < 150 {
		t.Fatalf("only %d upstream objects loaded", len(objs))
	}
	for _, o := range objs {
		switch o.Kind {
		case "ClusterRole", "Role", "ClusterRoleBinding", "RoleBinding":
		default:
			continue
		}
		if !isSystem(o) {
			t.Errorf("genuine default %s not recognised", objectKey(o))
			continue
		}
		mod := &resource.Object{Kind: o.Kind, Name: o.Name, Namespace: o.Namespace, Raw: deepCopy(o.Raw).(map[string]any)}
		switch o.Kind {
		case "ClusterRoleBinding", "RoleBinding":
			subs, _ := mod.Raw["subjects"].([]any)
			mod.Raw["subjects"] = append(subs, map[string]any{"kind": "ServiceAccount", "name": "intruder", "namespace": "shop"})
		default:
			if _, agg := mod.Raw["aggregationRule"]; agg {
				continue // rules come from the aggregated roles, each assessed
			}
			if covered("|secrets|*|create", nil) {
				t.Fatal("covered() with no defaults")
			}
			rules, _ := mod.Raw["rules"].([]any)
			mod.Raw["rules"] = append(rules, map[string]any{"apiGroups": []any{"intruder.example"}, "resources": []any{"things"}, "verbs": []any{"escalate"}})
			if allowed := loadDefaults().Roles[objectKey(o)]; covered("intruder.example|things|*|escalate", allowed) {
				continue // the default already grants everything (cluster-admin)
			}
		}
		if isSystem(mod) {
			t.Errorf("%s with an added grant still treated as a default", objectKey(o))
		}
	}
}

// Names and labels that look like defaults are not enough.
func TestDefaultNamesAndLabelsNotTrusted(t *testing.T) {
	inv, err := resource.Load([]string{"-"}, strings.NewReader(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: "system:backdoor", labels: {kubernetes.io/bootstrapping: rbac-defaults}}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects: [{kind: ServiceAccount, name: tool, namespace: shop}]
`))
	if err != nil {
		t.Fatal(err)
	}
	if isSystem(inv.Objects[0]) {
		t.Error("an unknown system:-named, default-labelled binding was trusted")
	}
	if _, err := os.Stat("defaults.json"); err != nil {
		t.Fatal(err)
	}
}

func deepCopy(v any) any {
	b, _ := json.Marshal(v)
	var out any
	json.Unmarshal(b, &out)
	return out
}
