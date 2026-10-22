package rbac

import (
	"strings"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

const reachBase = `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: debug, namespace: app}
rules:
  - apiGroups: [""]
    resources: ["pods/*"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: debug, namespace: app}
roleRef: {kind: Role, name: debug, apiGroup: rbac.authorization.k8s.io}
subjects:
  - {kind: Group, name: "system:serviceaccounts:app", apiGroup: rbac.authorization.k8s.io}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: editors, namespace: app}
roleRef: {kind: ClusterRole, name: edit, apiGroup: rbac.authorization.k8s.io}
subjects:
  - {kind: ServiceAccount, name: tool}
`

func reach(t *testing.T, workloads string) []string {
	t.Helper()
	inv, err := resource.Load([]string{"-"}, strings.NewReader(reachBase+"---\n"+workloads))
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := assessment.NewRegistry(reachableWorkloads)
	res := assessment.Evaluate(inv, reg.All(), assessment.Options{})
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.Resource.Name+": "+f.Severity.String()+": "+f.Message)
	}
	return out
}

func TestReachability(t *testing.T) {
	got := reach(t, `apiVersion: v1
kind: Pod
metadata: {name: viagroup, namespace: app}
spec: {containers: [{name: c, image: x}]}
---
apiVersion: v1
kind: Pod
metadata: {name: viabuiltin, namespace: app}
spec: {serviceAccountName: tool, containers: [{name: c, image: x}]}
---
apiVersion: v1
kind: Pod
metadata: {name: notoken, namespace: app}
spec: {automountServiceAccountToken: false, containers: [{name: c, image: x}]}
---
apiVersion: v1
kind: Pod
metadata: {name: projected, namespace: app}
spec:
  automountServiceAccountToken: false
  containers: [{name: c, image: x}]
  volumes: [{name: t, projected: {sources: [{serviceAccountToken: {path: token}}]}}]
---
apiVersion: v1
kind: Pod
metadata: {name: othernamespace, namespace: other}
spec: {containers: [{name: c, image: x}]}
`)
	joined := strings.Join(got, "\n")
	for _, want := range []string{
		"viagroup: high: ", "execute commands in other pods in namespace app (via RoleBinding debug",
		// The default edit role (not in the input) as Kubernetes defines it:
		// it can impersonate service accounts and mint their tokens.
		"viabuiltin: critical: ", "read secrets in namespace app (via RoleBinding editors → ClusterRole edit)",
		"impersonate other identities in namespace app (via RoleBinding editors → ClusterRole edit)",
		"mint service account tokens in namespace app (via RoleBinding editors → ClusterRole edit)",
		"projected: high:",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
	for _, unwanted := range []string{"notoken", "othernamespace"} {
		if strings.Contains(joined, unwanted+":") {
			t.Errorf("%s should not be reported:\n%s", unwanted, joined)
		}
	}
}
