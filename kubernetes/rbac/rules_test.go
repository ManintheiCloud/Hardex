package rbac

import (
	"strings"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

func wildcardFindings(t *testing.T, rules string) []string {
	t.Helper()
	y := "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata: {name: r}\nrules: " + rules + "\n"
	inv, err := resource.Load([]string{"-"}, strings.NewReader(y))
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := assessment.NewRegistry(wildcards)
	var out []string
	for _, f := range assessment.Evaluate(inv, reg.All(), assessment.Options{}).Findings {
		out = append(out, f.Severity.String()+": "+f.Message)
	}
	return out
}

// Calibrated against real operator manifests (Calico's controller manages
// every resource of its own API groups).
func TestWildcardSeverity(t *testing.T) {
	cases := map[string]string{
		`[{apiGroups: [crd.projectcalico.org], resources: ["*"], verbs: [get, list]}]`:           "low",
		`[{apiGroups: [projectcalico.org, cert-manager.io], resources: ["*"], verbs: [create]}]`: "low",
		`[{apiGroups: [""], resources: ["*"], verbs: [get]}]`:                                    "high", // core: Secrets
		`[{apiGroups: [rbac.authorization.k8s.io], resources: ["*"], verbs: [create]}]`:          "high",
		`[{apiGroups: [apps], resources: ["*"], verbs: [get]}]`:                                  "high",
		`[{apiGroups: [crd.projectcalico.org], resources: [felixconfigurations], verbs: ["*"]}]`: "high", // verb wildcard: escalate, bind…
		`[{apiGroups: ["*"], resources: [pods], verbs: [get]}]`:                                  "high",
		`[{apiGroups: [crd.projectcalico.org, ""], resources: ["*"], verbs: [get]}]`:             "high",
	}
	for rules, want := range cases {
		got := wildcardFindings(t, rules)
		if len(got) != 1 || !strings.HasPrefix(got[0], want) {
			t.Errorf("%s: got %v, want %s", rules, got, want)
		}
	}
}

// Since Kubernetes 1.35, exec over WebSockets needs create on pods/exec;
// get on nodes/proxy still allows exec through the kubelet.
func TestExecNeedsCreateButNodesProxyGetIsEnough(t *testing.T) {
	got := reach(t, `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: reader}
rules: [{apiGroups: ["*"], resources: ["*"], verbs: [get, list, watch]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: reader}
roleRef: {kind: ClusterRole, name: reader, apiGroup: rbac.authorization.k8s.io}
subjects: [{kind: ServiceAccount, name: audit, namespace: app}]
---
apiVersion: v1
kind: Pod
metadata: {name: audit, namespace: app}
spec: {serviceAccountName: audit, containers: [{name: c, image: x}]}
`)
	joined := strings.Join(got, "\n")
	if strings.Contains(joined, "execute commands in other pods cluster-wide") {
		t.Errorf("get on pods/exec counted as exec: %s", joined)
	}
	if !strings.Contains(joined, "nodes/proxy; get is enough") {
		t.Errorf("get on nodes/proxy not reported: %s", joined)
	}
}

func TestOwnNamespaceSecretsAreMedium(t *testing.T) {
	grant := func(ns string) string {
		return `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: certs, namespace: ` + ns + `}
rules: [{apiGroups: [""], resources: [secrets], verbs: [get]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: certs, namespace: ` + ns + `}
roleRef: {kind: Role, name: certs, apiGroup: rbac.authorization.k8s.io}
subjects: [{kind: ServiceAccount, name: ctl, namespace: ops}]
---
apiVersion: v1
kind: Pod
metadata: {name: ctl, namespace: ops}
spec: {serviceAccountName: ctl, containers: [{name: c, image: x}]}
`
	}
	if got := strings.Join(reach(t, grant("ops")), "\n"); !strings.Contains(got, "ctl: medium") {
		t.Errorf("own namespace: %s", got)
	}
	if got := strings.Join(reach(t, grant("payments")), "\n"); !strings.Contains(got, "ctl: high") {
		t.Errorf("other namespace: %s", got)
	}
}
