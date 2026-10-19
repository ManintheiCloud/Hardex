package paths

import (
	"strings"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

func run(t *testing.T, y string) map[string]string {
	t.Helper()
	inv, err := resource.Load([]string{"-"}, strings.NewReader(y))
	if err != nil {
		t.Fatal(err)
	}
	res := assessment.Evaluate(inv, Rules(), assessment.Options{})
	if len(res.Errors) > 0 {
		t.Fatal(res.Errors)
	}
	out := map[string]string{}
	for _, f := range res.Findings {
		out[f.Resource.Name] = f.Severity.String() + ": " + f.Message
	}
	return out
}

const ci = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: ci-admin}
roleRef: {kind: ClusterRole, name: cluster-admin, apiGroup: rbac.authorization.k8s.io}
subjects: [{kind: ServiceAccount, name: deployer, namespace: ci}]
---
apiVersion: v1
kind: Pod
metadata: {name: runner, namespace: ci}
spec: {serviceAccountName: deployer, containers: [{name: c, image: x}]}
`

func role(ns, name, rules string) string {
	return `---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: ` + name + `, namespace: ` + ns + `}
rules: [` + rules + `]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: ` + name + `, namespace: ` + ns + `}
roleRef: {kind: Role, name: ` + name + `, apiGroup: rbac.authorization.k8s.io}
subjects: [{kind: ServiceAccount, name: app, namespace: app}]
`
}

const app = `---
apiVersion: v1
kind: Pod
metadata: {name: web, namespace: app}
spec: {serviceAccountName: app, containers: [{name: c, image: x}]}
`

func TestPaths(t *testing.T) {
	t.Run("pod creation reaches admin through another token", func(t *testing.T) {
		got := run(t, ci+app+role("ci", "deploy", `{apiGroups: [""], resources: [pods], verbs: [create]}`))
		if !strings.HasPrefix(got["web"], "critical") || !strings.Contains(got["web"], "creates a pod running as service account ci/deployer") {
			t.Errorf("got %q", got["web"])
		}
		if _, ok := got["runner"]; ok {
			t.Error("direct cluster-admin holder reported as a path (HX-RBAC-008 covers it)")
		}
	})
	t.Run("pod creation without enforcement reaches node root", func(t *testing.T) {
		got := run(t, app+role("app", "deploy", `{apiGroups: [""], resources: [pods], verbs: [create]}`))
		if !strings.HasPrefix(got["web"], "high") || !strings.Contains(got["web"], "does not enforce Pod Security") {
			t.Errorf("got %q", got["web"])
		}
	})
	t.Run("pod security enforcement breaks the chain", func(t *testing.T) {
		ns := "---\napiVersion: v1\nkind: Namespace\nmetadata: {name: app, labels: {pod-security.kubernetes.io/enforce: restricted}}\n"
		got := run(t, ns+app+role("app", "deploy", `{apiGroups: [""], resources: [pods], verbs: [create]}`))
		if f, ok := got["web"]; ok {
			t.Errorf("unexpected path: %s", f)
		}
	})
	t.Run("exec into an escapable pod", func(t *testing.T) {
		priv := "---\napiVersion: v1\nkind: Pod\nmetadata: {name: agent, namespace: app}\nspec: {automountServiceAccountToken: false, containers: [{name: c, image: x, securityContext: {privileged: true}}]}\n"
		got := run(t, ci+app+priv+role("app", "debug", `{apiGroups: [""], resources: [pods/exec], verbs: [create]}`))
		if !strings.HasPrefix(got["web"], "critical") || !strings.Contains(got["web"], "execs into Pod app/agent") {
			t.Errorf("got %q", got["web"])
		}
	})
	t.Run("no token, no escape, no path", func(t *testing.T) {
		quiet := "---\napiVersion: v1\nkind: Pod\nmetadata: {name: quiet, namespace: app}\nspec: {automountServiceAccountToken: false, containers: [{name: c, image: x}]}\n"
		got := run(t, ci+quiet+role("app", "deploy", `{apiGroups: [""], resources: [pods], verbs: [create]}`))
		if _, ok := got["quiet"]; ok {
			t.Error("workload without token or escape has a path")
		}
	})
}

const controller = `---
apiVersion: v1
kind: Pod
metadata: {name: runner, namespace: ci}
spec: {serviceAccountName: deployer, nodeSelector: {pool: system}, containers: [{name: c, image: x}]}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: ci-admin}
roleRef: {kind: ClusterRole, name: cluster-admin, apiGroup: rbac.authorization.k8s.io}
subjects: [{kind: ServiceAccount, name: deployer, namespace: ci}]
`

func escaper(selector string) string {
	return `---
apiVersion: v1
kind: Pod
metadata: {name: web, namespace: app}
spec: {serviceAccountName: app, automountServiceAccountToken: false, hostPID: true` + selector + `, containers: [{name: c, image: x}]}
`
}

func TestPlacement(t *testing.T) {
	t.Run("escape steals a token on a shared node", func(t *testing.T) {
		got := run(t, controller+escaper(""))
		if !strings.HasPrefix(got["web"], "critical") || !strings.Contains(got["web"], "same node") {
			t.Errorf("got %q", got["web"])
		}
	})
	t.Run("disjoint node pools break the chain", func(t *testing.T) {
		got := run(t, controller+escaper(", nodeSelector: {pool: apps}"))
		if _, ok := got["web"]; ok {
			t.Errorf("reported across disjoint pools: %q", got["web"])
		}
	})
	t.Run("affinity In overlapping the pool keeps the chain", func(t *testing.T) {
		aff := ", affinity: {nodeAffinity: {requiredDuringSchedulingIgnoredDuringExecution: {nodeSelectorTerms: [{matchExpressions: [{key: pool, operator: In, values: [apps, system]}]}]}}}"
		got := run(t, controller+escaper(aff))
		if !strings.HasPrefix(got["web"], "critical") {
			t.Errorf("got %q", got["web"])
		}
	})
	t.Run("compatible", func(t *testing.T) {
		a := placement{"pool": {"a": true}}
		b := placement{"pool": {"b": true}, "zone": {"z": true}}
		if a.compatible(b) || !a.compatible(nil) || !a.compatible(placement{"zone": {"z": true}}) {
			t.Error("compatible")
		}
	})
}

const irsa = `---
apiVersion: v1
kind: ServiceAccount
metadata: {name: uploader, namespace: data, annotations: {eks.amazonaws.com/role-arn: "arn:aws:iam::111122223333:role/s3-writer"}}
---
apiVersion: v1
kind: Pod
metadata: {name: uploader, namespace: data}
spec: {serviceAccountName: uploader, nodeSelector: {pool: data}, containers: [{name: c, image: x}]}
`

func TestCloudIdentity(t *testing.T) {
	t.Run("own identity is HX-PATH-002 only", func(t *testing.T) {
		got := run(t, irsa)
		if !strings.HasPrefix(got["uploader"], "low") || !strings.Contains(got["uploader"], "s3-writer") {
			t.Errorf("got %q", got["uploader"])
		}
	})
	t.Run("escape on a shared node reaches the cloud role", func(t *testing.T) {
		got := run(t, irsa+escaper(""))
		if !strings.HasPrefix(got["web"], "high") || !strings.Contains(got["web"], "a cloud identity") || !strings.Contains(got["web"], "AWS IAM role") {
			t.Errorf("got %q", got["web"])
		}
	})
	t.Run("azure needs the pod label", func(t *testing.T) {
		sa := "---\napiVersion: v1\nkind: ServiceAccount\nmetadata: {name: app, namespace: app, annotations: {azure.workload.identity/client-id: 00000000-0000-0000-0000-000000000001}}\n"
		unlabelled := run(t, sa+app)
		if _, ok := unlabelled["web"]; ok {
			t.Errorf("unlabelled pod reported: %q", unlabelled["web"])
		}
		labelled := run(t, sa+strings.Replace(app, "namespace: app}", "namespace: app, labels: {azure.workload.identity/use: \"true\"}}", 1))
		if !strings.Contains(labelled["web"], "Azure managed identity") {
			t.Errorf("got %q", labelled["web"])
		}
	})
}
