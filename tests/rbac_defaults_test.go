package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Default RBAC objects are not reported only when they grant no more than
// their default definition; names and labels alone are not trusted.
func TestRBACDefaultsVerifiedByContent(t *testing.T) {
	docs := []string{
		// Genuine defaults: not reported.
		`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: cluster-admin, labels: {kubernetes.io/bootstrapping: rbac-defaults}}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects: [{apiGroup: rbac.authorization.k8s.io, kind: Group, name: "system:masters"}]`,
		`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: "kubeadm:cluster-admins"}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects: [{apiGroup: rbac.authorization.k8s.io, kind: Group, name: "kubeadm:cluster-admins"}]`,
		`apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: "kubeadm:bootstrap-signer-clusterinfo", namespace: kube-public}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: "kubeadm:bootstrap-signer-clusterinfo"}
subjects: [{apiGroup: rbac.authorization.k8s.io, kind: User, name: "system:anonymous"}]`,
		// A binding that only looks like a default.
		`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: "system:backdoor"}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects: [{kind: ServiceAccount, name: tool, namespace: shop}]`,
		// A binding labelled as a default.
		`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: helper, labels: {kubernetes.io/bootstrapping: rbac-defaults}}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: cluster-admin}
subjects: [{kind: ServiceAccount, name: helper, namespace: shop}]`,
		// A default binding with an added subject.
		`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: "system:basic-user", labels: {kubernetes.io/bootstrapping: rbac-defaults}}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: "system:basic-user"}
subjects: [{apiGroup: rbac.authorization.k8s.io, kind: Group, name: "system:authenticated"}, {apiGroup: rbac.authorization.k8s.io, kind: Group, name: "system:unauthenticated"}]`,
		// A default role with an added permission.
		`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: "system:discovery", labels: {kubernetes.io/bootstrapping: rbac-defaults}}
rules:
  - {nonResourceURLs: [/api, /api/*, /apis, /apis/*, /healthz, /livez, /openapi, /openapi/*, /readyz, /version, /version/], verbs: [get]}
  - {apiGroups: [""], resources: [secrets], verbs: [get, list]}`,
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rbac.yaml"), []byte(strings.Join(docs, "\n---\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	r := scan(t, "restricted", dir)
	got := map[string]bool{}
	for _, f := range r.Findings {
		got[f.Resource.Kind+"/"+f.Resource.Name] = true
	}
	for _, name := range []string{"ClusterRoleBinding/cluster-admin", "ClusterRoleBinding/kubeadm:cluster-admins", "RoleBinding/kubeadm:bootstrap-signer-clusterinfo"} {
		if got[name] {
			t.Errorf("genuine default %s reported", name)
		}
	}
	for _, name := range []string{"ClusterRoleBinding/system:backdoor", "ClusterRoleBinding/helper", "ClusterRoleBinding/system:basic-user", "ClusterRole/system:discovery"} {
		if !got[name] {
			t.Errorf("%s not reported: a default name or label must not hide it", name)
		}
	}
}
