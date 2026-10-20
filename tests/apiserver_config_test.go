package tests

import (
	"os"
	"path/filepath"
	"testing"
)

// The API server's structured configuration files decide authentication,
// authorization and encryption when their flags are set. These cases check
// the interplay of flags and files (k8s.io/apiserver/pkg/apis/apiserver/v1).
func TestAPIServerConfigFiles(t *testing.T) {
	pod := func(flags ...string) string {
		y := `apiVersion: v1
kind: Pod
metadata: {name: kube-apiserver, namespace: kube-system}
spec:
  containers:
    - name: kube-apiserver
      image: registry.k8s.io/kube-apiserver:v1.37.0
      command:
        - kube-apiserver
        - --authorization-mode=Node,RBAC
`
		for _, f := range flags {
			y += "        - " + f + "\n"
		}
		return y
	}
	cases := []struct {
		name  string
		files map[string]string
		rule  string
		want  int
	}{
		{"authn file without anonymous section: the flag default (true) applies", map[string]string{
			"pod.yaml":   pod("--authentication-config=/etc/kubernetes/authn.yaml"),
			"authn.yaml": "apiVersion: apiserver.config.k8s.io/v1\nkind: AuthenticationConfiguration\njwt: []\n",
		}, "HX-CP-001", 1},
		{"authn file without anonymous section, flag false", map[string]string{
			"pod.yaml":   pod("--authentication-config=/etc/kubernetes/authn.yaml", "--anonymous-auth=false"),
			"authn.yaml": "apiVersion: apiserver.config.k8s.io/v1\nkind: AuthenticationConfiguration\njwt: []\n",
		}, "HX-CP-001", 0},
		{"authn file disables anonymous", map[string]string{
			"pod.yaml":   pod("--authentication-config=/etc/kubernetes/authn.yaml"),
			"authn.yaml": "apiVersion: apiserver.config.k8s.io/v1\nkind: AuthenticationConfiguration\nanonymous: {enabled: false}\n",
		}, "HX-CP-001", 0},
		{"authn file enables anonymous everywhere", map[string]string{
			"authn.yaml": "apiVersion: apiserver.config.k8s.io/v1\nkind: AuthenticationConfiguration\nanonymous: {enabled: true}\n",
		}, "HX-CP-001", 1},
		{"authn flag set, file not in the input: not reported", map[string]string{
			"pod.yaml": pod("--authentication-config=/etc/kubernetes/authn.yaml"),
		}, "HX-CP-001", 0},
		{"authz file with Webhook only (no RBAC)", map[string]string{
			"authz.yaml": "apiVersion: apiserver.config.k8s.io/v1\nkind: AuthorizationConfiguration\nauthorizers:\n  - {type: Webhook, name: w}\n",
		}, "HX-CP-002", 1},
		{"encryption: catch-all entry before a secrets entry decides", map[string]string{
			"enc.yaml": "apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources:\n  - resources: ['*.*']\n    providers: [{identity: {}}]\n  - resources: [secrets]\n    providers: [{secretbox: {keys: [{name: k, secret: eA==}]}}]\n",
		}, "HX-CP-007", 1},
		{"encryption: core-group wildcard with aescbc first", map[string]string{
			"enc.yaml": "apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources:\n  - resources: ['*.']\n    providers: [{aescbc: {keys: [{name: k, secret: eA==}]}}, {identity: {}}]\n",
		}, "HX-CP-007", 0},
		{"encryption: only configmaps covered", map[string]string{
			"enc.yaml": "apiVersion: apiserver.config.k8s.io/v1\nkind: EncryptionConfiguration\nresources:\n  - resources: [configmaps]\n    providers: [{aescbc: {keys: [{name: k, secret: eA==}]}}]\n",
		}, "HX-CP-007", 1},
	}
	for _, c := range cases {
		dir := t.TempDir()
		for name, y := range c.files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(y), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		r := scan(t, "restricted", dir)
		n := 0
		for _, f := range r.Findings {
			if f.RuleID == c.rule {
				n++
			}
		}
		if n != c.want {
			t.Errorf("%s: %d %s findings, want %d", c.name, n, c.rule, c.want)
		}
	}
}
