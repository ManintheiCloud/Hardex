package rbac

import (
	"strings"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

func evaluate(t *testing.T, y string, rules ...assessment.Rule) []string {
	t.Helper()
	inv, err := resource.Load([]string{"-"}, strings.NewReader(y))
	if err != nil {
		t.Fatal(err)
	}
	reg, _ := assessment.NewRegistry(rules...)
	var out []string
	for _, f := range assessment.Evaluate(inv, reg.All(), assessment.Options{}).Findings {
		out = append(out, f.RuleID+" "+f.Resource.Name+": "+f.Severity.String()+": "+f.Message)
	}
	return out
}

const podAs = `---
apiVersion: v1
kind: Pod
metadata: {name: p, namespace: app}
spec: {serviceAccountName: tool, containers: [{name: c, image: x}]}
`

func bindTool(role string) string {
	return `---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: b, namespace: app}
roleRef: {kind: ClusterRole, name: ` + role + `, apiGroup: rbac.authorization.k8s.io}
subjects: [{kind: ServiceAccount, name: tool}]
`
}

const secretsReader = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secrets-reader
  labels: {team.example/aggregate-to-ops: "true", rbac.authorization.k8s.io/aggregate-to-view: "true"}
rules: [{apiGroups: [""], resources: [secrets], verbs: [list]}]
`

// A custom aggregated ClusterRole has no rules of its own in a manifest;
// what it grants comes from the roles its selectors match.
func TestAggregatedRoleInInput(t *testing.T) {
	ops := `---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: ops}
aggregationRule:
  clusterRoleSelectors:
    - matchExpressions: [{key: team.example/aggregate-to-ops, operator: In, values: ["true"]}]
rules: []
`
	got := strings.Join(evaluate(t, secretsReader+ops+bindTool("ops")+podAs, reachableWorkloads), "\n")
	if !strings.Contains(got, "read secrets in namespace app (via RoleBinding b → ClusterRole ops)") {
		t.Errorf("aggregated permissions not followed:\n%s", got)
	}
}

// A label adding a role to the default view role grants its rules to
// everyone bound to view, which is not in the input.
func TestLabelAggregatesIntoDefault(t *testing.T) {
	got := strings.Join(evaluate(t, secretsReader+bindTool("view")+podAs, reachableWorkloads, secretsAccess), "\n")
	for _, want := range []string{
		"read secrets in namespace app (via RoleBinding b → ClusterRole view)",
		"HX-RBAC-003 secrets-reader: high: rule 0 grants list on all secrets in scope (aggregated into ClusterRole admin, edit, view: granted to everyone bound to it)",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	// Without the label, view grants no dangerous capability.
	if got := evaluate(t, bindTool("view")+podAs, reachableWorkloads); len(got) != 0 {
		t.Errorf("default view reported: %v", got)
	}
}

// The default roles are taken from the upstream policy: admin cannot
// escalate or bind (the old summary said it could), but edit and admin can
// impersonate service accounts and mint tokens.
func TestDefaultRolesFromUpstream(t *testing.T) {
	for role, want := range map[string][]string{
		"admin": {"impersonate other identities", "mint service account tokens", "read secrets", "create workloads"},
		"edit":  {"impersonate other identities", "mint service account tokens", "read secrets", "create workloads"},
	} {
		got := strings.Join(evaluate(t, bindTool(role)+podAs, reachableWorkloads), "\n")
		for _, w := range want {
			if !strings.Contains(got, w+" in namespace app (via RoleBinding b → ClusterRole "+role+")") {
				t.Errorf("%s: missing %q in:\n%s", role, w, got)
			}
		}
		if strings.Contains(got, "escalate") {
			t.Errorf("%s reported as able to escalate:\n%s", role, got)
		}
	}
	// Any default ClusterRole is known, not only these four.
	if got := strings.Join(evaluate(t, bindTool("system:controller:replicaset-controller")+podAs, reachableWorkloads), "\n"); !strings.Contains(got, "create workloads") {
		t.Errorf("default controller role not resolved:\n%s", got)
	}
}

// A role that aggregates others is not "named objects only" because its own
// rules are.
func TestBroadSubjectAggregatedRole(t *testing.T) {
	y := secretsReader + `---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: cert-reader}
aggregationRule:
  clusterRoleSelectors: [{matchLabels: {team.example/aggregate-to-ops: "true"}}]
rules: [{apiGroups: [""], resources: [services], resourceNames: [x], verbs: [get]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: everyone}
roleRef: {kind: ClusterRole, name: cert-reader, apiGroup: rbac.authorization.k8s.io}
subjects: [{kind: Group, name: "system:authenticated", apiGroup: rbac.authorization.k8s.io}]
`
	got := strings.Join(evaluate(t, y, broadSubjects), "\n")
	if !strings.Contains(got, "HX-RBAC-007 everyone: high:") {
		t.Errorf("aggregated role treated as narrow:\n%s", got)
	}
}

// Roles that aggregate each other do not loop.
func TestAggregationCycle(t *testing.T) {
	y := `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: a, labels: {agg: b}}
aggregationRule: {clusterRoleSelectors: [{matchLabels: {agg: a}}]}
rules: [{apiGroups: [""], resources: [secrets], verbs: [get]}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: b, labels: {agg: a}}
aggregationRule: {clusterRoleSelectors: [{matchLabels: {agg: b}}]}
rules: [{apiGroups: [""], resources: [pods/exec], verbs: [create]}]
`
	for _, role := range []string{"a", "b"} {
		got := strings.Join(evaluate(t, y+bindTool(role)+podAs, reachableWorkloads), "\n")
		if !strings.Contains(got, "read secrets") || !strings.Contains(got, "execute commands") {
			t.Errorf("%s: %s", role, got)
		}
	}
}

func TestSelectorMatches(t *testing.T) {
	labels := map[string]any{"a": "1", "b": "2"}
	for _, c := range []struct {
		sel  string
		want bool
	}{
		{`{}`, true},
		{`{matchLabels: {a: "1"}}`, true},
		{`{matchLabels: {a: "2"}}`, false},
		{`{matchExpressions: [{key: a, operator: In, values: ["1", "3"]}]}`, true},
		{`{matchExpressions: [{key: c, operator: In, values: ["1"]}]}`, false},
		{`{matchExpressions: [{key: a, operator: NotIn, values: ["1"]}]}`, false},
		{`{matchExpressions: [{key: c, operator: NotIn, values: ["1"]}]}`, true},
		{`{matchExpressions: [{key: b, operator: Exists}]}`, true},
		{`{matchExpressions: [{key: b, operator: DoesNotExist}]}`, false},
		{`{matchExpressions: [{key: b, operator: Gt, values: ["1"]}]}`, false},
	} {
		inv, err := resource.Load([]string{"-"}, strings.NewReader("kind: X\nmetadata: {name: s}\nsel: "+c.sel+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		if got := selectorMatches(resource.Map(inv.Objects[0].Raw, "sel"), labels); got != c.want {
			t.Errorf("%s: %v, want %v", c.sel, got, c.want)
		}
	}
}

// Aggregation is transitive through the defaults: view is aggregated into
// edit and edit into admin, so a role added to view reaches admin.
func TestAggregationThroughDefaults(t *testing.T) {
	y := `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: node-proxy
  labels: {rbac.authorization.k8s.io/aggregate-to-view: "true"}
rules: [{apiGroups: [""], resources: [nodes/proxy], verbs: [get]}]
`
	for _, role := range []string{"view", "edit", "admin"} {
		got := strings.Join(evaluate(t, y+bindTool(role)+podAs, reachableWorkloads), "\n")
		if !strings.Contains(got, "reach kubelets directly") {
			t.Errorf("%s does not include a role aggregated into view:\n%s", role, got)
		}
	}
}
