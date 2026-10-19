package rbac

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// Reachability: which workloads actually hold dangerous permissions?
//
// HX-RBAC-001..007 judge roles and bindings in isolation. HX-RBAC-008 follows
// the chain an attacker follows after compromising a container:
// workload → service account token → bindings → roles → permissions.

// capability is a class of dangerous permission.
type capability struct {
	name     string
	severity finding.Severity
	grants   []grant
}

var capabilities = []capability{
	{"full control of all resources", finding.Critical, []grant{{groups: []string{"*"}, resources: []string{"*"}, verbs: []string{"*"}}}},
	{"grant itself any permission (escalate/bind)", finding.Critical, []grant{{groups: []string{"rbac.authorization.k8s.io"}, resources: []string{"roles", "clusterroles"}, verbs: []string{"escalate", "bind"}}}},
	{"impersonate other identities", finding.Critical, []grant{{groups: []string{"", "authentication.k8s.io"}, resources: []string{"users", "groups", "serviceaccounts"}, verbs: []string{"impersonate"}}}},
	{"read secrets", finding.High, []grant{{groups: []string{""}, resources: []string{"secrets"}, verbs: []string{"get", "list", "watch"}}}},
	{"execute commands in other pods", finding.High, []grant{{groups: []string{""}, resources: []string{"pods/exec", "pods/attach"}, verbs: []string{"create", "get"}}}},
	{"mint service account tokens", finding.High, []grant{{groups: []string{""}, resources: []string{"serviceaccounts/token"}, verbs: []string{"create"}}}},
	{"reach kubelets directly (nodes/proxy)", finding.High, []grant{{groups: []string{""}, resources: []string{"nodes/proxy"}, verbs: []string{"get", "create"}}}},
	{"create workloads", finding.Medium, []grant{
		{groups: []string{""}, resources: []string{"pods"}, verbs: []string{"create"}},
		{groups: []string{"apps"}, resources: []string{"deployments", "daemonsets", "statefulsets"}, verbs: []string{"create"}},
		{groups: []string{"batch"}, resources: []string{"jobs", "cronjobs"}, verbs: []string{"create"}},
	}},
}

// Default ClusterRoles that are usually not part of a manifest set but are
// commonly bound. Their rules are summarised by the capabilities they carry.
var builtinRoles = map[string][]map[string]any{
	"cluster-admin": {rule([]string{"*"}, []string{"*"}, []string{"*"})},
	"admin": {
		rule([]string{""}, []string{"secrets"}, []string{"get", "list", "watch"}),
		rule([]string{""}, []string{"pods/exec", "pods/attach"}, []string{"create", "get"}),
		rule([]string{""}, []string{"pods"}, []string{"create"}),
		rule([]string{"rbac.authorization.k8s.io"}, []string{"roles"}, []string{"bind", "escalate"}),
	},
	"edit": {
		rule([]string{""}, []string{"secrets"}, []string{"get", "list", "watch"}),
		rule([]string{""}, []string{"pods/exec", "pods/attach"}, []string{"create", "get"}),
		rule([]string{""}, []string{"pods"}, []string{"create"}),
	},
	"view": {},
}

func rule(groups, resources, verbs []string) map[string]any {
	toAny := func(s []string) []any {
		out := make([]any, len(s))
		for i, v := range s {
			out[i] = v
		}
		return out
	}
	return map[string]any{"apiGroups": toAny(groups), "resources": toAny(resources), "verbs": toAny(verbs)}
}

// effectiveMatch is wildcard-aware: unlike HX-RBAC-003..006, reachability
// must count a permission however it is expressed.
func effectiveMatch(r map[string]any, g grant) bool {
	if len(resource.Strings(r, "resourceNames")) > 0 {
		return false
	}
	groupOK := false
	for _, have := range resource.Strings(r, "apiGroups") {
		if have == "*" || contains(g.groups, have) {
			groupOK = true
		}
	}
	if !groupOK {
		return false
	}
	resOK := false
	for _, have := range resource.Strings(r, "resources") {
		for _, want := range g.resources {
			if resourceMatches(have, want) {
				resOK = true
			}
		}
	}
	if !resOK {
		return false
	}
	for _, have := range resource.Strings(r, "verbs") {
		if have == "*" || contains(g.verbs, have) {
			return true
		}
	}
	return false
}

func resourceMatches(have, want string) bool {
	if have == "*" || have == want {
		return true
	}
	if parent, sub, ok := strings.Cut(want, "/"); ok {
		return have == parent+"/*" || have == "*/"+sub
	}
	return false
}

// binding is one path from a subject to a role.
type binding struct {
	obj   *resource.Object
	rules []map[string]any
	role  string
	scope string // "cluster-wide" or "in namespace X"
}

func bindingsFor(inv *resource.Inventory, ns, sa string) []binding {
	roles := map[string]*resource.Object{}
	for _, r := range inv.OfKind("Role", "ClusterRole") {
		roles[r.Kind+"/"+r.EffectiveNamespace()+"/"+r.Name] = r
	}
	var out []binding
	for _, b := range inv.OfKind("RoleBinding", "ClusterRoleBinding") {
		if !subjectsInclude(b, ns, sa) {
			continue
		}
		refKind, refName := resource.String(b.Raw, "roleRef", "kind"), resource.String(b.Raw, "roleRef", "name")
		bd := binding{obj: b, role: refKind + " " + refName, scope: "cluster-wide"}
		if b.Kind == "RoleBinding" {
			bd.scope = "in namespace " + b.EffectiveNamespace()
		}
		lookupNS := ""
		if refKind == "Role" {
			lookupNS = b.EffectiveNamespace()
		}
		if r, ok := roles[refKind+"/"+lookupNS+"/"+refName]; ok {
			bd.rules = resource.Maps(r.Raw, "rules")
		} else if builtin, ok := builtinRoles[refName]; ok && refKind == "ClusterRole" {
			bd.rules = builtin
		} else {
			continue // role not in input; nothing can be concluded
		}
		out = append(out, bd)
	}
	return out
}

func subjectsInclude(b *resource.Object, ns, sa string) bool {
	for _, s := range resource.Maps(b.Raw, "subjects") {
		kind, name := resource.String(s, "kind"), resource.String(s, "name")
		subjNS := resource.String(s, "namespace")
		if subjNS == "" && b.Kind == "RoleBinding" {
			subjNS = b.EffectiveNamespace()
		}
		switch {
		case kind == "ServiceAccount" && name == sa && subjNS == ns:
			return true
		case kind == "Group" && (name == "system:serviceaccounts" || name == "system:serviceaccounts:"+ns || name == "system:authenticated"):
			return true
		}
	}
	return false
}

// tokenMounted reports whether pods of the workload receive an API token.
func tokenMounted(inv *resource.Inventory, obj *resource.Object, pod map[string]any, sa string) bool {
	for _, v := range resource.Maps(pod, "volumes") {
		for _, src := range resource.Maps(v, "projected", "sources") {
			if resource.Map(src, "serviceAccountToken") != nil {
				return true
			}
		}
	}
	if v, set := resource.Bool(pod, "automountServiceAccountToken"); set {
		return v
	}
	for _, o := range inv.OfKind("ServiceAccount") {
		if o.Name == sa && o.EffectiveNamespace() == obj.EffectiveNamespace() {
			if v, set := resource.Bool(o.Raw, "automountServiceAccountToken"); set {
				return v
			}
		}
	}
	return true
}

var reachableWorkloads = assessment.InventoryRule{
	Meta: assessment.Metadata{
		ID:          "HX-RBAC-008",
		Title:       "Workload holds dangerous API permissions",
		Severity:    finding.High,
		Category:    assessment.CategoryRBAC,
		Description: "Follows each workload's service account through RoleBindings and ClusterRoleBindings to the permissions its mounted token carries, and reports workloads that can read secrets, exec into pods, mint tokens, reach kubelets, create workloads (medium), escalate or impersonate, or control everything (critical).",
		Rationale:   "Container compromise is common; what matters is what the stolen token can do next. A web server whose service account can read every secret turns one application bug into a cluster-wide breach.",
		Remediation: "Give the workload a dedicated service account bound only to what it needs, or set automountServiceAccountToken: false if it never calls the API. Remove broad grants found through the listed binding.",
		References:  []finding.Reference{refCISRBAC, refNSAAuth, baselines.K8s("RBAC good practices", "https://kubernetes.io/docs/concepts/security/rbac-good-practices/")},
		Limitations: "Only bindings and roles present in the input are followed (plus the default cluster-admin, admin, edit and view ClusterRoles). Aggregated ClusterRoles, cloud IAM mappings and webhook authorizers are not evaluated. Workloads in kube-system are skipped unless --include-system is set.",
	},
	Check: func(ctx *assessment.Context) {
		for _, obj := range ctx.Inventory.Objects {
			pod, prefix := resource.PodSpec(obj)
			if pod == nil || (obj.EffectiveNamespace() == "kube-system" && !ctx.Options.IncludeSystem) {
				continue
			}
			sa := resource.String(pod, "serviceAccountName")
			if sa == "" {
				sa = "default"
			}
			if !tokenMounted(ctx.Inventory, obj, pod, sa) {
				continue
			}
			worst := finding.Severity(-1)
			var found []string
			seen := map[string]bool{}
			for _, b := range bindingsFor(ctx.Inventory, obj.EffectiveNamespace(), sa) {
			capLoop:
				for i, c := range capabilities {
					for _, r := range b.rules {
						matched := false
						for _, g := range c.grants {
							if effectiveMatch(r, g) {
								matched = true
							}
						}
						if !matched {
							continue
						}
						desc := fmt.Sprintf("%s %s (via %s %s → %s)", c.name, b.scope, b.obj.Kind, b.obj.Name, b.role)
						if !seen[desc] {
							seen[desc] = true
							found = append(found, desc)
						}
						if c.severity > worst {
							worst = c.severity
						}
						if i == 0 {
							// Full control subsumes every other capability.
							break capLoop
						}
						break
					}
				}
			}
			if len(found) == 0 {
				continue
			}
			sort.Strings(found)
			sev := worst
			ctx.Report(assessment.Hit{Object: obj, Path: prefix + ".serviceAccountName", Observed: obj.EffectiveNamespace() + "/" + sa,
				Severity: &sev,
				Message:  fmt.Sprintf("pods run as service account %s/%s, whose token can: %s", obj.EffectiveNamespace(), sa, strings.Join(found, "; "))})
		}
	},
}
