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
	// Since Kubernetes 1.35 the API server authorizes exec and attach over
	// WebSockets as "create" (AuthorizePodWebsocketUpgradeCreatePermission),
	// so "get" alone no longer grants them.
	{"execute commands in other pods", finding.High, []grant{{groups: []string{""}, resources: []string{"pods/exec", "pods/attach"}, verbs: []string{"create"}}}},
	{"mint service account tokens", finding.High, []grant{{groups: []string{""}, resources: []string{"serviceaccounts/token"}, verbs: []string{"create"}}}},
	// The kubelet authorizes a WebSocket exec (GET /exec/...) as "get
	// nodes/proxy", with no create check, so read access is enough.
	{"reach kubelets directly (nodes/proxy; get is enough to exec in any pod)", finding.High, []grant{{groups: []string{""}, resources: []string{"nodes/proxy"}, verbs: []string{"get", "create"}}}},
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

// Capability identifies a class of dangerous permission (an index into
// capabilities).
type Capability int

const (
	CapFullControl Capability = iota
	CapEscalate
	CapImpersonate
	CapReadSecrets
	CapExec
	CapMintTokens
	CapNodeProxy
	CapCreateWorkloads
)

// Name describes the capability.
func (c Capability) Name() string { return capabilities[c].name }

// Severity is the impact of holding the capability.
func (c Capability) Severity() finding.Severity { return capabilities[c].severity }

// Permission is one dangerous capability held by a service account.
type Permission struct {
	Cap Capability
	// Namespace is where it applies; "" means cluster-wide.
	Namespace string
	// Via names the binding and role that grant it.
	Via string
}

// Scope renders the namespace for messages.
func (p Permission) Scope() string {
	if p.Namespace == "" {
		return "cluster-wide"
	}
	return "in namespace " + p.Namespace
}

// Index answers "what can this service account do?" for an inventory. It
// is built once per evaluation so that analysing many workloads stays linear.
type Index struct {
	inv *resource.Inventory
	// bySubject maps a subject key ("sa:ns/name" or "group:name") to the
	// bindings naming it, so lookups do not scan every binding.
	bySubject map[string][]*indexedBinding
	automount map[string]bool // ns/name -> explicit ServiceAccount setting
	cache     map[string][]Permission
}

type indexedBinding struct {
	obj   *resource.Object
	rules []map[string]any
	role  string
}

// NewIndex builds an index over the inventory's RBAC objects.
func NewIndex(inv *resource.Inventory) *Index {
	idx := &Index{inv: inv, bySubject: map[string][]*indexedBinding{}, automount: map[string]bool{}, cache: map[string][]Permission{}}
	roles := map[string]*resource.Object{}
	for _, r := range inv.OfKind("Role", "ClusterRole") {
		roles[r.Kind+"/"+r.EffectiveNamespace()+"/"+r.Name] = r
	}
	for _, b := range inv.OfKind("RoleBinding", "ClusterRoleBinding") {
		refKind, refName := resource.String(b.Raw, "roleRef", "kind"), resource.String(b.Raw, "roleRef", "name")
		ib := indexedBinding{obj: b, role: refKind + " " + refName}
		lookupNS := ""
		if refKind == "Role" {
			lookupNS = b.EffectiveNamespace()
		}
		if r, ok := roles[refKind+"/"+lookupNS+"/"+refName]; ok {
			ib.rules = resource.Maps(r.Raw, "rules")
		} else if builtin, ok := builtinRoles[refName]; ok && refKind == "ClusterRole" {
			ib.rules = builtin
		} else {
			continue // role not in input; nothing can be concluded
		}
		bound := &ib
		seen := map[string]bool{}
		for _, subj := range resource.Maps(b.Raw, "subjects") {
			key := subjectKey(b, subj)
			if key != "" && !seen[key] {
				seen[key] = true
				idx.bySubject[key] = append(idx.bySubject[key], bound)
			}
		}
	}
	for _, o := range inv.OfKind("ServiceAccount") {
		if v, set := resource.Bool(o.Raw, "automountServiceAccountToken"); set {
			idx.automount[o.EffectiveNamespace()+"/"+o.Name] = v
		}
	}
	return idx
}

// Permissions returns the dangerous capabilities of a service account.
// Full control subsumes everything else and is reported alone per binding.
func (idx *Index) Permissions(ns, sa string) []Permission {
	key := ns + "/" + sa
	if p, ok := idx.cache[key]; ok {
		return p
	}
	var out []Permission
	seen := map[*indexedBinding]bool{}
	for _, subj := range []string{"sa:" + ns + "/" + sa, "group:system:serviceaccounts", "group:system:serviceaccounts:" + ns, "group:system:authenticated"} {
		for _, b := range idx.bySubject[subj] {
			if seen[b] {
				continue
			}
			seen[b] = true
			scope := ""
			if b.obj.Kind == "RoleBinding" {
				scope = b.obj.EffectiveNamespace()
			}
			via := b.obj.Kind + " " + b.obj.Name + " → " + b.role
			for ci, c := range capabilities {
				if grantsAny(b.rules, c.grants) {
					out = append(out, Permission{Cap: Capability(ci), Namespace: scope, Via: via})
					if ci == int(CapFullControl) {
						break
					}
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Via < out[j].Via })
	idx.cache[key] = out
	return out
}

func grantsAny(rules []map[string]any, grants []grant) bool {
	for _, r := range rules {
		for _, g := range grants {
			if effectiveMatch(r, g) {
				return true
			}
		}
	}
	return false
}

// subjectKey identifies a binding subject that can match a service account.
func subjectKey(b *resource.Object, s map[string]any) string {
	kind, name := resource.String(s, "kind"), resource.String(s, "name")
	switch kind {
	case "ServiceAccount":
		ns := resource.String(s, "namespace")
		if ns == "" && b.Kind == "RoleBinding" {
			ns = b.EffectiveNamespace()
		}
		return "sa:" + ns + "/" + name
	case "Group":
		if name == "system:serviceaccounts" || name == "system:authenticated" || strings.HasPrefix(name, "system:serviceaccounts:") {
			return "group:" + name
		}
	}
	return ""
}

// ServiceAccountOf returns the workload's service account name.
func ServiceAccountOf(pod map[string]any) string {
	if sa := resource.String(pod, "serviceAccountName"); sa != "" {
		return sa
	}
	return "default"
}

// TokenMounted reports whether pods of the workload receive an API token.
func (idx *Index) TokenMounted(obj *resource.Object, pod map[string]any) bool {
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
	if v, set := idx.automount[obj.EffectiveNamespace()+"/"+ServiceAccountOf(pod)]; set {
		return v
	}
	return true
}

var reachableWorkloads = assessment.InventoryRule{
	Meta: assessment.Metadata{
		ID:             "HX-RBAC-008",
		Title:          "Workload holds dangerous API permissions",
		Severity:       finding.High,
		Category:       assessment.CategoryRBAC,
		Description:    "Follows each workload's service account through RoleBindings and ClusterRoleBindings to the permissions its mounted token carries, and reports workloads that can read secrets (high; medium when only in the workload's own namespace), exec into pods, mint tokens, reach kubelets, create workloads (medium), escalate or impersonate, or control everything (critical).",
		Rationale:      "Container compromise is common; what matters is what the stolen token can do next. A web server whose service account can read every secret turns one application bug into a cluster-wide breach.",
		Remediation:    "Give the workload a dedicated service account bound only to what it needs, or set automountServiceAccountToken: false if it never calls the API. Remove broad grants found through the listed binding.",
		References:     []finding.Reference{refCISRBAC, refNSAAuth, baselines.K8s("RBAC good practices", "https://kubernetes.io/docs/concepts/security/rbac-good-practices/")},
		Limitations:    "Only bindings and roles present in the input are followed (plus the default cluster-admin, admin, edit and view ClusterRoles). Aggregated ClusterRoles, cloud IAM mappings and webhook authorizers are not evaluated. Workloads in kube-system are skipped unless --include-system is set.",
		NeedsInventory: true,
	},
	Check: func(ctx *assessment.Context) {
		idx := NewIndex(ctx.Inventory)
		for _, obj := range ctx.Inventory.Objects {
			pod, prefix := resource.PodSpec(obj)
			if pod == nil || (obj.EffectiveNamespace() == "kube-system" && !ctx.Options.IncludeSystem) {
				continue
			}
			if !idx.TokenMounted(obj, pod) {
				continue
			}
			sa := ServiceAccountOf(pod)
			worst := finding.Severity(-1)
			var found []string
			seen := map[string]bool{}
			for _, p := range idx.Permissions(obj.EffectiveNamespace(), sa) {
				desc := fmt.Sprintf("%s %s (via %s)", p.Cap.Name(), p.Scope(), p.Via)
				if !seen[desc] {
					seen[desc] = true
					found = append(found, desc)
				}
				capSev := p.Cap.Severity()
				if p.Cap == CapReadSecrets && p.Namespace == obj.EffectiveNamespace() && capSev > finding.Medium {
					// Controllers commonly keep their own certificates in
					// their namespace; reading only those Secrets exposes
					// less than reading other namespaces' (but still any
					// token Secrets there, so not less than medium).
					capSev = finding.Medium
				}
				if capSev > worst {
					worst = capSev
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
