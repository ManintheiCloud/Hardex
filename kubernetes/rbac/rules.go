// Package rbac implements checks on Roles, ClusterRoles and their bindings:
// excessive grants, privilege-escalation paths and overly broad subjects.
//
// To avoid reporting one grant several times, the specific-permission rules
// (HX-RBAC-003 to 006) evaluate explicit grants only; any grant expressed
// through a wildcard is reported once, by HX-RBAC-001.
package rbac

import (
	"fmt"
	"strings"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// Rules returns every RBAC rule.
func Rules() []assessment.Rule {
	return []assessment.Rule{wildcards, clusterAdminBinding, secretsAccess, escalationVerbs, sensitiveSubresources, workloadCreation, broadSubjects, reachableWorkloads}
}

var (
	refCISRBAC = baselines.CIS("5.1", "RBAC and Service Accounts")
	refNSAAuth = baselines.NSA("Authentication and authorization")
	sevHigh    = assessment.SeverityOverride(finding.High)
	sevMedium  = assessment.SeverityOverride(finding.Medium)
	sevLow     = assessment.SeverityOverride(finding.Low)
	sevCrit    = assessment.SeverityOverride(finding.Critical)
)

func roleObjects(ctx *assessment.Context) []*resource.Object {
	var out []*resource.Object
	for _, o := range ctx.Inventory.OfKind("Role", "ClusterRole") {
		if !ctx.Options.IncludeSystem && isSystem(o) {
			continue
		}
		out = append(out, o)
	}
	return out
}

// grant is one (apiGroup, resource, verb) permission requested by a check.
type grant struct {
	groups    []string
	resources []string
	verbs     []string
}

// explicitMatch reports whether the policy rule grants any of the requested
// permissions without relying on a wildcard.
func explicitMatch(rule map[string]any, g grant) (resourceMatched, verbMatched string, ok bool) {
	if len(resource.Strings(rule, "resourceNames")) > 0 {
		return "", "", false // limited to named objects: not a broad grant
	}
	if !intersects(resource.Strings(rule, "apiGroups"), g.groups) {
		return "", "", false
	}
	for _, r := range resource.Strings(rule, "resources") {
		if !contains(g.resources, r) {
			continue
		}
		for _, v := range resource.Strings(rule, "verbs") {
			if contains(g.verbs, v) {
				return r, v, true
			}
		}
	}
	return "", "", false
}

func intersects(a, b []string) bool {
	for _, x := range a {
		if contains(b, x) {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func scopeSeverity(o *resource.Object, cluster, namespaced *finding.Severity) *finding.Severity {
	if o.Kind == "ClusterRole" {
		return cluster
	}
	return namespaced
}

var wildcards = assessment.InventoryRule{
	Meta: assessment.Metadata{
		ID:          "HX-RBAC-001",
		Title:       "Wildcard RBAC permission",
		Severity:    finding.High,
		Category:    assessment.CategoryRBAC,
		Description: "Detects Roles and ClusterRoles that use \"*\" in verbs, resources or apiGroups. High for ClusterRoles, medium for Roles; low when the wildcards are resources or verbs within extension API groups (an operator's own CRDs) or the metrics APIs, which cannot reach built-in objects; medium (low for Roles) when an API group wildcard covers only scale subresources.",
		Rationale:   "Wildcards grant every current and future permission in scope, including secrets, escalation verbs and resources introduced later by CRDs. They make least privilege impossible to verify.",
		Remediation: "Replace wildcards with the explicit verbs, resources and API groups the subject needs.",
		References:  []finding.Reference{refCISRBAC, refNSAAuth},
		Limitations: "Roles are reported whether or not they are bound; an unbound role is latent risk.",
	},
	Check: func(ctx *assessment.Context) {
		for _, o := range roleObjects(ctx) {
			for i, rule := range resource.Maps(o.Raw, "rules") {
				var fields []string
				for _, f := range []string{"apiGroups", "resources", "verbs"} {
					if contains(resource.Strings(rule, f), "*") {
						fields = append(fields, f)
					}
				}
				if len(fields) == 0 {
					continue
				}
				sev := scopeSeverity(o, sevHigh, sevMedium)
				msg := fmt.Sprintf("rule %d uses a wildcard in %s", i, strings.Join(fields, ", "))
				groups := resource.Strings(rule, "apiGroups")
				switch {
				case !contains(fields, "apiGroups") && thirdPartyGroups(groups):
					// Every resource and/or verb of a project's own API groups
					// (typically an operator managing its CRDs), or of the
					// read-only metrics APIs: still a wildcard, but it cannot
					// reach Secrets, workloads or RBAC, and escalate, bind and
					// impersonate mean nothing there.
					sev = sevLow
					msg += " (limited to the API group " + strings.Join(groups, ", ") + ")"
				case contains(fields, "apiGroups") && onlyScaleSubresource(resource.Strings(rule, "resources")) && !contains(fields, "verbs"):
					// The scale subresource of everything (autoscalers): can
					// resize workloads, cannot read data or escalate.
					sev = scopeSeverity(o, sevMedium, sevLow)
					msg += " (scale subresources only)"
				}
				ctx.Report(assessment.Hit{Object: o, Path: fmt.Sprintf("rules[%d]", i), Observed: strings.Join(fields, ","),
					Severity: sev, Message: msg})
			}
		}
	},
}

// thirdPartyGroups reports whether every API group is an extension group
// (a domain name outside Kubernetes' own *.k8s.io groups), whose resources
// are CRDs rather than built-in objects such as Secrets or Pods.
func thirdPartyGroups(groups []string) bool {
	if len(groups) == 0 {
		return false
	}
	for _, g := range groups {
		if metricsGroups[g] {
			continue
		}
		if g == "" || g == "*" || !strings.Contains(g, ".") || strings.HasSuffix(g, ".k8s.io") || g == "k8s.io" {
			return false
		}
	}
	return true
}

// The aggregated metrics APIs serve read-only measurements.
var metricsGroups = map[string]bool{"metrics.k8s.io": true, "custom.metrics.k8s.io": true, "external.metrics.k8s.io": true}

func onlyScaleSubresource(resources []string) bool {
	for _, r := range resources {
		if r != "*/scale" {
			return false
		}
	}
	return len(resources) > 0
}

// referencedRole finds the Role or ClusterRole a binding refers to.
func referencedRole(inv *resource.Inventory, b *resource.Object) *resource.Object {
	kind, name := resource.String(b.Raw, "roleRef", "kind"), resource.String(b.Raw, "roleRef", "name")
	for _, o := range inv.OfKind(kind) {
		if o.Name == name && (kind == "ClusterRole" || o.EffectiveNamespace() == b.EffectiveNamespace()) {
			return o
		}
	}
	return nil
}

// nameScoped reports whether every rule of a role is limited to named
// objects (resourceNames) with read or proxy verbs — e.g. letting every user
// fetch one controller's public certificate.
func nameScoped(role *resource.Object) bool {
	rules := resource.Maps(role.Raw, "rules")
	if len(rules) == 0 {
		return false
	}
	for _, r := range rules {
		if len(resource.Strings(r, "resourceNames")) == 0 {
			return false
		}
		for _, v := range resource.Strings(r, "verbs") {
			if v != "get" && !(v == "create" && proxyOnly(resource.Strings(r, "resources"))) {
				return false
			}
		}
	}
	return true
}

func proxyOnly(resources []string) bool {
	for _, r := range resources {
		if r != "services/proxy" {
			return false
		}
	}
	return len(resources) > 0
}

var clusterAdminBinding = assessment.InventoryRule{
	Meta: assessment.Metadata{
		ID:          "HX-RBAC-002",
		Title:       "cluster-admin granted",
		Severity:    finding.High,
		Category:    assessment.CategoryRBAC,
		Description: "Detects bindings to the cluster-admin ClusterRole. Bindings to service accounts or to broad groups are critical.",
		Rationale:   "cluster-admin is unrestricted control of the cluster. A service account holding it turns any compromise of the pods using that account into full cluster compromise.",
		Remediation: "Bind a purpose-built role with only the permissions required. Reserve cluster-admin for break-glass human access.",
		References:  []finding.Reference{refCISRBAC, refNSAAuth},
	},
	Check: func(ctx *assessment.Context) {
		for _, b := range ctx.Inventory.OfKind("ClusterRoleBinding", "RoleBinding") {
			if resource.String(b.Raw, "roleRef", "kind") != "ClusterRole" || resource.String(b.Raw, "roleRef", "name") != "cluster-admin" {
				continue
			}
			if !ctx.Options.IncludeSystem && isSystem(b) {
				continue
			}
			for i, s := range resource.Maps(b.Raw, "subjects") {
				kind, name := resource.String(s, "kind"), resource.String(s, "name")
				hit := assessment.Hit{Object: b, Path: fmt.Sprintf("subjects[%d]", i), Observed: kind + " " + subjectName(s)}
				switch {
				case b.Kind == "RoleBinding":
					hit.Message = fmt.Sprintf("%s %s has cluster-admin within namespace %s", kind, subjectName(s), b.EffectiveNamespace())
				case kind == "ServiceAccount" || (kind == "Group" && strings.HasPrefix(name, "system:serviceaccounts")) || name == "system:authenticated":
					hit.Severity = sevCrit
					hit.Message = fmt.Sprintf("%s %s has cluster-admin; any pod running as it controls the cluster", kind, subjectName(s))
				default:
					hit.Message = fmt.Sprintf("%s %s has cluster-admin", kind, subjectName(s))
				}
				ctx.Report(hit)
			}
		}
	},
}

func subjectName(s map[string]any) string {
	if ns := resource.String(s, "namespace"); ns != "" {
		return ns + "/" + resource.String(s, "name")
	}
	return resource.String(s, "name")
}

var secretsAccess = assessment.InventoryRule{
	Meta: assessment.Metadata{
		ID:          "HX-RBAC-003",
		Title:       "Read access to Secrets",
		Severity:    finding.High,
		Category:    assessment.CategoryRBAC,
		Description: "Detects roles that explicitly grant get, list or watch on Secrets without restricting resourceNames. High for ClusterRoles, medium for Roles.",
		Rationale:   "Secrets hold credentials, including service account tokens in older clusters. list and watch return every secret's contents, so read access to secrets is effectively access to everything those credentials unlock.",
		Remediation: "Remove the grant, or restrict it with resourceNames to the specific secrets required.",
		References:  []finding.Reference{baselines.CIS("5.1", "RBAC and Service Accounts — minimize access to secrets"), refNSAAuth},
	},
	Check: func(ctx *assessment.Context) {
		g := grant{groups: []string{""}, resources: []string{"secrets"}, verbs: []string{"get", "list", "watch"}}
		for _, o := range roleObjects(ctx) {
			for i, rule := range resource.Maps(o.Raw, "rules") {
				if _, v, ok := explicitMatch(rule, g); ok {
					ctx.Report(assessment.Hit{Object: o, Path: fmt.Sprintf("rules[%d]", i), Observed: v + " secrets",
						Severity: scopeSeverity(o, sevHigh, sevMedium),
						Message:  fmt.Sprintf("rule %d grants %s on all secrets in scope", i, v)})
				}
			}
		}
	},
}

var escalationVerbs = assessment.InventoryRule{
	Meta: assessment.Metadata{
		ID:          "HX-RBAC-004",
		Title:       "RBAC privilege-escalation verb",
		Severity:    finding.Critical,
		Category:    assessment.CategoryRBAC,
		Description: "Detects roles that grant escalate or bind on roles/clusterroles, or impersonate on users, groups or service accounts.",
		Rationale:   "escalate and bind bypass RBAC's built-in escalation prevention, letting the holder grant themselves any permission. impersonate lets the holder act as any identity, including cluster administrators.",
		Remediation: "Remove these verbs. If a controller genuinely needs them, isolate it with a dedicated service account and restrict resourceNames.",
		References:  []finding.Reference{refCISRBAC, refNSAAuth, baselines.K8s("RBAC: privilege escalation prevention", "https://kubernetes.io/docs/reference/access-authn-authz/rbac/#privilege-escalation-prevention-and-bootstrapping")},
	},
	Check: func(ctx *assessment.Context) {
		grants := []grant{
			{groups: []string{"rbac.authorization.k8s.io"}, resources: []string{"roles", "clusterroles"}, verbs: []string{"escalate", "bind"}},
			{groups: []string{"", "authentication.k8s.io"}, resources: []string{"users", "groups", "serviceaccounts", "userextras/scopes", "uids"}, verbs: []string{"impersonate"}},
		}
		for _, o := range roleObjects(ctx) {
			for i, rule := range resource.Maps(o.Raw, "rules") {
				for _, g := range grants {
					if r, v, ok := explicitMatch(rule, g); ok {
						ctx.Report(assessment.Hit{Object: o, Path: fmt.Sprintf("rules[%d]", i), Observed: v + " " + r,
							Severity: scopeSeverity(o, nil, sevHigh),
							Message:  fmt.Sprintf("grants %s on %s", v, r)})
					}
				}
			}
		}
	},
}

var sensitiveSubresources = assessment.InventoryRule{
	Meta: assessment.Metadata{
		ID:          "HX-RBAC-005",
		Title:       "Access to sensitive subresource",
		Severity:    finding.High,
		Category:    assessment.CategoryRBAC,
		Description: "Detects roles that grant pods/exec, pods/attach, pods/portforward, pods/ephemeralcontainers, serviceaccounts/token or nodes/proxy.",
		Rationale:   "Exec and attach give a shell in other workloads (and their credentials). Ephemeral containers can inject a debug container into any pod. serviceaccounts/token mints tokens for other identities. nodes/proxy reaches the kubelet API directly, bypassing audit and admission; even get on it allows exec into every pod on the node, because the kubelet authorizes WebSocket exec as get nodes/proxy.",
		Remediation: "Remove the grant; provide debugging access through a separate, audited break-glass role.",
		References:  []finding.Reference{refCISRBAC, refNSAAuth},
		Limitations: "On Kubernetes 1.34 and earlier (or with the AuthorizePodWebsocketUpgradeCreatePermission feature gate disabled), get on pods/exec, pods/attach or pods/portforward also allowed them over WebSockets; such grants are not reported.",
	},
	Check: func(ctx *assessment.Context) {
		grants := []grant{
			// "get" no longer reaches exec, attach or port-forward over
			// WebSockets since Kubernetes 1.35 (create is required).
			{groups: []string{""}, resources: []string{"pods/exec", "pods/attach", "pods/portforward"}, verbs: []string{"create"}},
			{groups: []string{""}, resources: []string{"pods/ephemeralcontainers"}, verbs: []string{"patch", "update"}},
			{groups: []string{""}, resources: []string{"serviceaccounts/token"}, verbs: []string{"create"}},
			{groups: []string{""}, resources: []string{"nodes/proxy"}, verbs: []string{"get", "create"}},
		}
		for _, o := range roleObjects(ctx) {
			for i, rule := range resource.Maps(o.Raw, "rules") {
				for _, g := range grants {
					if r, v, ok := explicitMatch(rule, g); ok {
						ctx.Report(assessment.Hit{Object: o, Path: fmt.Sprintf("rules[%d]", i), Observed: v + " " + r,
							Severity: scopeSeverity(o, nil, sevMedium),
							Message:  fmt.Sprintf("grants %s on %s", v, r)})
					}
				}
			}
		}
	},
}

var workloadCreation = assessment.InventoryRule{
	Meta: assessment.Metadata{
		ID:          "HX-RBAC-006",
		Title:       "Workload creation permission",
		Severity:    finding.Medium,
		Category:    assessment.CategoryRBAC,
		Description: "Detects roles that grant create on pods or pod-creating controllers. Medium for ClusterRoles, low for Roles.",
		Rationale:   "Anyone who can create a pod can run it as any service account in the namespace and mount any secret there, inheriting all of those permissions. Unless admission policy blocks it, they can also create privileged pods.",
		Remediation: "Limit workload creation to deployment pipelines and controllers, and enforce Pod Security admission (restricted) in every namespace where it is granted.",
		References:  []finding.Reference{refCISRBAC, baselines.K8s("RBAC good practices: workload creation", "https://kubernetes.io/docs/concepts/security/rbac-good-practices/")},
	},
	Check: func(ctx *assessment.Context) {
		grants := []grant{
			{groups: []string{""}, resources: []string{"pods", "replicationcontrollers"}, verbs: []string{"create"}},
			{groups: []string{"apps"}, resources: []string{"deployments", "daemonsets", "statefulsets", "replicasets"}, verbs: []string{"create"}},
			{groups: []string{"batch"}, resources: []string{"jobs", "cronjobs"}, verbs: []string{"create"}},
		}
		for _, o := range roleObjects(ctx) {
			for i, rule := range resource.Maps(o.Raw, "rules") {
				for _, g := range grants {
					if r, v, ok := explicitMatch(rule, g); ok {
						ctx.Report(assessment.Hit{Object: o, Path: fmt.Sprintf("rules[%d]", i), Observed: v + " " + r,
							Severity: scopeSeverity(o, nil, sevLow),
							Message:  fmt.Sprintf("grants %s on %s", v, r)})
						break
					}
				}
			}
		}
	},
}

var broadSubjects = assessment.InventoryRule{
	Meta: assessment.Metadata{
		ID:          "HX-RBAC-007",
		Title:       "Permissions granted to anonymous or all users",
		Severity:    finding.High,
		Category:    assessment.CategoryRBAC,
		Description: "Detects bindings whose subjects are system:anonymous or system:unauthenticated (critical), or system:authenticated / all service accounts (high). One level lower — high and low — when every rule of the granted role is limited to named objects with read or proxy verbs.",
		Rationale:   "These groups include every caller that can reach the API server. A grant to them is a grant to any attacker with network access or any compromised pod.",
		Remediation: "Bind permissions to specific users, groups or service accounts.",
		References:  []finding.Reference{refCISRBAC, refNSAAuth},
	},
	Check: func(ctx *assessment.Context) {
		for _, b := range ctx.Inventory.OfKind("ClusterRoleBinding", "RoleBinding") {
			if !ctx.Options.IncludeSystem && isSystem(b) {
				continue
			}
			for i, s := range resource.Maps(b.Raw, "subjects") {
				name := resource.String(s, "name")
				role := resource.String(b.Raw, "roleRef", "name")
				hit := assessment.Hit{Object: b, Path: fmt.Sprintf("subjects[%d]", i), Observed: name}
				narrow := false
				if r := referencedRole(ctx.Inventory, b); r != nil && nameScoped(r) {
					narrow = true
				}
				switch name {
				case "system:anonymous", "system:unauthenticated":
					hit.Severity = sevCrit
					if narrow {
						hit.Severity = sevHigh
					}
					hit.Message = fmt.Sprintf("unauthenticated callers are granted %s", role)
				case "system:authenticated", "system:serviceaccounts":
					if narrow {
						hit.Severity = sevLow
					}
					hit.Message = fmt.Sprintf("every authenticated identity is granted %s", role)
				default:
					continue
				}
				if narrow {
					hit.Message += " (read or proxy access to named objects only)"
				}
				ctx.Report(hit)
			}
		}
	},
}
