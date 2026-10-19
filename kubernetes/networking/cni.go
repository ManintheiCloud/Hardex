package networking

import (
	"strings"

	"github.com/ManintheiCloud/Hardex/core/resource"
)

// CNI-specific policy support. Each function answers: does this policy put
// every pod in scope into default-deny for the direction? Only clear cases
// count; anything ambiguous is treated as not isolating, so the namespace is
// still reported rather than silently passed.
//
// Semantics follow the CNI projects' reference documentation:
//   - Cilium: an endpoint enters default-deny for a direction when a rule
//     selecting it has a non-empty section for that direction, unless the
//     rule sets enableDefaultDeny to false for it. An omitted or empty
//     section does not apply.
//   - Calico: a policy whose types include a direction applies to the
//     selected endpoints for that direction; traffic not allowed by a rule is
//     denied. Omitted types are inferred from the rules present (no rules →
//     Ingress). A rule with action Allow and no source/destination match
//     allows everything.

// policyScope reports whether o is a network policy that isolates pods for
// the direction, and whether it applies cluster-wide.
func policyScope(o *resource.Object, direction string) (isolating, clusterWide bool) {
	group := o.Group()
	switch {
	case o.Kind == "NetworkPolicy" && group == "networking.k8s.io":
		return isolates(o, direction), false
	case o.Kind == "CiliumNetworkPolicy" && group == "cilium.io":
		return ciliumIsolates(o, direction, false), false
	case o.Kind == "CiliumClusterwideNetworkPolicy" && group == "cilium.io":
		return ciliumIsolates(o, direction, true), true
	case o.Kind == "NetworkPolicy" && isCalico(group):
		return calicoIsolates(o.Raw, direction, false), false
	case o.Kind == "GlobalNetworkPolicy" && isCalico(group):
		return calicoIsolates(o.Raw, direction, true), true
	}
	return false, false
}

// PolicyKinds are the kinds whose objects policyScope understands.
var PolicyKinds = []string{"NetworkPolicy", "CiliumNetworkPolicy", "CiliumClusterwideNetworkPolicy", "GlobalNetworkPolicy"}

func isCalico(group string) bool {
	return group == "crd.projectcalico.org" || group == "projectcalico.org"
}

func emptySelector(v any) bool {
	m, ok := v.(map[string]any)
	return ok && len(resource.Map(m, "matchLabels")) == 0 && len(resource.Slice(m, "matchExpressions")) == 0
}

func ciliumIsolates(o *resource.Object, direction string, clusterWide bool) bool {
	specs := resource.Maps(o.Raw, "specs")
	if spec := resource.Map(o.Raw, "spec"); spec != nil {
		specs = append(specs, spec)
	}
	for _, s := range specs {
		if ciliumSpecIsolates(s, direction, clusterWide) {
			return true
		}
	}
	return false
}

func ciliumSpecIsolates(spec map[string]any, direction string, clusterWide bool) bool {
	sel, ok := resource.Lookup(spec, "endpointSelector")
	if !ok || !emptySelector(sel) {
		return false // node (host) policies and narrowed selectors do not cover all pods
	}
	field, defaultDeny := "ingress", "ingress"
	peersKey, entitiesKey := "fromEndpoints", "fromEntities"
	openEntities := map[string]bool{"all": true, "cluster": true}
	if direction == "Egress" {
		field, defaultDeny = "egress", "egress"
		peersKey, entitiesKey = "toEndpoints", "toEntities"
		openEntities = map[string]bool{"all": true, "cluster": true, "world": true}
	}
	if v, set := resource.Bool(spec, "enableDefaultDeny", defaultDeny); set && !v {
		return false
	}
	rules := resource.Slice(spec, field)
	if len(rules) == 0 {
		return false // omitted or empty: the section does not apply
	}
	for _, r := range resource.Maps(spec, field) {
		for _, e := range resource.Strings(r, entitiesKey) {
			if openEntities[strings.ToLower(e)] {
				return false
			}
		}
		if clusterWide {
			// In a clusterwide policy an empty endpoint selector is every
			// pod in the cluster.
			for _, peer := range resource.Slice(r, peersKey) {
				if emptySelector(peer) {
					return false
				}
			}
		}
	}
	return true
}

func calicoIsolates(raw map[string]any, direction string, global bool) bool {
	spec := resource.Map(raw, "spec")
	if spec == nil {
		return false
	}
	if sel := strings.TrimSpace(resource.String(spec, "selector")); sel != "" && sel != "all()" {
		return false
	}
	if _, narrowed := spec["serviceAccountSelector"]; narrowed {
		return false
	}
	if global {
		if ns := strings.TrimSpace(resource.String(spec, "namespaceSelector")); ns != "" && ns != "all()" {
			return false
		}
	}
	ingress, egress := resource.Maps(spec, "ingress"), resource.Maps(spec, "egress")
	types := resource.Strings(spec, "types")
	if len(types) == 0 {
		switch {
		case len(ingress) > 0 && len(egress) > 0:
			types = []string{"Ingress", "Egress"}
		case len(egress) > 0:
			types = []string{"Egress"}
		default:
			types = []string{"Ingress"}
		}
	}
	declared := false
	for _, t := range types {
		if t == direction {
			declared = true
		}
	}
	if !declared {
		return false
	}
	rules, peer := ingress, "source"
	if direction == "Egress" {
		rules, peer = egress, "destination"
	}
	for _, r := range rules {
		if resource.String(r, "action") == "Allow" && len(resource.Map(r, peer)) == 0 {
			return false // allow-all rule
		}
	}
	return true
}
