// Package networking implements checks on network segmentation and service
// exposure.
package networking

import (
	"fmt"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// Rules returns every networking rule.
func Rules() []assessment.Rule {
	return []assessment.Rule{ingressIsolation, egressIsolation, serviceExposure, externalIPs, ingressTLS, nginxSnippets, retiredIngressNginx, gatewayTLS, gatewayRouteNamespaces}
}

var (
	refNSANet = baselines.NSA("Network separation and hardening")
	refCISNet = baselines.CIS("5.3", "Network Policies and CNI")
)

var systemNamespaces = map[string]bool{"kube-system": true, "kube-public": true, "kube-node-lease": true}

// isolates reports whether a NetworkPolicy selects every pod in its namespace
// and does not re-open the given direction to all traffic.
func isolates(np *resource.Object, direction string) bool {
	sel, ok := resource.Lookup(np.Raw, "spec", "podSelector")
	if !ok {
		return false
	}
	if m, isMap := sel.(map[string]any); !isMap || len(resource.Map(m, "matchLabels")) > 0 || len(resource.Slice(m, "matchExpressions")) > 0 {
		return false
	}
	types := resource.Strings(np.Raw, "spec", "policyTypes")
	field := map[string]string{"Ingress": "ingress", "Egress": "egress"}[direction]
	declared := false
	if len(types) == 0 {
		// Without policyTypes, Ingress is implied; Egress only if egress rules exist.
		declared = direction == "Ingress" || resource.Slice(np.Raw, "spec", field) != nil
	} else {
		for _, t := range types {
			if t == direction {
				declared = true
			}
		}
	}
	if !declared {
		return false
	}
	return !opensAll(np, direction)
}

// opensAll reports whether one of the policy's rules for the direction
// allows all traffic: no ports, and no peers or a peer that matches
// everything (every pod in every namespace, or every address).
func opensAll(np *resource.Object, direction string) bool {
	field, peers := "ingress", "from"
	if direction == "Egress" {
		field, peers = "egress", "to"
	}
	for _, r := range resource.Maps(np.Raw, "spec", field) {
		if len(resource.Slice(r, "ports")) > 0 {
			continue
		}
		ps := resource.Maps(r, peers)
		if len(resource.Slice(r, peers)) == 0 {
			return true
		}
		for _, p := range ps {
			if peerMatchesAll(p) {
				return true
			}
		}
	}
	return false
}

// peerMatchesAll: namespaceSelector: {} (with no podSelector, or an empty
// one) selects every pod in the cluster; an ipBlock of 0.0.0.0/0 or ::/0
// without exceptions, every address.
func peerMatchesAll(p map[string]any) bool {
	if ns, ok := resource.Lookup(p, "namespaceSelector"); ok && emptySelector(ns) {
		pod, hasPod := resource.Lookup(p, "podSelector")
		if !hasPod || emptySelector(pod) {
			return true
		}
	}
	if b := resource.Map(p, "ipBlock"); b != nil && len(resource.Slice(b, "except")) == 0 {
		cidr := resource.String(b, "cidr")
		return cidr == "0.0.0.0/0" || cidr == "::/0"
	}
	return false
}

// reopens reports whether a NetworkPolicy selects every pod of its
// namespace and allows all traffic in the direction. Policies add up: such
// a policy cancels any default deny beside it.
func reopens(np *resource.Object, direction string) bool {
	if np.Kind != "NetworkPolicy" || np.Group() != "networking.k8s.io" {
		return false
	}
	sel, ok := resource.Lookup(np.Raw, "spec", "podSelector")
	if !ok || !emptySelector(sel) {
		return false
	}
	types := resource.Strings(np.Raw, "spec", "policyTypes")
	field := map[string]string{"Ingress": "ingress", "Egress": "egress"}[direction]
	declared := (len(types) == 0 && (direction == "Ingress" || resource.Slice(np.Raw, "spec", field) != nil)) || contains(types, direction)
	return declared && opensAll(np, direction)
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func isolationRule(meta assessment.Metadata, direction string) assessment.Rule {
	return assessment.InventoryRule{Meta: meta, Check: func(ctx *assessment.Context) {
		isolatedNS := map[string]bool{}
		reopenedBy := map[string]string{}
		clusterWide := false
		for _, np := range ctx.Inventory.OfKind(PolicyKinds...) {
			if reopens(np, direction) {
				reopenedBy[np.EffectiveNamespace()] = np.Name
			}
			if ok, global := policyScope(np, direction); ok {
				if global {
					clusterWide = true
				} else {
					isolatedNS[np.EffectiveNamespace()] = true
				}
			}
		}
		for _, ns := range ctx.Inventory.Namespaces() {
			if systemNamespaces[ns] && !ctx.Options.IncludeSystem {
				continue
			}
			subject := namespaceObject(ctx.Inventory, ns)
			if subject == nil {
				continue // namespace declared but has no workloads in scope
			}
			isolated := clusterWide || isolatedNS[ns]
			if by, ok := reopenedBy[ns]; ok && isolated {
				ctx.Report(assessment.Hit{Object: subject, Observed: "default deny cancelled by " + by,
					Message: fmt.Sprintf("namespace %s has a default-deny policy for %s traffic, but NetworkPolicy %s allows all of it to every pod (policies add up)", ns, direction, by)})
				continue
			}
			if !isolated {
				ctx.Report(assessment.Hit{Object: subject, Observed: "no default-deny policy",
					Message: fmt.Sprintf("namespace %s has no NetworkPolicy isolating all pods for %s traffic", ns, direction)})
			}
		}
	}}
}

// namespaceObject returns the Namespace object for ns, or a synthetic one
// located at the namespace's first workload. It returns nil if the namespace
// has no workloads (an empty namespace needs no isolation).
func namespaceObject(inv *resource.Inventory, ns string) *resource.Object {
	var first *resource.Object
	for _, o := range inv.Objects {
		if resource.IsWorkload(o) && o.EffectiveNamespace() == ns {
			first = o
			break
		}
	}
	if first == nil {
		return nil
	}
	for _, o := range inv.OfKind("Namespace") {
		if o.Name == ns {
			return o
		}
	}
	return &resource.Object{Kind: "Namespace", APIVersion: "v1", Name: ns, Source: first.Source, Line: first.Line,
		Raw: map[string]any{"kind": "Namespace", "metadata": map[string]any{"name": ns}}}
}

var ingressIsolation = isolationRule(assessment.Metadata{
	ID:             "HX-NET-001",
	Title:          "Namespace without default-deny ingress",
	Severity:       finding.Medium,
	Category:       assessment.CategoryNetworking,
	Description:    "Detects namespaces containing workloads where no NetworkPolicy selects all pods and denies ingress by default, or where another policy allows all ingress to every pod again (policies add up, so it cancels the default deny). A rule whose peer matches everything (namespaceSelector: {}, ipBlock 0.0.0.0/0) allows all traffic.",
	Rationale:      "Kubernetes allows all pod-to-pod traffic by default. Without a default-deny policy, one compromised pod can reach every service in the cluster, including databases and internal admin endpoints.",
	Remediation:    "Add a NetworkPolicy with podSelector: {} and policyTypes: [Ingress], then add policies allowing only required traffic. Confirm your CNI plugin enforces NetworkPolicy.",
	References:     []finding.Reference{refNSANet, refCISNet},
	Limitations:    "Only policies present in the scanned input are considered: Kubernetes NetworkPolicies, Cilium (CiliumNetworkPolicy, CiliumClusterwideNetworkPolicy) and Calico (NetworkPolicy, GlobalNetworkPolicy). A policy re-opening all traffic beside a default deny is recognised for Kubernetes NetworkPolicies (an allow-all rule, or a peer matching every pod or address); for Cilium and Calico, each policy is judged on its own. Whether the CNI plugin enforces policies at all is not visible in manifests.",
	NeedsInventory: true,
}, "Ingress")

var egressIsolation = isolationRule(assessment.Metadata{
	ID:             "HX-NET-002",
	Title:          "Namespace without default-deny egress",
	Severity:       finding.Low,
	Category:       assessment.CategoryNetworking,
	Description:    "Detects namespaces containing workloads where no NetworkPolicy selects all pods and denies egress by default.",
	Rationale:      "Unrestricted egress lets a compromised pod reach cloud metadata services, the API server, other tenants and the internet for command-and-control or exfiltration.",
	Remediation:    "Add a NetworkPolicy with podSelector: {} and policyTypes: [Egress], then allow DNS and the specific destinations each workload needs.",
	References:     []finding.Reference{refNSANet, refCISNet},
	Limitations:    "As for HX-NET-001.",
	NeedsInventory: true,
}, "Egress")

var serviceExposure = assessment.ObjectRule{
	Meta: assessment.Metadata{
		ID:          "HX-NET-003",
		Title:       "Service exposed outside the cluster",
		Severity:    finding.Medium,
		Category:    assessment.CategoryNetworking,
		Description: "Detects LoadBalancer Services without loadBalancerSourceRanges (medium) and NodePort Services (low).",
		Rationale:   "LoadBalancer and NodePort services are reachable from outside the cluster network. Without source restrictions, internal tools exposed this way are reachable by anyone who can route to the load balancer or nodes.",
		Remediation: "Use ClusterIP behind an Ingress with authentication where possible; otherwise set loadBalancerSourceRanges to the networks that need access.",
		References:  []finding.Reference{refNSANet},
		Limitations: "Cloud-provider annotations that make a load balancer internal are not yet recognised.",
	},
	Kinds: []string{"Service"},
	Check: func(ctx *assessment.Context, o *resource.Object) {
		switch resource.String(o.Raw, "spec", "type") {
		case "LoadBalancer":
			if len(resource.Slice(o.Raw, "spec", "loadBalancerSourceRanges")) == 0 {
				ctx.Report(assessment.Hit{Object: o, Path: "spec.loadBalancerSourceRanges", Observed: "<unset>",
					Message: "LoadBalancer service accepts traffic from any source"})
			}
		case "NodePort":
			ctx.Report(assessment.Hit{Object: o, Path: "spec.type", Observed: "NodePort", Severity: assessment.SeverityOverride(finding.Low),
				Message: "service is exposed on every node's address"})
		}
	},
}

var externalIPs = assessment.ObjectRule{
	Meta: assessment.Metadata{
		ID:          "HX-NET-004",
		Title:       "Service with externalIPs",
		Severity:    finding.Medium,
		Category:    assessment.CategoryNetworking,
		Description: "Detects Services that set spec.externalIPs.",
		Rationale:   "externalIPs let a Service claim traffic for arbitrary IP addresses, enabling in-cluster traffic interception (CVE-2020-8554). Few legitimate setups need it.",
		Remediation: "Remove externalIPs, and block the field cluster-wide with an admission policy (e.g. the DenyServiceExternalIPs admission plugin).",
		References:  []finding.Reference{refNSANet, baselines.K8s("CVE-2020-8554", "https://github.com/kubernetes/kubernetes/issues/97076")},
	},
	Kinds: []string{"Service"},
	Check: func(ctx *assessment.Context, o *resource.Object) {
		if ips := resource.Strings(o.Raw, "spec", "externalIPs"); len(ips) > 0 {
			ctx.Report(assessment.Hit{Object: o, Path: "spec.externalIPs", Observed: fmt.Sprint(ips),
				Message: fmt.Sprintf("service claims external IPs %v", ips)})
		}
	},
}
