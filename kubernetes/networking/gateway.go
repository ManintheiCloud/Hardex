package networking

import (
	"fmt"
	"strings"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// gatewayAPIGroup distinguishes Gateway API Gateways from other kinds named
// Gateway (e.g. Istio's networking.istio.io Gateway).
const gatewayAPIGroup = "gateway.networking.k8s.io"

func isGatewayAPI(o *resource.Object) bool { return o.Group() == gatewayAPIGroup }

var gatewayTLS = assessment.ObjectRule{
	Meta: assessment.Metadata{
		ID:          "HX-NET-008",
		Title:       "Gateway listener without TLS",
		Severity:    finding.Medium,
		Category:    assessment.CategoryNetworking,
		Description: "Detects Gateway API listeners with protocol HTTP whose hostname is not also served by an HTTPS or TLS listener on the same Gateway.",
		Rationale:   "Traffic to an HTTP-only listener crosses the network in clear text: credentials, session cookies and API tokens can be read or modified in transit.",
		Remediation: "Add an HTTPS listener with certificateRefs for the hostname (for example issued by cert-manager), and keep the HTTP listener only to redirect to HTTPS with an HTTPRoute RequestRedirect filter.",
		References:  []finding.Reference{refNSANet, baselines.K8s("Gateway API: TLS configuration", "https://gateway-api.sigs.k8s.io/guides/tls/")},
		Limitations: "An HTTP listener alongside an HTTPS listener for the same hostname is assumed to redirect; the HTTPRoutes are not inspected. TLS terminated in front of the Gateway (e.g. at a cloud load balancer) is not visible.",
	},
	Kinds: []string{"Gateway"},
	Check: func(ctx *assessment.Context, o *resource.Object) {
		if !isGatewayAPI(o) {
			return
		}
		listeners := resource.Maps(o.Raw, "spec", "listeners")
		var secure []string
		secureAll := false
		for _, l := range listeners {
			if p := resource.String(l, "protocol"); p == "HTTPS" || p == "TLS" {
				h := resource.String(l, "hostname")
				if h == "" {
					secureAll = true
				}
				secure = append(secure, h)
			}
		}
		for i, l := range listeners {
			if resource.String(l, "protocol") != "HTTP" {
				continue
			}
			h := resource.String(l, "hostname")
			if secureAll || (h != "" && hostCovered(h, secure)) {
				continue
			}
			name := resource.String(l, "name")
			if h == "" {
				h = "every hostname"
			}
			ctx.Report(assessment.Hit{Object: o, Path: fmt.Sprintf("spec.listeners[%d].protocol", i), Observed: "HTTP",
				Message: fmt.Sprintf("listener %s serves %s over plain HTTP with no TLS listener for it", name, h)})
		}
	},
}

var gatewayRouteNamespaces = assessment.ObjectRule{
	Meta: assessment.Metadata{
		ID:          "HX-NET-009",
		Title:       "Gateway accepts routes from every namespace",
		Severity:    finding.Medium,
		Category:    assessment.CategoryNetworking,
		Description: "Detects Gateway API listeners whose allowedRoutes.namespaces.from is All, or Selector with an empty selector.",
		Rationale:   "Any namespace that can create an HTTPRoute can then attach it to the listener and claim its hostnames and paths: a tenant, or an attacker with a foothold in any namespace, can intercept traffic meant for another application, including credentials posted to it.",
		Remediation: "Set allowedRoutes.namespaces.from to Same, or to Selector with a label selector matching only the namespaces that own the listener's hostnames. Pin hostnames on the listener so routes cannot widen them.",
		References:  []finding.Reference{refNSANet, baselines.K8s("Gateway API: cross-namespace routing", "https://gateway-api.sigs.k8s.io/guides/multiple-ns/")},
		Limitations: "Selectors are not evaluated against namespace labels; only the empty selector is reported.",
	},
	Kinds: []string{"Gateway"},
	Check: func(ctx *assessment.Context, o *resource.Object) {
		if !isGatewayAPI(o) {
			return
		}
		for i, l := range resource.Maps(o.Raw, "spec", "listeners") {
			ns := resource.Map(l, "allowedRoutes", "namespaces")
			from := resource.String(ns, "from")
			open := from == "All"
			if from == "Selector" {
				sel := resource.Map(ns, "selector")
				open = len(resource.Map(sel, "matchLabels")) == 0 && len(resource.Maps(sel, "matchExpressions")) == 0
			}
			if !open {
				continue // the default is Same
			}
			h := resource.String(l, "hostname")
			if h == "" {
				h = "any hostname"
			}
			ctx.Report(assessment.Hit{Object: o, Path: fmt.Sprintf("spec.listeners[%d].allowedRoutes.namespaces.from", i), Observed: strings.TrimSpace(from),
				Message: fmt.Sprintf("listener %s lets routes in every namespace claim %s", resource.String(l, "name"), h)})
		}
	},
}
