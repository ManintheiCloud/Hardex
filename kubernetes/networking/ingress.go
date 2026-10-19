package networking

import (
	"fmt"
	"strings"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

var ingressTLS = assessment.ObjectRule{
	Meta: assessment.Metadata{
		ID:          "HX-NET-005",
		Title:       "Ingress without TLS",
		Severity:    finding.Medium,
		Category:    assessment.CategoryNetworking,
		Description: "Detects Ingresses with no TLS configuration, and Ingress hosts not covered by any TLS entry.",
		Rationale:   "Traffic to hosts without TLS crosses the network in clear text: credentials, session cookies and API tokens can be read or modified in transit.",
		Remediation: "Add spec.tls entries (with a certificate Secret, e.g. issued by cert-manager) covering every host in spec.rules, and redirect HTTP to HTTPS in the ingress controller.",
		References:  []finding.Reference{refNSANet, baselines.K8s("Ingress: TLS", "https://kubernetes.io/docs/concepts/services-networking/ingress/#tls")},
		Limitations: "TLS terminated in front of the Ingress (e.g. at a cloud load balancer) is not visible and is reported.",
	},
	Kinds: []string{"Ingress"},
	Check: func(ctx *assessment.Context, o *resource.Object) {
		tls := resource.Maps(o.Raw, "spec", "tls")
		if len(tls) == 0 {
			ctx.Report(assessment.Hit{Object: o, Path: "spec.tls", Observed: "<unset>", Message: "Ingress serves its hosts over plain HTTP"})
			return
		}
		var covered []string
		for _, t := range tls {
			covered = append(covered, resource.Strings(t, "hosts")...)
		}
		for i, r := range resource.Maps(o.Raw, "spec", "rules") {
			host := resource.String(r, "host")
			if host == "" || hostCovered(host, covered) {
				continue
			}
			ctx.Report(assessment.Hit{Object: o, Path: fmt.Sprintf("spec.rules[%d].host", i), Observed: host,
				Message: fmt.Sprintf("host %s is not covered by any TLS entry", host)})
		}
	},
}

// hostCovered matches exact names and single-label wildcards (*.example.com).
func hostCovered(host string, covered []string) bool {
	for _, c := range covered {
		if strings.EqualFold(c, host) {
			return true
		}
		if strings.HasPrefix(c, "*.") {
			if i := strings.IndexByte(host, '.'); i > 0 && strings.EqualFold(host[i:], c[1:]) {
				return true
			}
		}
	}
	return false
}
