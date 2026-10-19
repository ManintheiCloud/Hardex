package networking

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// Annotations that inject raw NGINX configuration into ingress-nginx.
var snippetAnnotations = []string{
	"nginx.ingress.kubernetes.io/configuration-snippet",
	"nginx.ingress.kubernetes.io/server-snippet",
	"nginx.ingress.kubernetes.io/auth-snippet",
	"nginx.ingress.kubernetes.io/modsecurity-snippet",
	"nginx.ingress.kubernetes.io/stream-snippet",
}

var nginxSnippets = assessment.ObjectRule{
	Meta: assessment.Metadata{
		ID:          "HX-NET-006",
		Title:       "Ingress injects NGINX configuration snippets",
		Severity:    finding.High,
		Category:    assessment.CategoryNetworking,
		Description: "Detects Ingresses with ingress-nginx snippet annotations (configuration-snippet, server-snippet, auth-snippet, modsecurity-snippet, stream-snippet).",
		Rationale:   "Snippets are inserted verbatim into the controller's NGINX configuration. Anyone who can create or edit an Ingress can use them to read the controller's service account token and every Secret it can access (CVE-2021-25742), or to proxy traffic anywhere.",
		Remediation: "Replace snippets with dedicated annotations or controller configuration, and run the controller with allow-snippet-annotations: false.",
		References: []finding.Reference{
			refNSANet,
			baselines.K8s("CVE-2021-25742: ingress-nginx custom snippets", "https://discuss.kubernetes.io/t/security-advisory-cve-2021-25742-ingress-nginx-custom-snippets-allows-retrieval-of-ingress-nginx-serviceaccount-token-and-secrets-across-all-namespaces/17860"),
		},
		Limitations: "Whether the controller actually honours snippets (allow-snippet-annotations) is controller configuration that Hardex does not read; the annotation is reported either way.",
	},
	Kinds: []string{"Ingress"},
	Check: func(ctx *assessment.Context, o *resource.Object) {
		anns := resource.Map(o.Raw, "metadata", "annotations")
		for _, key := range snippetAnnotations {
			if _, ok := anns[key]; ok {
				ctx.Report(assessment.Hit{Object: o, Path: "metadata.annotations[" + key + "]", Observed: "<snippet>",
					Message: fmt.Sprintf("Ingress injects raw NGINX configuration via %s", strings.TrimPrefix(key, "nginx.ingress.kubernetes.io/"))})
			}
		}
	},
}

var retiredIngressNginx = assessment.InventoryRule{
	Meta: assessment.Metadata{
		ID:          "HX-NET-007",
		Title:       "Retired ingress-nginx controller",
		Severity:    finding.Medium,
		Category:    assessment.CategorySupplyChain,
		Description: "Detects workloads running the community ingress-nginx controller image and IngressClasses served by it.",
		Rationale:   "The Kubernetes project retired ingress-nginx: best-effort maintenance ended in March 2026 and no further releases or security fixes are published. An internet-facing component that will not receive security fixes accumulates exploitable vulnerabilities.",
		Remediation: "Migrate to a maintained ingress or Gateway API implementation, and plan the migration for internet-facing clusters first.",
		References:  []finding.Reference{baselines.K8s("Ingress NGINX retirement", "https://kubernetes.io/blog/2025/11/11/ingress-nginx-retirement/")},
		Limitations: "Identified by image name (…/ingress-nginx/controller) and IngressClass controller (k8s.io/ingress-nginx); renamed mirrors of the image are not recognised.",
	},
	Check: func(ctx *assessment.Context) {
		for _, o := range ctx.Inventory.Objects {
			if o.Kind == "IngressClass" && resource.String(o.Raw, "spec", "controller") == "k8s.io/ingress-nginx" {
				ctx.Report(assessment.Hit{Object: o, Path: "spec.controller", Observed: "k8s.io/ingress-nginx",
					Message: "IngressClass is served by the retired ingress-nginx controller"})
				continue
			}
			pod, prefix := resource.PodSpec(o)
			if pod == nil {
				continue
			}
			var hits []string
			for _, c := range resource.Containers(pod) {
				img := resource.String(c.Spec, "image")
				if strings.Contains(img, "ingress-nginx/controller") {
					hits = append(hits, c.Path(prefix)+".image")
				}
			}
			sort.Strings(hits)
			for _, path := range hits {
				ctx.Report(assessment.Hit{Object: o, Path: path, Observed: "ingress-nginx/controller",
					Message: "workload runs the retired ingress-nginx controller, which no longer receives security fixes"})
			}
		}
	},
}
