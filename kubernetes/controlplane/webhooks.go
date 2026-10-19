package controlplane

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// Resources whose admission a security policy webhook typically guards.
var guardedResources = map[string]bool{
	"*": true, "pods": true, "pods/*": true, "deployments": true, "daemonsets": true, "statefulsets": true,
	"replicasets": true, "jobs": true, "cronjobs": true, "roles": true, "rolebindings": true,
	"clusterroles": true, "clusterrolebindings": true, "services": true, "ingresses": true, "networkpolicies": true,
}

var failOpenWebhooks = assessment.ObjectRule{
	Meta: assessment.Metadata{
		ID:          "HX-CP-009",
		Title:       "Admission webhook fails open",
		Severity:    finding.Medium,
		Category:    assessment.CategoryControlPlane,
		Description: "Detects ValidatingWebhookConfigurations and MutatingWebhookConfigurations whose webhooks guard workload, RBAC or networking resources with failurePolicy: Ignore.",
		Rationale:   "A policy webhook that fails open is bypassed whenever it is unavailable. An attacker who can slow down, crash or partition the webhook service can then create workloads the policy would have rejected.",
		Remediation: "Set failurePolicy: Fail for security policy webhooks, run them highly available, and exclude only the namespaces needed to recover the webhook itself.",
		References:  []finding.Reference{refNSAAuth, baselines.K8s("Dynamic admission control: failure policy", "https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#failure-policy")},
		Limitations: "Webhooks that are not security controls (e.g. defaulting or metrics) are reported too when they fail open; waive them with a justification.",
	},
	Kinds: []string{"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"},
	Check: func(ctx *assessment.Context, o *resource.Object) {
		for i, wh := range resource.Maps(o.Raw, "webhooks") {
			if resource.String(wh, "failurePolicy") != "Ignore" {
				continue // v1 defaults to Fail
			}
			if !guardsResources(wh) {
				continue
			}
			ctx.Report(assessment.Hit{Object: o, Path: fmt.Sprintf("webhooks[%d].failurePolicy", i), Observed: "Ignore",
				Message: fmt.Sprintf("webhook %s is skipped whenever it is unavailable", resource.String(wh, "name"))})
		}
	},
}

func guardsResources(wh map[string]any) bool {
	for _, r := range resource.Maps(wh, "rules") {
		writes := false
		for _, op := range resource.Strings(r, "operations") {
			if op == "*" || op == "CREATE" || op == "UPDATE" {
				writes = true
			}
		}
		if !writes {
			continue
		}
		for _, res := range resource.Strings(r, "resources") {
			if guardedResources[res] {
				return true
			}
		}
	}
	return false
}

var externalWebhooks = assessment.ObjectRule{
	Meta: assessment.Metadata{
		ID:          "HX-CP-010",
		Title:       "Admission webhook served from outside the cluster",
		Severity:    finding.Medium,
		Category:    assessment.CategoryControlPlane,
		Description: "Detects admission webhooks that guard workload, RBAC or networking resources and are called by URL (clientConfig.url) rather than through an in-cluster Service. Mutating webhooks are reported as high: they can rewrite every pod they see.",
		Rationale:   "The API server sends every matching object to the webhook and trusts its answer. A webhook reached by URL puts that trust in whatever answers at that DNS name and in the network between — outside the cluster's RBAC, NetworkPolicy and audit. A compromised or spoofed mutating webhook can inject privileged containers into every pod in the cluster.",
		Remediation: "Serve the webhook from a Service in the cluster (clientConfig.service). If an external endpoint is unavoidable, pin its CA with caBundle, scope rules and namespaceSelector narrowly, and monitor the endpoint as part of the control plane.",
		References:  []finding.Reference{refNSAAuth, baselines.K8s("Dynamic admission control: contacting the webhook", "https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#contact-the-webhook")},
		Limitations: "URLs that resolve to the control-plane host (localhost, 127.0.0.1, ::1) are treated as local. Whether the endpoint is actually trustworthy cannot be judged from the manifest.",
	},
	Kinds: []string{"ValidatingWebhookConfiguration", "MutatingWebhookConfiguration"},
	Check: func(ctx *assessment.Context, o *resource.Object) {
		for i, wh := range resource.Maps(o.Raw, "webhooks") {
			raw := resource.String(wh, "clientConfig", "url")
			if raw == "" || !guardsResources(wh) {
				continue
			}
			u, err := url.Parse(raw)
			host := ""
			if err == nil {
				host = strings.ToLower(u.Hostname())
			}
			if host == "localhost" || host == "127.0.0.1" || host == "::1" {
				continue
			}
			var sev *finding.Severity
			msg := fmt.Sprintf("webhook %s sends admission requests to %s", resource.String(wh, "name"), raw)
			if o.Kind == "MutatingWebhookConfiguration" {
				h := finding.High
				sev = &h
				msg += " and may rewrite the objects it receives"
			}
			if resource.String(wh, "clientConfig", "caBundle") == "" {
				msg += "; no caBundle pins its certificate"
			}
			ctx.Report(assessment.Hit{Object: o, Path: fmt.Sprintf("webhooks[%d].clientConfig.url", i), Observed: raw, Severity: sev, Message: msg})
		}
	},
}
