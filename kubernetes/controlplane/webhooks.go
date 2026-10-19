package controlplane

import (
	"fmt"

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
		Title:       "Validating webhook fails open",
		Severity:    finding.Medium,
		Category:    assessment.CategoryControlPlane,
		Description: "Detects ValidatingWebhookConfigurations whose webhooks guard workload, RBAC or networking resources with failurePolicy: Ignore.",
		Rationale:   "A policy webhook that fails open is bypassed whenever it is unavailable. An attacker who can slow down, crash or partition the webhook service can then create workloads the policy would have rejected.",
		Remediation: "Set failurePolicy: Fail for security policy webhooks, run them highly available, and exclude only the namespaces needed to recover the webhook itself.",
		References:  []finding.Reference{refNSAAuth, baselines.K8s("Dynamic admission control: failure policy", "https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#failure-policy")},
		Limitations: "Webhooks that are not security controls (e.g. defaulting or metrics) are reported too when they fail open; waive them with a justification.",
	},
	Kinds: []string{"ValidatingWebhookConfiguration"},
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
