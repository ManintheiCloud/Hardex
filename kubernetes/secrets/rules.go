// Package secrets implements checks on how credentials are stored and passed
// to workloads.
//
// Every rule in this package must avoid copying secret material into
// findings: findings are written to terminals, CI logs and SARIF uploads.
package secrets

import (
	"fmt"
	"regexp"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// Rules returns every secrets rule.
func Rules() []assessment.Rule { return []assessment.Rule{inlineSecretData, literalEnvCredential} }

var refNSASecrets = baselines.NSA("Authentication and authorization — secrets")
var refCISSecrets = baselines.CIS("5.4", "Secrets Management")

// Secret types managed by Kubernetes or tooling rather than written by hand.
var managedSecretTypes = map[string]bool{
	"kubernetes.io/service-account-token": true,
	"helm.sh/release.v1":                  true,
	"bootstrap.kubernetes.io/token":       true,
}

var inlineSecretData = assessment.ObjectRule{
	Meta: assessment.Metadata{
		ID:          "HX-SEC-001",
		Title:       "Secret values in manifest",
		Severity:    finding.Medium,
		Category:    assessment.CategorySecrets,
		Description: "Detects Secret manifests that carry their values inline (data or stringData).",
		Rationale:   "Secret data is base64-encoded, not encrypted. A Secret manifest committed to version control exposes the credential to everyone with repository access, forever, including in history.",
		Remediation: "Keep secret values out of manifests: use an external secret store (e.g. via the Secrets Store CSI driver or an external-secrets operator) or encrypt them at rest in the repository (e.g. SOPS, sealed secrets).",
		References:  []finding.Reference{refNSASecrets, refCISSecrets},
		Limitations: "When scanning a live-cluster export, Secrets necessarily contain data; disable this rule for such scans.",
	},
	Kinds: []string{"Secret"},
	Check: func(ctx *assessment.Context, obj *resource.Object) {
		if managedSecretTypes[resource.String(obj.Raw, "type")] {
			return
		}
		n := len(resource.Map(obj.Raw, "data")) + len(resource.Map(obj.Raw, "stringData"))
		if n == 0 {
			return
		}
		ctx.Report(assessment.Hit{Object: obj, Path: "data", Observed: fmt.Sprintf("%d key(s), values redacted", n),
			Message: fmt.Sprintf("Secret carries %d value(s) inline", n)})
	},
}

var credentialName = regexp.MustCompile(`(?i)(passw(or)?d|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential)`)

// Names that match the pattern but conventionally hold non-secret values.
var benignSuffix = regexp.MustCompile(`(?i)(_file|_path|_url|_uri|_endpoint|_host|_name|_user(name)?|_enabled|_ttl|_timeout|_header)$`)

var literalEnvCredential = assessment.ObjectRule{
	Meta: assessment.Metadata{
		ID:          "HX-SEC-002",
		Title:       "Credential in environment variable literal",
		Severity:    finding.Medium,
		Category:    assessment.CategorySecrets,
		Description: "Detects container environment variables whose name suggests a credential and whose value is written literally in the manifest instead of referencing a Secret.",
		Rationale:   "Literal values live in the workload spec, which far more principals can read than Secrets (anyone with get on Deployments), and they are copied into version control and controller history.",
		Remediation: "Move the value into a Secret and reference it with env[].valueFrom.secretKeyRef, or mount it as a file.",
		References:  []finding.Reference{refNSASecrets, refCISSecrets},
		Limitations: "Name-based heuristic: credentials under unremarkable names are missed, and non-secret values under credential-like names may be reported. Values are never included in findings.",
	},
	Kinds: resource.WorkloadKinds(),
	Check: func(ctx *assessment.Context, obj *resource.Object) {
		pod, prefix := resource.PodSpec(obj)
		for _, c := range resource.Containers(pod) {
			for i, env := range resource.Maps(c.Spec, "env") {
				name := resource.String(env, "name")
				if resource.String(env, "value") == "" || !credentialName.MatchString(name) || benignSuffix.MatchString(name) {
					continue
				}
				ctx.Report(assessment.Hit{Object: obj, Container: c.Name,
					Path: fmt.Sprintf("%s.env[%d].value", c.Path(prefix), i), Observed: name + "=<redacted>",
					Message: fmt.Sprintf("container %q sets %s from a literal value", c.Name, name)})
			}
		}
	},
}
