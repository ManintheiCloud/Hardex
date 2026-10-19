package controlplane

import (
	"fmt"
	"strings"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
)

// Rules returns every control-plane rule.
func Rules() []assessment.Rule {
	return []assessment.Rule{anonymousAuth, authorizationMode, auditLogging, profiling, admissionPlugins, etcdTLS, encryptionAtRest, kubeletCA, failOpenWebhooks, externalWebhooks}
}

var (
	refCISAPI  = baselines.CIS("1.2", "API Server")
	refCISEtcd = baselines.CIS("2", "etcd")
	refNSAAuth = baselines.NSA("Authentication and authorization")
	refNSAAud  = baselines.NSA("Audit logging and threat detection")
	refNSACP   = baselines.NSA("Network separation and hardening — control plane")
)

func report(ctx *assessment.Context, c component, flag, observed, msg string, sev *finding.Severity) {
	ctx.Report(assessment.Hit{Object: c.obj, Container: c.container.Name, Path: c.path() + "[--" + flag + "]",
		Observed: observed, Message: msg, Severity: sev})
}

// reportItem reports a problem with one item of a list-valued flag, so that
// separate problems with the same flag have distinct field paths (and
// therefore distinct fingerprints).
func reportItem(ctx *assessment.Context, c component, flag, item, observed, msg string, sev *finding.Severity) {
	ctx.Report(assessment.Hit{Object: c.obj, Container: c.container.Name, Path: c.path() + "[--" + flag + "][" + item + "]",
		Observed: observed, Message: msg, Severity: sev})
}

func apiServerRule(meta assessment.Metadata, check func(ctx *assessment.Context, c component)) assessment.Rule {
	return assessment.InventoryRule{Meta: meta, Check: func(ctx *assessment.Context) {
		for _, c := range findComponents(ctx.Inventory, "kube-apiserver") {
			check(ctx, c)
		}
	}}
}

var anonymousAuth = apiServerRule(assessment.Metadata{
	ID:          "HX-CP-001",
	Title:       "API server allows anonymous requests",
	Severity:    finding.Medium,
	Category:    assessment.CategoryControlPlane,
	Description: "Detects kube-apiserver configurations that do not set --anonymous-auth=false and do not use a structured authentication configuration.",
	Rationale:   "Anonymous requests are attributed to system:anonymous. Any RBAC binding to that user or system:unauthenticated, made in error or by an attacker, becomes reachable by anyone who can reach the API server.",
	Remediation: "Set --anonymous-auth=false. If anonymous health checks are required, use a structured --authentication-config that limits anonymous access to the health endpoints.",
	References:  []finding.Reference{refCISAPI, refNSAAuth},
	Limitations: "When --authentication-config is set, its contents are not yet inspected.",
}, func(ctx *assessment.Context, c component) {
	if _, ok := c.flag("authentication-config"); ok {
		return
	}
	if v, _ := c.flag("anonymous-auth"); v != "false" {
		report(ctx, c, "anonymous-auth", valueOrDefault(v, "true"), "API server accepts anonymous requests", nil)
	}
})

var authorizationMode = apiServerRule(assessment.Metadata{
	ID:          "HX-CP-002",
	Title:       "API server authorization disabled or weak",
	Severity:    finding.Critical,
	Category:    assessment.CategoryControlPlane,
	Description: "Detects kube-apiserver configurations whose --authorization-mode is unset (defaulting to AlwaysAllow) or includes AlwaysAllow, and those that do not enable RBAC (medium).",
	Rationale:   "With AlwaysAllow, every authenticated request is permitted: any service account token is effectively cluster-admin.",
	Remediation: "Set --authorization-mode=Node,RBAC.",
	References:  []finding.Reference{refCISAPI, refNSAAuth},
	Limitations: "When --authorization-config is set, its contents are not yet inspected.",
}, func(ctx *assessment.Context, c component) {
	if _, ok := c.flag("authorization-config"); ok {
		return
	}
	v, set := c.flag("authorization-mode")
	switch {
	case !set:
		report(ctx, c, "authorization-mode", "<unset> (AlwaysAllow)", "API server authorizes every request", nil)
	case listContains(v, "AlwaysAllow"):
		report(ctx, c, "authorization-mode", v, "API server authorization mode includes AlwaysAllow", nil)
	case !listContains(v, "RBAC"):
		report(ctx, c, "authorization-mode", v, "API server does not enable RBAC authorization", assessment.SeverityOverride(finding.Medium))
	}
})

var auditLogging = apiServerRule(assessment.Metadata{
	ID:          "HX-CP-003",
	Title:       "API server audit logging not configured",
	Severity:    finding.Medium,
	Category:    assessment.CategoryControlPlane,
	Description: "Detects kube-apiserver configurations without an audit policy, or with a policy but no log or webhook backend.",
	Rationale:   "Without audit logs there is no record of who did what through the API. Incidents cannot be investigated and malicious activity cannot be detected.",
	Remediation: "Set --audit-policy-file to a reviewed policy and --audit-log-path (with --audit-log-maxage, -maxbackup, -maxsize) or --audit-webhook-config-file.",
	References:  []finding.Reference{refCISAPI, refNSAAud},
}, func(ctx *assessment.Context, c component) {
	if _, ok := c.flag("audit-policy-file"); !ok {
		report(ctx, c, "audit-policy-file", "<unset>", "API server has no audit policy; no requests are audited", nil)
		return
	}
	_, logOK := c.flag("audit-log-path")
	_, hookOK := c.flag("audit-webhook-config-file")
	if !logOK && !hookOK {
		report(ctx, c, "audit-log-path", "<unset>", "audit policy is set but no audit backend is configured", nil)
	}
})

var profiling = assessment.InventoryRule{
	Meta: assessment.Metadata{
		ID:          "HX-CP-004",
		Title:       "Control-plane profiling enabled",
		Severity:    finding.Low,
		Category:    assessment.CategoryControlPlane,
		Description: "Detects kube-apiserver, kube-controller-manager and kube-scheduler without --profiling=false.",
		Rationale:   "Profiling endpoints reveal detailed program and system information and add an unnecessary attack surface.",
		Remediation: "Set --profiling=false on each control-plane component.",
		References:  []finding.Reference{refCISAPI, baselines.CIS("1.3", "Controller Manager"), baselines.CIS("1.4", "Scheduler")},
	},
	Check: func(ctx *assessment.Context) {
		for _, bin := range []string{"kube-apiserver", "kube-controller-manager", "kube-scheduler"} {
			for _, c := range findComponents(ctx.Inventory, bin) {
				if v, _ := c.flag("profiling"); v != "false" {
					report(ctx, c, "profiling", valueOrDefault(v, "true"), bin+" exposes profiling endpoints", nil)
				}
			}
		}
	},
}

var admissionPlugins = apiServerRule(assessment.Metadata{
	ID:          "HX-CP-005",
	Title:       "Weak admission control",
	Severity:    finding.High,
	Category:    assessment.CategoryControlPlane,
	Description: "Detects kube-apiserver configurations that enable AlwaysAdmit (high), disable PodSecurity (high), or do not enable NodeRestriction (medium).",
	Rationale:   "Admission control is where cluster-wide guardrails are enforced. AlwaysAdmit bypasses it; without PodSecurity, nothing blocks privileged pods; without NodeRestriction, a compromised kubelet can modify any node or pod object.",
	Remediation: "Remove AlwaysAdmit, keep PodSecurity enabled, and add NodeRestriction to --enable-admission-plugins.",
	References:  []finding.Reference{refCISAPI, refNSAAuth},
}, func(ctx *assessment.Context, c component) {
	enabled, _ := c.flag("enable-admission-plugins")
	disabled, _ := c.flag("disable-admission-plugins")
	if listContains(enabled, "AlwaysAdmit") {
		reportItem(ctx, c, "enable-admission-plugins", "AlwaysAdmit", enabled, "AlwaysAdmit admission plugin is enabled", nil)
	}
	if listContains(disabled, "PodSecurity") {
		reportItem(ctx, c, "disable-admission-plugins", "PodSecurity", disabled, "PodSecurity admission is disabled", nil)
	}
	if !listContains(enabled, "NodeRestriction") {
		reportItem(ctx, c, "enable-admission-plugins", "NodeRestriction", valueOrDefault(enabled, "<unset>"), "NodeRestriction admission plugin is not enabled",
			assessment.SeverityOverride(finding.Medium))
	}
})

var etcdTLS = assessment.InventoryRule{
	Meta: assessment.Metadata{
		ID:          "HX-CP-006",
		Title:       "etcd not protected by mutual TLS",
		Severity:    finding.High,
		Category:    assessment.CategoryControlPlane,
		Description: "Detects etcd without client and peer certificate authentication (or using self-signed auto-TLS), and kube-apiserver without etcd client certificates.",
		Rationale:   "etcd stores every object in the cluster, including all Secrets. Anyone who can talk to etcd without a client certificate can read or rewrite the entire cluster state, bypassing authentication, authorization and audit.",
		Remediation: "Run etcd with --client-cert-auth=true, --peer-client-cert-auth=true, CA-issued certificates (not --auto-tls), and give kube-apiserver --etcd-cafile, --etcd-certfile and --etcd-keyfile.",
		References:  []finding.Reference{refCISEtcd, refNSACP},
	},
	Check: func(ctx *assessment.Context) {
		for _, c := range findComponents(ctx.Inventory, "etcd") {
			for _, f := range []string{"client-cert-auth", "peer-client-cert-auth"} {
				if v, _ := c.flag(f); v != "true" {
					report(ctx, c, f, valueOrDefault(v, "false"), "etcd does not require "+strings.TrimSuffix(f, "-cert-auth")+" certificates", nil)
				}
			}
			for _, f := range []string{"auto-tls", "peer-auto-tls"} {
				if v, _ := c.flag(f); v == "true" {
					report(ctx, c, f, v, "etcd uses self-signed auto-generated certificates", nil)
				}
			}
			for _, f := range []string{"cert-file", "key-file", "trusted-ca-file"} {
				if _, ok := c.flag(f); !ok {
					report(ctx, c, f, "<unset>", "etcd is missing --"+f, nil)
				}
			}
		}
		for _, c := range findComponents(ctx.Inventory, "kube-apiserver") {
			for _, f := range []string{"etcd-cafile", "etcd-certfile", "etcd-keyfile"} {
				if _, ok := c.flag(f); !ok {
					report(ctx, c, f, "<unset>", "API server does not authenticate to etcd with TLS (--"+f+" unset)", nil)
				}
			}
		}
	},
}

var encryptionAtRest = apiServerRule(assessment.Metadata{
	ID:          "HX-CP-007",
	Title:       "Secrets not encrypted at rest",
	Severity:    finding.Medium,
	Category:    assessment.CategoryControlPlane,
	Description: "Detects kube-apiserver configurations without --encryption-provider-config.",
	Rationale:   "Without encryption at rest, Secrets are stored in etcd in plain form; an etcd backup or disk snapshot discloses every credential in the cluster.",
	Remediation: "Configure --encryption-provider-config with a KMS v2 provider (preferred) or aescbc/secretbox, covering at least secrets, and rewrite existing secrets.",
	References:  []finding.Reference{refCISAPI, baselines.NSA("Authentication and authorization — secrets")},
	Limitations: "The contents of the encryption configuration (e.g. an identity provider listed first) are not yet inspected.",
}, func(ctx *assessment.Context, c component) {
	if _, ok := c.flag("encryption-provider-config"); !ok {
		report(ctx, c, "encryption-provider-config", "<unset>", "API server does not encrypt resources at rest", nil)
	}
})

var kubeletCA = apiServerRule(assessment.Metadata{
	ID:          "HX-CP-008",
	Title:       "API server does not verify kubelet certificates",
	Severity:    finding.Medium,
	Category:    assessment.CategoryControlPlane,
	Description: "Detects kube-apiserver configurations without --kubelet-certificate-authority.",
	Rationale:   "Without it the API server does not verify kubelet serving certificates, so exec, logs and port-forward traffic can be intercepted by anyone able to impersonate a node on the network.",
	Remediation: "Enable kubelet serving certificate bootstrap (serverTLSBootstrap) and set --kubelet-certificate-authority to the CA that signs them.",
	References:  []finding.Reference{refCISAPI, refNSACP},
}, func(ctx *assessment.Context, c component) {
	if _, ok := c.flag("kubelet-certificate-authority"); !ok {
		report(ctx, c, "kubelet-certificate-authority", "<unset>", "API server connects to kubelets without verifying their certificates", nil)
	}
})

func valueOrDefault(v, def string) string {
	if v == "" {
		return def
	}
	return fmt.Sprint(v)
}
