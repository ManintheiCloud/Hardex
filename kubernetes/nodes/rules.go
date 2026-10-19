// Package nodes implements checks on kubelet configuration files
// (KubeletConfiguration, kubelet.config.k8s.io/v1beta1).
//
// Unset fields are evaluated against the v1beta1 defaults applied by the
// kubelet when it loads a configuration file. These differ from the defaults
// of the equivalent command-line flags; kubelets configured purely through
// flags are not yet assessed.
package nodes

import (
	"fmt"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// Rules returns every node rule.
func Rules() []assessment.Rule {
	return []assessment.Rule{anonymousAuth, authorization, readOnlyPort, kernelDefaults}
}

var (
	refCISKubelet = baselines.CIS("4.2", "Kubelet")
	refNSANode    = baselines.NSA("Network separation and hardening — worker node")
	limitation    = "Only KubeletConfiguration files are assessed; command-line flags that override them are not visible."
)

func kubeletRule(meta assessment.Metadata, check func(ctx *assessment.Context, o *resource.Object)) assessment.Rule {
	meta.Category = assessment.CategoryNodes
	if meta.Limitations == "" {
		meta.Limitations = limitation
	}
	return assessment.ObjectRule{Meta: meta, Kinds: []string{"KubeletConfiguration"}, Check: check}
}

var anonymousAuth = kubeletRule(assessment.Metadata{
	ID:          "HX-NODE-001",
	Title:       "Kubelet allows anonymous requests",
	Severity:    finding.High,
	Description: "Detects kubelet configurations that set authentication.anonymous.enabled to true.",
	Rationale:   "The kubelet API can list pods, read logs and execute commands in containers. Anonymous access lets anyone who can reach port 10250 attempt those operations.",
	Remediation: "Set authentication.anonymous.enabled: false and authentication.webhook.enabled: true.",
	References:  []finding.Reference{refCISKubelet, refNSANode},
}, func(ctx *assessment.Context, o *resource.Object) {
	if v, _ := resource.Bool(o.Raw, "authentication", "anonymous", "enabled"); v {
		ctx.Report(assessment.Hit{Object: o, Path: "authentication.anonymous.enabled", Observed: "true",
			Message: "kubelet accepts anonymous requests"})
	}
})

var authorization = kubeletRule(assessment.Metadata{
	ID:          "HX-NODE-002",
	Title:       "Kubelet authorization disabled",
	Severity:    finding.Critical,
	Description: "Detects kubelet configurations with authorization.mode AlwaysAllow, or with webhook authentication explicitly disabled.",
	Rationale:   "With AlwaysAllow, any client that authenticates to the kubelet (or any anonymous client, if anonymous auth is on) can execute commands in every container on the node.",
	Remediation: "Set authorization.mode: Webhook and authentication.webhook.enabled: true.",
	References:  []finding.Reference{refCISKubelet, refNSANode},
}, func(ctx *assessment.Context, o *resource.Object) {
	if m := resource.String(o.Raw, "authorization", "mode"); m == "AlwaysAllow" {
		ctx.Report(assessment.Hit{Object: o, Path: "authorization.mode", Observed: m, Message: "kubelet authorizes every request"})
	}
	if v, set := resource.Bool(o.Raw, "authentication", "webhook", "enabled"); set && !v {
		ctx.Report(assessment.Hit{Object: o, Path: "authentication.webhook.enabled", Observed: "false",
			Severity: assessment.SeverityOverride(finding.High),
			Message:  "kubelet does not delegate bearer-token authentication to the API server"})
	}
})

var readOnlyPort = kubeletRule(assessment.Metadata{
	ID:          "HX-NODE-003",
	Title:       "Kubelet read-only port enabled",
	Severity:    finding.Medium,
	Description: "Detects kubelet configurations with a non-zero readOnlyPort.",
	Rationale:   "The read-only port (historically 10255) serves pod specs and node information without any authentication or authorization, which aids reconnaissance and can leak environment variables.",
	Remediation: "Set readOnlyPort: 0.",
	References:  []finding.Reference{refCISKubelet, refNSANode},
}, func(ctx *assessment.Context, o *resource.Object) {
	if n, ok := resource.Number(o.Raw, "readOnlyPort"); ok && n != 0 {
		ctx.Report(assessment.Hit{Object: o, Path: "readOnlyPort", Observed: fmt.Sprint(n),
			Message: fmt.Sprintf("kubelet serves unauthenticated read-only API on port %v", n)})
	}
})

var kernelDefaults = kubeletRule(assessment.Metadata{
	ID:          "HX-NODE-004",
	Title:       "Kubelet does not protect kernel defaults",
	Severity:    finding.Low,
	Description: "Detects kubelet configurations that do not set protectKernelDefaults: true.",
	Rationale:   "When enabled, the kubelet refuses to start if kernel tunables differ from its expected safe defaults, instead of silently modifying them.",
	Remediation: "Set protectKernelDefaults: true after configuring the required sysctls on the node.",
	References:  []finding.Reference{refCISKubelet},
}, func(ctx *assessment.Context, o *resource.Object) {
	if v, _ := resource.Bool(o.Raw, "protectKernelDefaults"); !v {
		ctx.Report(assessment.Hit{Object: o, Path: "protectKernelDefaults", Observed: "false",
			Message: "kubelet may modify kernel parameters"})
	}
})
