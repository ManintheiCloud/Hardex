package controlplane

import (
	"fmt"
	"strings"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// The API server's structured configuration files (apiserver.config.k8s.io),
// read when they are part of the input: --authentication-config,
// --authorization-config and --encryption-provider-config point at them.
// Field semantics follow k8s.io/apiserver/pkg/apis/apiserver/v1.
const apiserverConfigGroup = "apiserver.config.k8s.io/"

func configFiles(inv *resource.Inventory, kind string) []*resource.Object {
	var out []*resource.Object
	for _, o := range inv.OfKind(kind) {
		if strings.HasPrefix(o.APIVersion, apiserverConfigGroup) {
			out = append(out, o)
		}
	}
	return out
}

// healthPaths are the endpoints the documentation suggests limiting
// anonymous access to.
var healthPaths = map[string]bool{"/livez": true, "/readyz": true, "/healthz": true}

// checkAuthenticationConfig reports an AuthenticationConfiguration whose
// anonymous authenticator is enabled for anything beyond health checks.
func checkAuthenticationConfig(ctx *assessment.Context, o *resource.Object) {
	anon := resource.Map(o.Raw, "anonymous")
	if anon == nil {
		return
	}
	if on, _ := resource.Bool(anon, "enabled"); !on {
		return
	}
	conds := resource.Maps(anon, "conditions")
	if len(conds) == 0 {
		ctx.Report(assessment.Hit{Object: o, Path: "anonymous.enabled", Observed: "true",
			Message: "authentication configuration accepts anonymous requests on every path"})
		return
	}
	for i, c := range conds {
		if p := resource.String(c, "path"); !healthPaths[p] {
			ctx.Report(assessment.Hit{Object: o, Path: fmt.Sprintf("anonymous.conditions[%d].path", i), Observed: p,
				Message: fmt.Sprintf("authentication configuration accepts anonymous requests on %s, not only health checks", p)})
		}
	}
}

// anonymousSectionEverywhere reports whether every AuthenticationConfiguration
// in the input has an anonymous section; without one, --anonymous-auth
// (default true) still decides.
func anonymousSectionEverywhere(cfgs []*resource.Object) bool {
	for _, o := range cfgs {
		if resource.Map(o.Raw, "anonymous") == nil {
			return false
		}
	}
	return true
}

// checkAuthorizationConfig reports an AuthorizationConfiguration that
// includes AlwaysAllow (critical) or does not include RBAC (medium), as the
// flag check does for --authorization-mode.
func checkAuthorizationConfig(ctx *assessment.Context, o *resource.Object, medium *finding.Severity) {
	auths := resource.Maps(o.Raw, "authorizers")
	rbac := false
	for i, a := range auths {
		switch resource.String(a, "type") {
		case "AlwaysAllow":
			ctx.Report(assessment.Hit{Object: o, Path: fmt.Sprintf("authorizers[%d].type", i), Observed: "AlwaysAllow",
				Message: "authorization configuration includes AlwaysAllow"})
		case "RBAC":
			rbac = true
		}
	}
	if !rbac {
		var types []string
		for _, a := range auths {
			types = append(types, resource.String(a, "type"))
		}
		ctx.Report(assessment.Hit{Object: o, Path: "authorizers", Observed: strings.Join(types, ","), Severity: medium,
			Message: "authorization configuration does not enable RBAC"})
	}
}

// secretsEntry returns the index of the resources entry that applies to
// Secrets: the first whose resources list names secrets, the core group
// ("*.") or everything ("*.*").
func secretsEntry(entries []map[string]any) int {
	for i, e := range entries {
		for _, r := range resource.Strings(e, "resources") {
			if r == "secrets" || r == "secrets." || r == "*." || r == "*.*" {
				return i
			}
		}
	}
	return -1
}

// checkEncryptionConfig reports an EncryptionConfiguration under which
// Secrets are written to etcd unencrypted: no entry covers them, or the
// first provider of the entry that does is identity.
func checkEncryptionConfig(ctx *assessment.Context, o *resource.Object) {
	entries := resource.Maps(o.Raw, "resources")
	i := secretsEntry(entries)
	if i < 0 {
		ctx.Report(assessment.Hit{Object: o, Path: "resources", Observed: "<no entry for secrets>",
			Message: "encryption configuration does not cover Secrets; they are stored unencrypted"})
		return
	}
	providers := resource.Maps(entries[i], "providers")
	if len(providers) == 0 {
		return // invalid configuration; the API server refuses to start
	}
	if _, identity := providers[0]["identity"]; identity {
		ctx.Report(assessment.Hit{Object: o, Path: fmt.Sprintf("resources[%d].providers[0]", i), Observed: "identity",
			Message: "encryption configuration writes Secrets unencrypted: identity is the first provider"})
	}
}
