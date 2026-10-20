package kubernetes

import (
	"strings"

	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/remediation"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// Fixers returns the automatic remediations, keyed by rule ID.
//
// A rule has a fixer only when a single, safe-by-construction value exists.
// Choices that need human judgement — which UID to run as, which image
// version to pin, which capability a workload really needs, which RBAC grant
// to remove — are left to the rule's remediation guidance. RBAC, control
// plane and node findings have no automatic fixes by design (ADR 0003).
func Fixers() map[string]remediation.Fixer {
	return map[string]remediation.Fixer{
		"HX-WL-001":  setAtFindingPath(false, remediation.Medium, "set privileged: false"),
		"HX-WL-002":  setAtFindingPath(false, remediation.High, "stop sharing the host namespace"),
		"HX-WL-004":  setAtFindingPath(false, remediation.Low, "set allowPrivilegeEscalation: false"),
		"HX-WL-005":  fixRunAsNonRoot,
		"HX-WL-007":  fixDropAll,
		"HX-WL-008":  fixSeccomp,
		"HX-WL-009":  setAtFindingPath(true, remediation.High, "set readOnlyRootFilesystem: true (mount emptyDir for writable paths)"),
		"HX-WL-013":  setAtFindingPath(false, remediation.Medium, "set automountServiceAccountToken: false"),
		"HX-WL-014":  removeAtFindingPath(remediation.High, "remove hostPort"),
		"HX-WL-015":  fixAppArmor,
		"HX-WL-017":  setAtFindingPath("Default", remediation.Low, "set procMount: Default"),
		"HX-WL-021":  removeAtFindingPath(remediation.Medium, "remove host so the handler targets the pod"),
		"HX-NET-001": defaultDeny("Ingress"),
		"HX-NET-002": defaultDeny("Egress"),
	}
}

func setAtFindingPath(value any, risk remediation.Risk, desc string) remediation.Fixer {
	return func(_ *resource.Object, f finding.Finding) (*remediation.Change, string) {
		path := remediation.ParsePath(f.Path)
		if len(path) == 0 {
			return nil, "finding has no field path"
		}
		return &remediation.Change{Description: desc, Risk: risk, Set: []remediation.Assignment{{Path: path, Value: value}}}, ""
	}
}

func removeAtFindingPath(risk remediation.Risk, desc string) remediation.Fixer {
	return func(_ *resource.Object, f finding.Finding) (*remediation.Change, string) {
		path := remediation.ParsePath(f.Path)
		if len(path) == 0 {
			return nil, "finding has no field path"
		}
		return &remediation.Change{Description: desc, Risk: risk, Set: []remediation.Assignment{{Path: path, Remove: true}}}, ""
	}
}

func fixRunAsNonRoot(obj *resource.Object, f finding.Finding) (*remediation.Change, string) {
	if strings.HasSuffix(f.Path, ".runAsUser") {
		return nil, "runs as UID 0 explicitly; choose a non-root UID the image supports"
	}
	return setAtFindingPath(true, remediation.Medium, "set runAsNonRoot: true (the kubelet will refuse to start a root image)")(obj, f)
}

func fixDropAll(obj *resource.Object, f finding.Finding) (*remediation.Change, string) {
	if !strings.HasSuffix(f.Path, ".drop") {
		return nil, "added capabilities must be reviewed individually"
	}
	return setAtFindingPath([]any{"ALL"}, remediation.Medium, `set capabilities.drop: ["ALL"]`)(obj, f)
}

func fixSeccomp(obj *resource.Object, f finding.Finding) (*remediation.Change, string) {
	risk := remediation.Low
	if f.Observed == "Unconfined" {
		risk = remediation.Medium // someone disabled it deliberately
	}
	return setAtFindingPath("RuntimeDefault", risk, "set seccompProfile.type: RuntimeDefault")(obj, f)
}

func fixAppArmor(obj *resource.Object, f finding.Finding) (*remediation.Change, string) {
	if strings.HasPrefix(f.Path, "metadata.annotations") {
		return nil, "legacy AppArmor annotation; replace it with securityContext.appArmorProfile"
	}
	return setAtFindingPath("RuntimeDefault", remediation.Medium, "set appArmorProfile.type: RuntimeDefault")(obj, f)
}

func defaultDeny(direction string) remediation.Fixer {
	lower := strings.ToLower(direction)
	return func(_ *resource.Object, f finding.Finding) (*remediation.Change, string) {
		return &remediation.Change{
			Description: "add a default-deny " + lower + " NetworkPolicy; then allow required traffic explicitly",
			Risk:        remediation.High,
			Create: map[string]any{
				"apiVersion": "networking.k8s.io/v1",
				"kind":       "NetworkPolicy",
				"metadata": map[string]any{
					"name":      "default-deny-" + lower,
					"namespace": f.Resource.Name,
					"labels":    map[string]any{"app.kubernetes.io/managed-by": "hardex"},
				},
				"spec": map[string]any{
					"podSelector": map[string]any{},
					"policyTypes": []any{direction},
				},
			},
		}, ""
	}
}
