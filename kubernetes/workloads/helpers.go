// Package workloads implements checks on pod specifications: privilege,
// host access, Linux security modules, capabilities, and supply-chain hygiene.
//
// Together, the HX-WL rules cover every control in the Kubernetes Pod
// Security Standards (Baseline and Restricted levels), plus additional
// NSA/CISA recommendations that PSS does not include.
package workloads

import (
	"fmt"
	"strings"

	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

// containerVisitor is called for each container of each workload.
type containerVisitor func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string, c resource.Container)

// eachContainer builds an ObjectRule that visits every container.
func eachContainer(meta assessment.Metadata, fn containerVisitor) assessment.Rule {
	return eachPod(meta, func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string) {
		for _, c := range resource.Containers(pod) {
			fn(ctx, obj, pod, prefix, c)
		}
	})
}

// eachPod builds an ObjectRule that visits every workload's pod spec.
func eachPod(meta assessment.Metadata, fn func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string)) assessment.Rule {
	return assessment.ObjectRule{
		Meta:  meta,
		Kinds: resource.WorkloadKinds(),
		Check: func(ctx *assessment.Context, obj *resource.Object) {
			pod, prefix := resource.PodSpec(obj)
			if pod == nil {
				return
			}
			if !ctx.Options.IncludeSystem && obj.EffectiveNamespace() == "kube-system" {
				// Platform components (kube-proxy, the CNI, CoreDNS, and the
				// control-plane static pods, which the control-plane rules
				// assess) legitimately need host access and are not changed
				// by cluster users. --include-system assesses them too.
				return
			}
			fn(ctx, obj, pod, prefix)
		},
	}
}

// effective resolves a security context field that may be set at the pod
// level and overridden per container. It returns the value, the path it was
// read from, and whether it was set at all.
func effective(pod map[string]any, prefix string, c resource.Container, field ...string) (any, string, bool) {
	cPath := append([]string{"securityContext"}, field...)
	if v, ok := resource.Lookup(c.Spec, cPath...); ok {
		return v, c.Path(prefix) + "." + strings.Join(cPath, "."), true
	}
	if v, ok := resource.Lookup(pod, cPath...); ok {
		return v, prefix + "." + strings.Join(cPath, "."), true
	}
	return nil, c.Path(prefix) + "." + strings.Join(cPath, "."), false
}

// overriddenPodLevel returns a pod-level security context field that every
// container overrides with its own value, so that no running container uses
// it. The Pod Security Standards (and PodSecurity admission) still forbid a
// disallowed value there, and with reason: an ephemeral container added
// later (kubectl debug) that does not set the field inherits it.
func overriddenPodLevel(pod map[string]any, prefix string, field ...string) (any, string, bool) {
	path := append([]string{"securityContext"}, field...)
	v, ok := resource.Lookup(pod, path...)
	cs := resource.Containers(pod)
	if !ok || len(cs) == 0 {
		return nil, "", false
	}
	for _, c := range cs {
		if _, set := resource.Lookup(c.Spec, path...); !set {
			return nil, "", false
		}
	}
	return v, prefix + "." + strings.Join(path, "."), true
}

// inheritedNote is appended to findings on an overridden pod-level value.
const inheritedNote = "; every container sets its own value, but a container added later (kubectl debug) inherits this one"

// isWindows reports whether the pod declares a Windows OS. Several Linux-only
// controls do not apply to Windows pods (per the Pod Security Standards).
func isWindows(pod map[string]any) bool {
	return resource.String(pod, "os", "name") == "windows"
}

// userNamespaced reports whether the pod runs in its own user namespace
// (hostUsers: false). Since Kubernetes 1.35 the Pod Security Standards relax
// the root-user and /proc controls for such pods: UID 0 inside the pod maps
// to an unprivileged UID on the node.
func userNamespaced(pod map[string]any) bool {
	v, ok := resource.Lookup(pod, "hostUsers")
	b, isBool := v.(bool)
	return ok && isBool && !b
}

func show(v any) string {
	if v == nil {
		return "<unset>"
	}
	return fmt.Sprint(v)
}

func normalizeCap(c string) string {
	return strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(c)), "CAP_")
}
