package workloads

import (
	"fmt"

	"github.com/ManintheiCloud/Hardex/core/resource"
)

// EscapeVector reports whether a pod spec gives its containers a direct path
// to root on the node, and how. It is the shared definition used by
// attack-path analysis; each vector is also reported by its own HX-WL rule.
func EscapeVector(pod map[string]any) (string, bool) {
	if v, _ := resource.Bool(pod, "hostPID"); v {
		return "shares the host PID namespace", true
	}
	if v, _ := resource.Bool(pod, "securityContext", "windowsOptions", "hostProcess"); v {
		return "runs as a Windows HostProcess", true
	}
	for _, vol := range resource.Maps(pod, "volumes") {
		if p := resource.String(vol, "hostPath", "path"); p != "" && isCriticalHostPath(p) {
			return fmt.Sprintf("mounts host path %s", p), true
		}
	}
	for _, c := range resource.Containers(pod) {
		if v, _ := resource.Bool(c.Spec, "securityContext", "privileged"); v {
			return fmt.Sprintf("container %q is privileged", c.Name), true
		}
		if v, _ := resource.Bool(c.Spec, "securityContext", "windowsOptions", "hostProcess"); v {
			return fmt.Sprintf("container %q runs as a Windows HostProcess", c.Name), true
		}
		for _, cp := range resource.Strings(c.Spec, "securityContext", "capabilities", "add") {
			if n := normalizeCap(cp); criticalCaps[n] {
				return fmt.Sprintf("container %q adds %s", c.Name, n), true
			}
		}
	}
	return "", false
}
