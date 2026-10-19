package workloads

import (
	"fmt"
	"strings"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

var seccomp = eachContainer(assessment.Metadata{
	ID:          "HX-WL-008",
	Title:       "Seccomp profile not enforced",
	Severity:    finding.Medium,
	Category:    assessment.CategoryWorkloads,
	Description: "Detects Linux containers whose effective seccomp profile is not RuntimeDefault or Localhost. An explicit Unconfined profile is raised to high.",
	Rationale:   "Seccomp filters the system calls a container may make. Without it, the full kernel syscall surface is reachable, and many container-escape exploits rely on syscalls that the runtime default profile blocks.",
	Remediation: "Set securityContext.seccompProfile.type: RuntimeDefault at pod level (or Localhost with a reviewed profile).",
	References:  []finding.Reference{baselines.PSS("Baseline", "Seccomp"), baselines.PSS("Restricted", "Seccomp"), refNSAPod, refCISPods},
	Limitations: "Clusters with the kubelet's seccompDefault feature enabled apply RuntimeDefault implicitly; Hardex cannot observe that from manifests and reports the unset profile.",
}, func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string, c resource.Container) {
	if isWindows(pod) {
		return
	}
	v, path, set := effective(pod, prefix, c, "seccompProfile", "type")
	typ, _ := v.(string)
	switch {
	case typ == "RuntimeDefault" || typ == "Localhost":
		return
	case set && typ == "Unconfined":
		ctx.Report(assessment.Hit{Object: obj, Container: c.Name, Path: path, Observed: typ, Severity: sevHigh,
			Message: fmt.Sprintf("container %q explicitly disables seccomp", c.Name)})
	default:
		ctx.Report(assessment.Hit{Object: obj, Container: c.Name, Path: path, Observed: show(v),
			Message: fmt.Sprintf("container %q has no seccomp profile", c.Name)})
	}
})

var appArmor = eachContainer(assessment.Metadata{
	ID:          "HX-WL-015",
	Title:       "AppArmor disabled",
	Severity:    finding.High,
	Category:    assessment.CategoryWorkloads,
	Description: "Detects containers whose AppArmor profile is explicitly set to Unconfined, through the securityContext field or the legacy annotation.",
	Rationale:   "AppArmor confines file, mount and capability use even for root. Disabling it removes a layer that blocks several known escape techniques.",
	Remediation: "Remove the Unconfined setting so the runtime default applies, or set securityContext.appArmorProfile.type: RuntimeDefault.",
	References:  []finding.Reference{baselines.PSS("Baseline", "AppArmor"), refNSAPod, refCISPods},
}, func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string, c resource.Container) {
	if v, path, _ := effective(pod, prefix, c, "appArmorProfile", "type"); v == "Unconfined" {
		ctx.Report(assessment.Hit{Object: obj, Container: c.Name, Path: path, Observed: "Unconfined",
			Message: fmt.Sprintf("container %q runs without AppArmor", c.Name)})
		return
	}
	key := "container.apparmor.security.beta.kubernetes.io/" + c.Name
	if v := annotationOfPod(obj, key); v == "unconfined" {
		ctx.Report(assessment.Hit{Object: obj, Container: c.Name, Path: "metadata.annotations[" + key + "]", Observed: v,
			Message: fmt.Sprintf("container %q runs without AppArmor (legacy annotation)", c.Name)})
	}
})

func annotationOfPod(obj *resource.Object, key string) string {
	var anns map[string]any
	if obj.Kind == "Pod" {
		anns = resource.Map(obj.Raw, "metadata", "annotations")
	} else {
		// The pod template's metadata sits beside its spec.
		_, prefix := resource.PodSpec(obj)
		parts := strings.Split(strings.TrimSuffix(prefix, ".spec"), ".")
		anns = resource.Map(obj.Raw, append(parts, "metadata", "annotations")...)
	}
	v, _ := anns[key].(string)
	return v
}

var allowedSELinuxTypes = map[string]bool{
	"": true, "container_t": true, "container_init_t": true, "container_kvm_t": true, "container_engine_t": true,
}

var seLinux = eachContainer(assessment.Metadata{
	ID:          "HX-WL-016",
	Title:       "Custom SELinux context",
	Severity:    finding.High,
	Category:    assessment.CategoryWorkloads,
	Description: "Detects containers that set an SELinux type outside the container types allowed by the Pod Security Standards, or that set a custom SELinux user or role.",
	Rationale:   "Changing the SELinux context can place a container in a domain with host-level access (e.g. spc_t or unconfined_t), defeating mandatory access control.",
	Remediation: "Remove seLinuxOptions.user and .role, and use one of container_t, container_init_t, container_kvm_t or container_engine_t (or leave type unset).",
	References:  []finding.Reference{baselines.PSS("Baseline", "SELinux"), refNSAPod, refCISPods},
}, func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string, c resource.Container) {
	v, path, set := effective(pod, prefix, c, "seLinuxOptions")
	opts, _ := v.(map[string]any)
	if !set || opts == nil {
		return
	}
	if t := resource.String(opts, "type"); !allowedSELinuxTypes[t] {
		ctx.Report(assessment.Hit{Object: obj, Container: c.Name, Path: path + ".type", Observed: t,
			Message: fmt.Sprintf("container %q uses SELinux type %s", c.Name, t)})
	}
	for _, f := range []string{"user", "role"} {
		if s := resource.String(opts, f); s != "" {
			ctx.Report(assessment.Hit{Object: obj, Container: c.Name, Path: path + "." + f, Observed: s,
				Message: fmt.Sprintf("container %q sets a custom SELinux %s", c.Name, f)})
		}
	}
})

var procMount = eachContainer(assessment.Metadata{
	ID:          "HX-WL-017",
	Title:       "Unmasked /proc mount",
	Severity:    finding.High,
	Category:    assessment.CategoryWorkloads,
	Description: "Detects containers with securityContext.procMount set to Unmasked.",
	Rationale:   "The default /proc mount masks paths that leak host information or allow kernel tuning. Unmasking them exposes the host to the container.",
	Remediation: "Remove procMount or set it to Default.",
	References:  []finding.Reference{baselines.PSS("Baseline", "/proc Mount Type"), refCISPods},
}, func(ctx *assessment.Context, obj *resource.Object, _ map[string]any, prefix string, c resource.Container) {
	if v := resource.String(c.Spec, "securityContext", "procMount"); v != "" && v != "Default" {
		ctx.Report(assessment.Hit{Object: obj, Container: c.Name, Path: c.Path(prefix) + ".securityContext.procMount", Observed: v,
			Message: fmt.Sprintf("container %q uses procMount %s", c.Name, v)})
	}
})

// The "safe" sysctl set from the Pod Security Standards.
var safeSysctls = map[string]bool{
	"kernel.shm_rmid_forced": true, "net.ipv4.ip_local_port_range": true,
	"net.ipv4.ip_unprivileged_port_start": true, "net.ipv4.tcp_syncookies": true,
	"net.ipv4.ping_group_range": true, "net.ipv4.ip_local_reserved_ports": true,
	"net.ipv4.tcp_keepalive_time": true, "net.ipv4.tcp_fin_timeout": true,
	"net.ipv4.tcp_keepalive_intvl": true, "net.ipv4.tcp_keepalive_probes": true,
}

var unsafeSysctls = eachPod(assessment.Metadata{
	ID:          "HX-WL-018",
	Title:       "Unsafe sysctl",
	Severity:    finding.Medium,
	Category:    assessment.CategoryWorkloads,
	Description: "Detects pods that set sysctls outside the Pod Security Standards safe set.",
	Rationale:   "Unsafe sysctls are not namespaced or not isolated between pods; setting them can affect the node and every other workload on it.",
	Remediation: "Remove the sysctl, or run the workload on dedicated nodes where the kubelet explicitly allows it.",
	References:  []finding.Reference{baselines.PSS("Baseline", "Sysctls"), refCISPods},
}, func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string) {
	for i, s := range resource.Maps(pod, "securityContext", "sysctls") {
		name := resource.String(s, "name")
		if !safeSysctls[name] {
			ctx.Report(assessment.Hit{Object: obj, Path: fmt.Sprintf("%s.securityContext.sysctls[%d].name", prefix, i), Observed: name,
				Message: fmt.Sprintf("pod sets unsafe sysctl %s", name)})
		}
	}
})

var restrictedVolumeTypes = map[string]bool{
	"configMap": true, "csi": true, "downwardAPI": true, "emptyDir": true, "ephemeral": true,
	"persistentVolumeClaim": true, "projected": true, "secret": true,
}

var volumeTypes = eachPod(assessment.Metadata{
	ID:          "HX-WL-019",
	Title:       "Non-standard volume type",
	Severity:    finding.Low,
	Category:    assessment.CategoryWorkloads,
	Description: "Detects pods using volume types outside the Pod Security Standards Restricted allow-list (hostPath is reported separately by HX-WL-003).",
	Rationale:   "In-tree network and node volume types bypass PersistentVolume access controls and are a common source of unexpected data or credential exposure.",
	Remediation: "Use a PersistentVolumeClaim (backed by a CSI driver) instead of an in-tree volume source.",
	References:  []finding.Reference{baselines.PSS("Restricted", "Volume Types"), refCISPods},
}, func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string) {
	for i, vol := range resource.Maps(pod, "volumes") {
		for k := range vol {
			if k == "name" || k == "hostPath" || restrictedVolumeTypes[k] {
				continue
			}
			ctx.Report(assessment.Hit{Object: obj, Path: fmt.Sprintf("%s.volumes[%d].%s", prefix, i, k), Observed: k,
				Message: fmt.Sprintf("volume %q uses type %s", resource.String(vol, "name"), k)})
		}
	}
})
