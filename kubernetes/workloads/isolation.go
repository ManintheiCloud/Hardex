package workloads

import (
	"fmt"
	"net"
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
	Description: "Detects containers with securityContext.procMount set to Unmasked. In a pod with its own user namespace (hostUsers: false), which the Pod Security Standards Baseline allows since Kubernetes 1.35 but Restricted does not, it is reported as low.",
	Rationale:   "The default /proc mount masks paths that leak host information or allow kernel tuning. Unmasking them exposes the host to the container. In a user namespace the container's root is unprivileged on the node, which is why Baseline allows it there.",
	Remediation: "Remove procMount or set it to Default.",
	References:  []finding.Reference{baselines.PSS("Baseline", "/proc Mount Type"), refCISPods},
}, func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string, c resource.Container) {
	v := resource.String(c.Spec, "securityContext", "procMount")
	if v == "" || v == "Default" {
		return
	}
	hit := assessment.Hit{Object: obj, Container: c.Name, Path: c.Path(prefix) + ".securityContext.procMount", Observed: v,
		Message: fmt.Sprintf("container %q uses procMount %s", c.Name, v)}
	if userNamespaced(pod) {
		hit.Severity = sevLow
		hit.Message += " in a user namespace (hostUsers: false); Baseline allows this, Restricted does not"
	}
	ctx.Report(hit)
})

// The "safe" sysctl set from the Pod Security Standards, as of Kubernetes
// 1.37 (pod-security-admission policy/check_sysctls.go). The value is the
// first Kubernetes minor version whose PodSecurity admission allows it.
var safeSysctls = map[string]int{
	"kernel.shm_rmid_forced": 0, "net.ipv4.ip_local_port_range": 0,
	"net.ipv4.ip_unprivileged_port_start": 0, "net.ipv4.tcp_syncookies": 0,
	"net.ipv4.ping_group_range": 0, "net.ipv4.ip_local_reserved_ports": 27,
	"net.ipv4.tcp_keepalive_time": 29, "net.ipv4.tcp_fin_timeout": 29,
	"net.ipv4.tcp_keepalive_intvl": 29, "net.ipv4.tcp_keepalive_probes": 29,
	"net.ipv4.tcp_rmem": 32, "net.ipv4.tcp_wmem": 32,
	"net.ipv4.tcp_slow_start_after_idle": 37, "net.ipv4.tcp_notsent_lowat": 37,
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
	Limitations: "The safe set is the one in Kubernetes 1.37. net.ipv4.tcp_slow_start_after_idle and net.ipv4.tcp_notsent_lowat were added in 1.37; PodSecurity admission on older clusters still rejects them, though they are namespaced and safe.",
}, func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string) {
	for i, s := range resource.Maps(pod, "securityContext", "sysctls") {
		name := resource.String(s, "name")
		if _, safe := safeSysctls[name]; !safe {
			ctx.Report(assessment.Hit{Object: obj, Path: fmt.Sprintf("%s.securityContext.sysctls[%d].name", prefix, i), Observed: name,
				Message: fmt.Sprintf("pod sets unsafe sysctl %s", name)})
		}
	}
})

var restrictedVolumeTypes = map[string]bool{
	"configMap": true, "csi": true, "downwardAPI": true, "emptyDir": true, "ephemeral": true,
	"image": true, "persistentVolumeClaim": true, "projected": true, "secret": true,
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

// probeHandlers are the container fields whose httpGet or tcpSocket handler
// the kubelet runs from the node; their host field is restricted by the Pod
// Security Standards Baseline since Kubernetes 1.34.
var probeHandlers = [][]string{
	{"livenessProbe"}, {"readinessProbe"}, {"startupProbe"},
	{"lifecycle", "postStart"}, {"lifecycle", "preStop"},
}

var probeHost = eachContainer(assessment.Metadata{
	ID:          "HX-WL-021",
	Title:       "Probe or lifecycle hook targets another host",
	Severity:    finding.Medium,
	Category:    assessment.CategoryWorkloads,
	Description: "Detects httpGet and tcpSocket probes and lifecycle hooks that set host, which the Pod Security Standards Baseline forbids since Kubernetes 1.34.",
	Rationale:   "The kubelet runs these handlers from the node's network namespace. With host set, anyone who can create a pod can make the kubelet connect to any address it can reach: services bound to the node's loopback, the cloud metadata endpoint, or other internal hosts. Probe failures are recorded in events, so responses can leak back.",
	Remediation: "Remove the host field so the handler targets the pod's own IP. To check an external dependency, do it from inside the container (an exec probe) or not in a probe at all.",
	References:  []finding.Reference{baselines.PSS("Baseline", "Host Probes / Lifecycle Hooks"), refNSAPod},
	Limitations: "A loopback host in a hostNetwork pod is reported as low: the kubelet then reaches only the pod's own network namespace, which is the node's. Baseline forbids it regardless.",
}, func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string, c resource.Container) {
	hostNet, _ := resource.Lookup(pod, "hostNetwork")
	for _, h := range probeHandlers {
		for _, kind := range []string{"httpGet", "tcpSocket"} {
			field := append(append([]string{}, h...), kind, "host")
			host := resource.String(c.Spec, field...)
			if host == "" {
				continue
			}
			hit := assessment.Hit{Object: obj, Container: c.Name, Path: c.Path(prefix) + "." + strings.Join(field, "."), Observed: host,
				Message: fmt.Sprintf("container %q %s %s targets host %s", c.Name, strings.Join(h, "."), kind, host)}
			if b, _ := hostNet.(bool); b && loopback(host) {
				hit.Severity = sevLow
				hit.Message += " (the pod uses the host network, so this is its own loopback)"
			}
			ctx.Report(hit)
		}
	}
})

func loopback(host string) bool {
	h := strings.ToLower(strings.Trim(host, "[]"))
	if h == "localhost" || h == "::1" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// systemHostAccess lists, as information, workloads in kube-system with host
// access. The other workload rules skip kube-system (its platform
// components need host access by design) unless --include-system is given;
// without this inventory a workload placed there, a common way to keep a
// foothold in a cluster, would be invisible. Monitoring always reports new
// entries.
var systemHostAccess = assessment.ObjectRule{
	Meta: assessment.Metadata{
		ID:           "HX-WL-022",
		Title:        "Host-access workload in kube-system",
		Severity:     finding.Info,
		Category:     assessment.CategoryWorkloads,
		Description:  "Lists workloads in kube-system that are privileged, share host namespaces, mount host paths or add capabilities. Information only: kube-system holds platform components that need this. Reported only when the other workload rules skip kube-system (without --include-system). hardex monitor sends an event for every new entry, whatever --notify-min is.",
		Rationale:    "kube-system is excluded from the workload rules to keep platform components out of reports, which also hides anything else placed there; a privileged DaemonSet in kube-system is a well-known way to keep access to a cluster. Listing every host-access workload there keeps such additions visible, and drift monitoring flags them when they appear.",
		Remediation:  "Confirm each listed workload is a platform component you run (network plugin, kube-proxy, CSI driver, control plane). Record the reviewed list as a baseline (hardex monitor --baseline) so a new entry stands out; assess kube-system in full with --include-system.",
		References:   []finding.Reference{refNSAPod},
		NotifyAlways: true,
		Inventory:    true,
	},
	Kinds: resource.WorkloadKinds(),
	Check: func(ctx *assessment.Context, obj *resource.Object) {
		if ctx.Options.IncludeSystem || obj.EffectiveNamespace() != "kube-system" {
			return
		}
		pod, prefix := resource.PodSpec(obj)
		if pod == nil {
			return
		}
		var access []string
		for _, ns := range []string{"hostNetwork", "hostPID", "hostIPC"} {
			if v, _ := resource.Bool(pod, ns); v {
				access = append(access, ns)
			}
		}
		for _, v := range resource.Maps(pod, "volumes") {
			if p := resource.String(v, "hostPath", "path"); p != "" {
				access = append(access, "hostPath "+p)
			}
		}
		for _, c := range resource.Containers(pod) {
			if v, _ := resource.Bool(c.Spec, "securityContext", "privileged"); v {
				access = append(access, "privileged "+c.Name)
			}
			for _, cp := range resource.Strings(c.Spec, "securityContext", "capabilities", "add") {
				access = append(access, "capability "+normalizeCap(cp)+" "+c.Name)
			}
		}
		if len(access) == 0 {
			return
		}
		ctx.Report(assessment.Hit{Object: obj, Path: prefix, Observed: strings.Join(access, ", "),
			Message: "kube-system workload with host access: " + strings.Join(access, ", ")})
	},
}
