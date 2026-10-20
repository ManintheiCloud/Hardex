package workloads

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ManintheiCloud/Hardex/baselines"
	"github.com/ManintheiCloud/Hardex/core/assessment"
	"github.com/ManintheiCloud/Hardex/core/finding"
	"github.com/ManintheiCloud/Hardex/core/resource"
)

var (
	refNSAPod   = baselines.NSA("Kubernetes Pod security")
	refCISPods  = baselines.CIS("5.2", "Pod Security Standards")
	sevCritical = assessment.SeverityOverride(finding.Critical)
	sevHigh     = assessment.SeverityOverride(finding.High)
	sevLow      = assessment.SeverityOverride(finding.Low)
	sevInfo     = assessment.SeverityOverride(finding.Info)
)

var privileged = eachContainer(assessment.Metadata{
	ID:          "HX-WL-001",
	Title:       "Privileged container",
	Severity:    finding.Critical,
	Category:    assessment.CategoryWorkloads,
	Description: "Detects containers with securityContext.privileged set to true.",
	Rationale:   "A privileged container has every capability and full access to host devices. Escaping to the node is trivial, and from the node an attacker can usually reach every other workload and the kubelet's credentials.",
	Remediation: "Remove securityContext.privileged. If specific kernel access is needed, grant the single required capability instead and document why.",
	References:  []finding.Reference{baselines.PSS("Baseline", "Privileged Containers"), refNSAPod, refCISPods},
}, func(ctx *assessment.Context, obj *resource.Object, _ map[string]any, prefix string, c resource.Container) {
	if v, _ := resource.Bool(c.Spec, "securityContext", "privileged"); v {
		ctx.Report(assessment.Hit{Object: obj, Container: c.Name,
			Path: c.Path(prefix) + ".securityContext.privileged", Observed: "true",
			Message: fmt.Sprintf("container %q runs privileged", c.Name)})
	}
})

var hostNamespaces = eachPod(assessment.Metadata{
	ID:          "HX-WL-002",
	Title:       "Host namespace sharing",
	Severity:    finding.High,
	Category:    assessment.CategoryWorkloads,
	Description: "Detects pods that share the node's network, PID or IPC namespace.",
	Rationale:   "hostNetwork exposes node-local services (including the kubelet and cloud metadata endpoints) and lets the pod sniff or spoof node traffic. hostPID allows inspecting and signalling every process on the node. hostIPC exposes shared memory of other workloads.",
	Remediation: "Remove hostNetwork, hostPID and hostIPC. Expose services through a Service instead of the node network.",
	References:  []finding.Reference{baselines.PSS("Baseline", "Host Namespaces"), refNSAPod, refCISPods},
}, func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string) {
	for _, field := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		if v, _ := resource.Bool(pod, field); v {
			ctx.Report(assessment.Hit{Object: obj, Path: prefix + "." + field, Observed: "true",
				Message: fmt.Sprintf("pod shares the node's %s namespace", strings.TrimPrefix(field, "host"))})
		}
	}
})

// Host paths whose exposure gives near-immediate node or cluster compromise.
// Writing to any of them (a static pod manifest, the kubelet's state, a
// binary under /usr) takes over the node.
var criticalHostPaths = []string{
	"/", "/etc", "/root", "/proc", "/sys", "/dev", "/boot", "/usr", "/bin", "/sbin", "/lib",
	"/var/run", "/run", "/var/lib/kubelet", "/var/lib/docker", "/var/lib/containerd", "/var/lib/etcd",
	"/var/run/docker.sock", "/run/containerd/containerd.sock", "/var/run/crio/crio.sock",
	"/etc/kubernetes",
}

// Host paths where even *reading* compromises the node or cluster: keys,
// kubeconfigs, other pods' Secret volumes, etcd data. A read-only mount of a
// path that contains, or is inside, one of these is still critical.
var readSensitivePaths = []string{
	"/etc/kubernetes/pki", "/etc/kubernetes/admin.conf", "/etc/kubernetes/super-admin.conf",
	"/etc/kubernetes/kubelet.conf", "/etc/kubernetes/controller-manager.conf", "/etc/kubernetes/scheduler.conf",
	"/etc/kubernetes/bootstrap-kubelet.conf", "/var/lib/kubelet/pki", "/var/lib/kubelet/pods",
	"/var/lib/kubelet/kubeconfig", "/var/lib/etcd", "/etc/shadow", "/etc/ssh", "/root", "/home",
	"/proc", "/sys", "/dev", "/var/lib/docker", "/var/lib/containerd",
}

// Runtime sockets and the directories that hold them: a read-only mount
// does not stop a process from connecting to a socket.
func isSocketPath(p string) bool {
	return strings.HasSuffix(p, ".sock") || p == "/var/run" || p == "/run" ||
		strings.HasPrefix(p, "/var/run/") || strings.HasPrefix(p, "/run/")
}

func cleanPath(p string) string { return "/" + strings.Trim(p, "/") }

// isReadSensitive reports whether p is, contains, or lies inside a path
// whose contents are credentials.
func isReadSensitive(p string) bool {
	p = cleanPath(p)
	for _, s := range readSensitivePaths {
		if p == s || p == "/" || strings.HasPrefix(s, p+"/") || strings.HasPrefix(p, s+"/") {
			return true
		}
	}
	return false
}

// hostPathCritical reports whether a hostPath volume gives node or cluster
// compromise in this pod: always for sockets and credential paths, and for
// other sensitive paths only if some container can write to it — mounts it
// without readOnly, or could remount it (privileged or CAP_SYS_ADMIN).
func hostPathCritical(pod map[string]any, vol map[string]any) (bool, string) {
	raw := resource.String(vol, "hostPath", "path")
	if raw == "" {
		return false, ""
	}
	path := cleanPath(raw)
	if !isCriticalHostPath(path) {
		return false, ""
	}
	if isSocketPath(path) {
		return true, "sensitive node path"
	}
	if isReadSensitive(path) {
		return true, "sensitive node path: readable contents expose credentials or data"
	}
	name := resource.String(vol, "name")
	for _, c := range resource.Containers(pod) {
		canRemount := false
		if v, _ := resource.Bool(c.Spec, "securityContext", "privileged"); v {
			canRemount = true
		}
		for _, cp := range resource.Strings(c.Spec, "securityContext", "capabilities", "add") {
			if n := normalizeCap(cp); n == "SYS_ADMIN" || n == "ALL" {
				canRemount = true
			}
		}
		for _, m := range resource.Maps(c.Spec, "volumeMounts") {
			if resource.String(m, "name") != name {
				continue
			}
			if ro, _ := resource.Bool(m, "readOnly"); !ro || canRemount {
				return true, "sensitive node path, writable"
			}
		}
	}
	return false, "sensitive node path, mounted read-only"
}

var hostPathVolumes = eachPod(assessment.Metadata{
	ID:          "HX-WL-003",
	Title:       "HostPath volume",
	Severity:    finding.High,
	Category:    assessment.CategoryWorkloads,
	Description: "Detects pods that mount directories from the node's filesystem. Mounts of sensitive paths are raised to critical when they give node or cluster compromise: runtime sockets and paths holding credentials (keys, kubeconfigs, other pods' volumes, etcd data) even read-only, and other sensitive paths (root, /etc, kubelet state, system binaries) when a container can write to them.",
	Rationale:   "HostPath mounts bypass container filesystem isolation. Writable mounts of sensitive paths allow node takeover; a mounted container runtime socket is equivalent to root on the node.",
	Remediation: "Replace hostPath with emptyDir, a ConfigMap/Secret, or a PersistentVolumeClaim. If node access is unavoidable (e.g. a log collector), mount the narrowest path read-only and isolate the workload in a dedicated namespace.",
	References:  []finding.Reference{baselines.PSS("Baseline", "HostPath Volumes"), refNSAPod, refCISPods},
}, func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string) {
	for i, vol := range resource.Maps(pod, "volumes") {
		hp := resource.Map(vol, "hostPath")
		if hp == nil {
			continue
		}
		path := resource.String(hp, "path")
		hit := assessment.Hit{Object: obj, Path: fmt.Sprintf("%s.volumes[%d].hostPath.path", prefix, i), Observed: path,
			Message: fmt.Sprintf("volume %q mounts host path %s", resource.String(vol, "name"), path)}
		if critical, why := hostPathCritical(pod, vol); critical {
			hit.Severity = sevCritical
			hit.Message += " (" + why + ")"
		} else if why != "" {
			hit.Message += " (" + why + ")"
		}
		ctx.Report(hit)
	}
})

func isCriticalHostPath(p string) bool {
	p = cleanPath(p)
	for _, c := range criticalHostPaths {
		if p == c {
			return true
		}
	}
	// Any socket (container runtimes, systemd), anything holding kubelet or
	// control-plane credentials, and anything under /etc.
	return strings.HasSuffix(p, ".sock") ||
		strings.HasPrefix(p, "/var/lib/kubelet/") ||
		strings.HasPrefix(p, "/etc/")
}

var privilegeEscalation = eachContainer(assessment.Metadata{
	ID:          "HX-WL-004",
	Title:       "Privilege escalation allowed",
	Severity:    finding.Medium,
	Category:    assessment.CategoryWorkloads,
	Description: "Detects Linux containers that do not set securityContext.allowPrivilegeEscalation to false.",
	Rationale:   "When allowed (the default), setuid binaries and file capabilities inside the image can raise a process's privileges, turning a low-privilege foothold into root inside the container.",
	Remediation: "Set securityContext.allowPrivilegeEscalation: false on every container.",
	References:  []finding.Reference{baselines.PSS("Restricted", "Privilege Escalation"), refNSAPod, refCISPods},
}, func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string, c resource.Container) {
	if isWindows(pod) {
		return
	}
	v, set := resource.Bool(c.Spec, "securityContext", "allowPrivilegeEscalation")
	if set && !v {
		return
	}
	observed := "<unset> (defaults to true)"
	if set {
		observed = "true"
	}
	ctx.Report(assessment.Hit{Object: obj, Container: c.Name,
		Path: c.Path(prefix) + ".securityContext.allowPrivilegeEscalation", Observed: observed,
		Message: fmt.Sprintf("container %q may gain more privileges than its parent process", c.Name)})
})

var runAsNonRoot = eachContainer(assessment.Metadata{
	ID:          "HX-WL-005",
	Title:       "Container may run as root",
	Severity:    finding.Medium,
	Category:    assessment.CategoryWorkloads,
	Description: "Detects containers that are not required to run as a non-root user (runAsNonRoot is not true at container or pod level), and containers explicitly configured to run as UID 0. Pods with their own user namespace (hostUsers: false) are exempt, as in the Pod Security Standards since Kubernetes 1.35.",
	Rationale:   "Root inside a container is root on the node's kernel interfaces. Combined with any container escape, misconfigured mount or kernel vulnerability, it maximises the attacker's starting privilege.",
	Remediation: "Set securityContext.runAsNonRoot: true (pod or container level) and a non-zero runAsUser, and build images that run as a non-root USER.",
	References:  []finding.Reference{baselines.PSS("Restricted", "Running as Non-root"), baselines.PSS("Restricted", "Running as Non-root user"), refNSAPod, refCISPods},
	Limitations: "If runAsNonRoot is unset, the effective user depends on the image's USER directive, which Hardex does not inspect.",
}, func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string, c resource.Container) {
	if isWindows(pod) || userNamespaced(pod) {
		return
	}
	uid, uidPath, uidSet := effective(pod, prefix, c, "runAsUser")
	if n, ok := uid.(float64); uidSet && ok && n == 0 {
		ctx.Report(assessment.Hit{Object: obj, Container: c.Name, Path: uidPath, Observed: "0", Severity: sevHigh,
			Message: fmt.Sprintf("container %q is explicitly configured to run as root (UID 0)", c.Name)})
		return
	}
	nonRoot, path, _ := effective(pod, prefix, c, "runAsNonRoot")
	if b, ok := nonRoot.(bool); ok && b {
		return
	}
	hit := assessment.Hit{Object: obj, Container: c.Name, Path: path, Observed: show(nonRoot),
		Message: fmt.Sprintf("container %q is not required to run as non-root; the image's USER decides", c.Name)}
	if n, ok := uid.(float64); uidSet && ok && n > 0 {
		hit.Severity = sevLow
		hit.Message = fmt.Sprintf("container %q sets runAsUser %v but not runAsNonRoot; set both so the kubelet enforces it", c.Name, n)
	}
	ctx.Report(hit)
})

// PSS Baseline permits these capabilities to be added; anything else is a
// Baseline violation.
var baselineAllowedCaps = map[string]bool{
	"AUDIT_WRITE": true, "CHOWN": true, "DAC_OVERRIDE": true, "FOWNER": true, "FSETID": true,
	"KILL": true, "MKNOD": true, "NET_BIND_SERVICE": true, "SETFCAP": true, "SETGID": true,
	"SETPCAP": true, "SETUID": true, "SYS_CHROOT": true,
}

// Capabilities that, alone, commonly lead to node compromise.
var criticalCaps = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "SYS_MODULE": true, "SYS_PTRACE": true, "SYS_RAWIO": true,
	"BPF": true, "DAC_READ_SEARCH": true, "SYS_BOOT": true,
}

var dangerousCapabilities = eachContainer(assessment.Metadata{
	ID:          "HX-WL-006",
	Title:       "Dangerous Linux capability added",
	Severity:    finding.High,
	Category:    assessment.CategoryWorkloads,
	Description: "Detects containers that add Linux capabilities outside the Pod Security Standards Baseline allow-list. Capabilities that commonly enable escape (SYS_ADMIN, SYS_MODULE, SYS_PTRACE, BPF, ALL, ...) are critical.",
	Rationale:   "Capabilities split root's power into pieces; several of those pieces are each sufficient to escape the container or tamper with the node.",
	Remediation: "Remove the capability from securityContext.capabilities.add. Prefer drop: [ALL] and add back only NET_BIND_SERVICE if a low port is required.",
	References:  []finding.Reference{baselines.PSS("Baseline", "Capabilities"), refNSAPod, refCISPods},
}, func(ctx *assessment.Context, obj *resource.Object, _ map[string]any, prefix string, c resource.Container) {
	for i, raw := range resource.Strings(c.Spec, "securityContext", "capabilities", "add") {
		capName := normalizeCap(raw)
		if baselineAllowedCaps[capName] {
			continue
		}
		hit := assessment.Hit{Object: obj, Container: c.Name,
			Path:     fmt.Sprintf("%s.securityContext.capabilities.add[%d]", c.Path(prefix), i),
			Observed: raw, Message: fmt.Sprintf("container %q adds capability %s", c.Name, capName)}
		if criticalCaps[capName] {
			hit.Severity = sevCritical
		}
		ctx.Report(hit)
	}
})

var minimalCapabilities = eachContainer(assessment.Metadata{
	ID:          "HX-WL-007",
	Title:       "Capabilities not reduced to minimum",
	Severity:    finding.Low,
	Category:    assessment.CategoryWorkloads,
	Description: "Detects Linux containers that do not drop ALL capabilities, or that add any capability other than NET_BIND_SERVICE.",
	Rationale:   "Container runtimes grant a default capability set that most applications never use. Dropping them removes kernel attack surface at no cost to the workload.",
	Remediation: "Set securityContext.capabilities.drop: [\"ALL\"] and, only if needed, add: [\"NET_BIND_SERVICE\"].",
	References:  []finding.Reference{baselines.PSS("Restricted", "Capabilities"), refNSAPod, refCISPods},
}, func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string, c resource.Container) {
	if isWindows(pod) {
		return
	}
	capsPath := c.Path(prefix) + ".securityContext.capabilities"
	dropsAll := false
	for _, d := range resource.Strings(c.Spec, "securityContext", "capabilities", "drop") {
		if normalizeCap(d) == "ALL" {
			dropsAll = true
		}
	}
	if !dropsAll {
		ctx.Report(assessment.Hit{Object: obj, Container: c.Name, Path: capsPath + ".drop",
			Observed: show(resource.Strings(c.Spec, "securityContext", "capabilities", "drop")),
			Message:  fmt.Sprintf("container %q does not drop ALL capabilities", c.Name)})
	}
	var extra []string
	for _, a := range resource.Strings(c.Spec, "securityContext", "capabilities", "add") {
		n := normalizeCap(a)
		// Non-baseline capabilities are already reported by HX-WL-006.
		if n != "NET_BIND_SERVICE" && baselineAllowedCaps[n] {
			extra = append(extra, n)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		ctx.Report(assessment.Hit{Object: obj, Container: c.Name, Path: capsPath + ".add",
			Observed: strings.Join(extra, ","),
			Message:  fmt.Sprintf("container %q adds capabilities beyond NET_BIND_SERVICE: %s", c.Name, strings.Join(extra, ", "))})
	}
})

var readOnlyRootFS = eachContainer(assessment.Metadata{
	ID:          "HX-WL-009",
	Title:       "Writable root filesystem",
	Severity:    finding.Low,
	Category:    assessment.CategoryWorkloads,
	Description: "Detects containers that do not set securityContext.readOnlyRootFilesystem to true.",
	Rationale:   "A writable root filesystem lets an attacker who gains code execution drop tools, modify binaries and persist changes for the life of the container.",
	Remediation: "Set securityContext.readOnlyRootFilesystem: true and mount an emptyDir for any path the application must write (e.g. /tmp).",
	References:  []finding.Reference{refNSAPod},
}, func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string, c resource.Container) {
	if isWindows(pod) {
		return
	}
	if v, _ := resource.Bool(c.Spec, "securityContext", "readOnlyRootFilesystem"); !v {
		ctx.Report(assessment.Hit{Object: obj, Container: c.Name,
			Path:     c.Path(prefix) + ".securityContext.readOnlyRootFilesystem",
			Observed: show(resource.Map(c.Spec, "securityContext")["readOnlyRootFilesystem"]),
			Message:  fmt.Sprintf("container %q has a writable root filesystem", c.Name)})
	}
})

var hostPorts = eachContainer(assessment.Metadata{
	ID:          "HX-WL-014",
	Title:       "Host port bound",
	Severity:    finding.Medium,
	Category:    assessment.CategoryWorkloads,
	Description: "Detects containers that bind a port directly on the node with hostPort.",
	Rationale:   "hostPort exposes the container on the node's address, bypassing Service-level controls and NetworkPolicy assumptions, and pins the workload to nodes where the port is free.",
	Remediation: "Remove hostPort and expose the workload through a Service (ClusterIP, or an Ingress/LoadBalancer with restricted sources).",
	References:  []finding.Reference{baselines.PSS("Baseline", "Host Ports"), refNSAPod, refCISPods},
}, func(ctx *assessment.Context, obj *resource.Object, _ map[string]any, prefix string, c resource.Container) {
	for i, p := range resource.Maps(c.Spec, "ports") {
		if n, ok := resource.Number(p, "hostPort"); ok && n > 0 {
			ctx.Report(assessment.Hit{Object: obj, Container: c.Name,
				Path: fmt.Sprintf("%s.ports[%d].hostPort", c.Path(prefix), i), Observed: fmt.Sprint(n),
				Message: fmt.Sprintf("container %q binds host port %v", c.Name, n)})
		}
	}
})

var hostProcess = eachContainer(assessment.Metadata{
	ID:          "HX-WL-020",
	Title:       "Windows HostProcess container",
	Severity:    finding.Critical,
	Category:    assessment.CategoryWorkloads,
	Description: "Detects Windows containers that run as HostProcess, at pod or container level.",
	Rationale:   "A HostProcess container runs directly on the Windows node with host-level access; it is the Windows equivalent of a privileged container.",
	Remediation: "Remove securityContext.windowsOptions.hostProcess.",
	References:  []finding.Reference{baselines.PSS("Baseline", "HostProcess"), refCISPods},
}, func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string, c resource.Container) {
	v, path, _ := effective(pod, prefix, c, "windowsOptions", "hostProcess")
	if b, ok := v.(bool); ok && b {
		ctx.Report(assessment.Hit{Object: obj, Container: c.Name, Path: path, Observed: "true",
			Message: fmt.Sprintf("container %q runs as a Windows HostProcess", c.Name)})
	}
})
