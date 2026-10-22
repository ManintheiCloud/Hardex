package pssdiff

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	hardex "github.com/ManintheiCloud/Hardex"
	"github.com/ManintheiCloud/Hardex/core/finding"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	psaapi "k8s.io/pod-security-admission/api"
	"k8s.io/pod-security-admission/policy"
)

// level is the Pod Security Standards level a Hardex finding belongs to.
// Rules outside the standard (read-only root filesystem, resource limits,
// image references, ...) are not listed and are ignored.
func level(f finding.Finding) (string, bool) {
	switch f.RuleID {
	case "HX-WL-001", "HX-WL-002", "HX-WL-003", "HX-WL-006", "HX-WL-014",
		"HX-WL-015", "HX-WL-016", "HX-WL-018", "HX-WL-020", "HX-WL-021":
		return "baseline", true
	case "HX-WL-004", "HX-WL-005", "HX-WL-007", "HX-WL-019":
		return "restricted", true
	case "HX-WL-008": // an explicit Unconfined profile is Baseline; unset is Restricted
		if f.Observed == "Unconfined" {
			return "baseline", true
		}
		return "restricted", true
	case "HX-WL-017": // an unmasked /proc in a user namespace is Restricted only
		if f.Severity == finding.Low {
			return "restricted", true
		}
		return "baseline", true
	}
	return "", false
}

func TestAgainstPodSecurityAdmission(t *testing.T) {
	seed := time.Now().UnixNano()
	if s := os.Getenv("PSS_DIFF_SEED"); s != "" {
		seed, _ = strconv.ParseInt(s, 10, 64)
	}
	n := 3000
	if s := os.Getenv("PSS_DIFF_PODS"); s != "" {
		n, _ = strconv.Atoi(s)
	}
	t.Logf("seed %d (rerun with PSS_DIFF_SEED=%d), %d pods", seed, seed, n)
	rng := rand.New(rand.NewSource(seed))

	pods := make([]*corev1.Pod, 0, n+len(edgeCases()))
	pods = append(pods, edgeCases()...)
	for i := 0; i < n; i++ {
		p := compliant(fmt.Sprintf("r%05d", i))
		for k := rng.Intn(4); k >= 0; k-- {
			m := mutations[rng.Intn(len(mutations))]
			m.apply(rng, p)
			p.Annotations["pss-diff/mutations"] += m.name + " "
		}
		pods = append(pods, p)
	}

	dir := t.TempDir()
	var docs []string
	for _, p := range pods {
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		docs = append(docs, string(b))
	}
	if err := os.WriteFile(filepath.Join(dir, "pods.yaml"), []byte(strings.Join(docs, "\n---\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	report, _, err := hardex.Scan(hardex.ScanOptions{Paths: []string{dir}, Profile: "restricted", Now: time.Unix(1_800_000_000, 0)})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Complete() {
		t.Fatalf("assessment incomplete: %v", report.Errors)
	}
	found := map[string][]finding.Finding{}
	for _, f := range report.Findings {
		if _, ok := level(f); ok {
			found[f.Resource.Name] = append(found[f.Resource.Name], f)
		}
	}

	eval, err := policy.NewEvaluator(policy.DefaultChecks(), nil)
	if err != nil {
		t.Fatal(err)
	}
	latest := psaapi.LatestVersion()
	mismatches := 0
	for _, p := range pods {
		var hxBaseline, hxRestricted bool
		for _, f := range found[p.Name] {
			l, _ := level(f)
			hxBaseline = hxBaseline || l == "baseline"
			hxRestricted = true
		}
		for _, c := range []struct {
			level psaapi.Level
			hx    bool
		}{{psaapi.LevelBaseline, hxBaseline}, {psaapi.LevelRestricted, hxRestricted}} {
			res := policy.AggregateCheckResults(eval.EvaluatePod(psaapi.LevelVersion{Level: c.level, Version: latest}, &p.ObjectMeta, &p.Spec))
			if res.Allowed == !c.hx {
				continue
			}
			mismatches++
			if mismatches > 25 {
				continue
			}
			spec, _ := json.Marshal(p.Spec)
			var hx []string
			for _, f := range found[p.Name] {
				l, _ := level(f)
				hx = append(hx, fmt.Sprintf("%s(%s,%s) %s=%s", f.RuleID, l, f.Severity, f.Path, f.Observed))
			}
			sort.Strings(hx)
			t.Errorf("pod %s, %s: PodSecurity allowed=%v, Hardex violation=%v\n  mutations: %s\n  PodSecurity: %s\n  Hardex: %s\n  annotations: %v\n  spec: %s",
				p.Name, c.level, res.Allowed, c.hx, p.Annotations["pss-diff/mutations"],
				strings.Join(res.ForbiddenReasons, "; ")+" — "+strings.Join(res.ForbiddenDetails, "; "),
				strings.Join(hx, "; "), p.Annotations, spec)
		}
	}
	if mismatches > 25 {
		t.Errorf("... %d mismatches in all", mismatches)
	}
}

func ptr[T any](v T) *T { return &v }

// compliant returns a pod that meets the Restricted level: every mutation
// starts from here, so a pod differs from compliance in a few controls.
func compliant(name string) *corev1.Pod {
	sc := func() *corev1.SecurityContext {
		return &corev1.SecurityContext{
			AllowPrivilegeEscalation: ptr(false),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
		}
	}
	return &corev1.Pod{
		TypeMeta:   metav1.TypeMeta{APIVersion: "v1", Kind: "Pod"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "pss", Annotations: map[string]string{"pss-diff/mutations": ""}},
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{
				RunAsNonRoot:   ptr(true),
				SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
			},
			InitContainers: []corev1.Container{{Name: "init", Image: "registry.example/init@sha256:" + strings.Repeat("a", 64), SecurityContext: sc()}},
			Containers: []corev1.Container{
				{Name: "app", Image: "registry.example/app@sha256:" + strings.Repeat("b", 64), SecurityContext: sc()},
				{Name: "side", Image: "registry.example/side@sha256:" + strings.Repeat("c", 64), SecurityContext: sc()},
			},
		},
	}
}

// container picks one of the pod's containers, init containers included.
func container(r *rand.Rand, p *corev1.Pod) *corev1.Container {
	all := []*corev1.Container{&p.Spec.InitContainers[0], &p.Spec.Containers[0], &p.Spec.Containers[1]}
	c := all[r.Intn(len(all))]
	if c.SecurityContext == nil {
		c.SecurityContext = &corev1.SecurityContext{}
	}
	return c
}

func pick[T any](r *rand.Rand, xs ...T) T { return xs[r.Intn(len(xs))] }

type mutation struct {
	name  string
	apply func(*rand.Rand, *corev1.Pod)
}

var mutations = []mutation{
	{"hostNamespace", func(r *rand.Rand, p *corev1.Pod) {
		switch r.Intn(3) {
		case 0:
			p.Spec.HostNetwork = true
		case 1:
			p.Spec.HostPID = true
		default:
			p.Spec.HostIPC = true
		}
	}},
	{"privileged", func(r *rand.Rand, p *corev1.Pod) {
		container(r, p).SecurityContext.Privileged = ptr(r.Intn(4) != 0)
	}},
	{"addCapability", func(r *rand.Rand, p *corev1.Pod) {
		c := container(r, p)
		if c.SecurityContext.Capabilities == nil {
			c.SecurityContext.Capabilities = &corev1.Capabilities{}
		}
		c.SecurityContext.Capabilities.Add = append(c.SecurityContext.Capabilities.Add, corev1.Capability(pick(r,
			"NET_BIND_SERVICE", "CHOWN", "KILL", "AUDIT_WRITE", "SETUID", "MKNOD", "NET_RAW", "SYS_CHROOT",
			"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL", "net_bind_service", "CAP_SYS_ADMIN", "CAP_NET_BIND_SERVICE", "BPF")))
	}},
	{"dropCapabilities", func(r *rand.Rand, p *corev1.Pod) {
		c := container(r, p)
		switch r.Intn(4) {
		case 0:
			c.SecurityContext.Capabilities = nil
		case 1:
			c.SecurityContext.Capabilities.Drop = []corev1.Capability{"NET_RAW"}
		case 2:
			c.SecurityContext.Capabilities.Drop = []corev1.Capability{"all"}
		default:
			c.SecurityContext.Capabilities.Drop = []corev1.Capability{"NET_RAW", "ALL"}
		}
	}},
	{"volume", func(r *rand.Rand, p *corev1.Pod) {
		v := corev1.Volume{Name: fmt.Sprintf("v%d", len(p.Spec.Volumes))}
		switch r.Intn(12) {
		case 0:
			v.HostPath = &corev1.HostPathVolumeSource{Path: pick(r, "/", "/var/log", "/etc", "/tmp", "/var/run/docker.sock", "/usr/local/bin")}
		case 1:
			v.EmptyDir = &corev1.EmptyDirVolumeSource{}
		case 2:
			v.ConfigMap = &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "cm"}}
		case 3:
			v.Secret = &corev1.SecretVolumeSource{SecretName: "s"}
		case 4:
			v.Projected = &corev1.ProjectedVolumeSource{}
		case 5:
			v.CSI = &corev1.CSIVolumeSource{Driver: "csi.example"}
		case 6:
			v.PersistentVolumeClaim = &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "c"}
		case 7:
			v.DownwardAPI = &corev1.DownwardAPIVolumeSource{}
		case 8:
			v.NFS = &corev1.NFSVolumeSource{Server: "nfs.example", Path: "/x"}
		case 9:
			v.GitRepo = &corev1.GitRepoVolumeSource{Repository: "https://example.invalid/r"}
		case 10:
			v.Ephemeral = &corev1.EphemeralVolumeSource{}
		default:
			v.Image = &corev1.ImageVolumeSource{Reference: "registry.example/data:1"}
		}
		p.Spec.Volumes = append(p.Spec.Volumes, v)
		if r.Intn(2) == 0 {
			c := container(r, p)
			c.VolumeMounts = append(c.VolumeMounts, corev1.VolumeMount{Name: v.Name, MountPath: "/m/" + v.Name, ReadOnly: r.Intn(2) == 0})
		}
	}},
	{"hostPort", func(r *rand.Rand, p *corev1.Pod) {
		c := container(r, p)
		c.Ports = append(c.Ports, corev1.ContainerPort{ContainerPort: 8080, HostPort: pick[int32](r, 0, 0, 80, 8080)})
	}},
	{"probeHost", func(r *rand.Rand, p *corev1.Pod) {
		c := container(r, p)
		host := pick(r, "", "127.0.0.1", "localhost", "10.0.0.1", "db.example", "::1")
		h := corev1.ProbeHandler{}
		if r.Intn(2) == 0 {
			h.HTTPGet = &corev1.HTTPGetAction{Host: host, Path: "/", Port: intstr.FromInt32(80)}
		} else {
			h.TCPSocket = &corev1.TCPSocketAction{Host: host, Port: intstr.FromInt32(80)}
		}
		switch r.Intn(4) {
		case 0:
			c.LivenessProbe = &corev1.Probe{ProbeHandler: h}
		case 1:
			c.ReadinessProbe = &corev1.Probe{ProbeHandler: h}
		case 2:
			c.StartupProbe = &corev1.Probe{ProbeHandler: h}
		default:
			c.Lifecycle = &corev1.Lifecycle{PostStart: &corev1.LifecycleHandler{HTTPGet: h.HTTPGet, TCPSocket: h.TCPSocket}}
		}
	}},
	{"appArmor", func(r *rand.Rand, p *corev1.Pod) {
		typ := pick(r, corev1.AppArmorProfileTypeRuntimeDefault, corev1.AppArmorProfileTypeLocalhost, corev1.AppArmorProfileTypeUnconfined)
		prof := &corev1.AppArmorProfile{Type: typ}
		if typ == corev1.AppArmorProfileTypeLocalhost {
			prof.LocalhostProfile = ptr("custom")
		}
		switch r.Intn(3) {
		case 0:
			p.Spec.SecurityContext.AppArmorProfile = prof
		case 1:
			container(r, p).SecurityContext.AppArmorProfile = prof
		default:
			c := container(r, p)
			p.Annotations["container.apparmor.security.beta.kubernetes.io/"+c.Name] = pick(r, "runtime/default", "localhost/custom", "unconfined")
		}
	}},
	{"seLinux", func(r *rand.Rand, p *corev1.Pod) {
		o := &corev1.SELinuxOptions{}
		switch r.Intn(4) {
		case 0:
			o.Type = pick(r, "container_t", "container_init_t", "container_kvm_t", "container_engine_t", "spc_t", "unconfined_t", "")
		case 1:
			o.User = "system_u"
		case 2:
			o.Role = "system_r"
		default:
			o.Level = "s0:c123,c456"
		}
		if r.Intn(2) == 0 {
			p.Spec.SecurityContext.SELinuxOptions = o
		} else {
			container(r, p).SecurityContext.SELinuxOptions = o
		}
	}},
	{"procMount", func(r *rand.Rand, p *corev1.Pod) {
		container(r, p).SecurityContext.ProcMount = ptr(pick(r, corev1.UnmaskedProcMount, corev1.DefaultProcMount))
	}},
	{"hostUsers", func(r *rand.Rand, p *corev1.Pod) {
		p.Spec.HostUsers = ptr(r.Intn(3) == 0)
	}},
	{"seccomp", func(r *rand.Rand, p *corev1.Pod) {
		prof := func() *corev1.SeccompProfile {
			switch r.Intn(3) {
			case 0:
				return &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}
			case 1:
				return &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeLocalhost, LocalhostProfile: ptr("p.json")}
			default:
				return &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
			}
		}
		switch r.Intn(3) {
		case 0:
			p.Spec.SecurityContext.SeccompProfile = nil
		case 1:
			p.Spec.SecurityContext.SeccompProfile = prof()
		default:
			container(r, p).SecurityContext.SeccompProfile = prof()
		}
	}},
	{"sysctl", func(r *rand.Rand, p *corev1.Pod) {
		p.Spec.SecurityContext.Sysctls = append(p.Spec.SecurityContext.Sysctls, corev1.Sysctl{Name: pick(r,
			"kernel.shm_rmid_forced", "net.ipv4.ip_local_port_range", "net.ipv4.tcp_syncookies", "net.ipv4.ping_group_range",
			"net.ipv4.ip_unprivileged_port_start", "net.ipv4.ip_local_reserved_ports", "net.ipv4.tcp_keepalive_time",
			"net.ipv4.tcp_fin_timeout", "net.ipv4.tcp_keepalive_intvl", "net.ipv4.tcp_keepalive_probes",
			"net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem", "net.core.somaxconn", "kernel.msgmax", "vm.overcommit_memory",
			"net.ipv4.tcp_slow_start_after_idle", "net.ipv4.tcp_notsent_lowat"), Value: "1"})
	}},
	{"windows", func(r *rand.Rand, p *corev1.Pod) {
		p.Spec.OS = &corev1.PodOS{Name: corev1.Windows}
		if r.Intn(2) == 0 {
			o := &corev1.WindowsSecurityContextOptions{HostProcess: ptr(r.Intn(3) != 0)}
			if r.Intn(2) == 0 {
				p.Spec.SecurityContext.WindowsOptions = o
			} else {
				container(r, p).SecurityContext.WindowsOptions = o
			}
		}
	}},
	{"privilegeEscalation", func(r *rand.Rand, p *corev1.Pod) {
		c := container(r, p)
		if r.Intn(2) == 0 {
			c.SecurityContext.AllowPrivilegeEscalation = nil
		} else {
			c.SecurityContext.AllowPrivilegeEscalation = ptr(true)
		}
	}},
	{"runAsNonRoot", func(r *rand.Rand, p *corev1.Pod) {
		switch r.Intn(4) {
		case 0:
			p.Spec.SecurityContext.RunAsNonRoot = nil
		case 1:
			p.Spec.SecurityContext.RunAsNonRoot = ptr(false)
		case 2:
			container(r, p).SecurityContext.RunAsNonRoot = ptr(false)
		default:
			p.Spec.SecurityContext.RunAsNonRoot = nil
			for _, c := range []*corev1.Container{&p.Spec.InitContainers[0], &p.Spec.Containers[0], &p.Spec.Containers[1]} {
				if c.SecurityContext == nil {
					c.SecurityContext = &corev1.SecurityContext{}
				}
				c.SecurityContext.RunAsNonRoot = ptr(true)
			}
		}
	}},
	{"runAsUser", func(r *rand.Rand, p *corev1.Pod) {
		uid := pick[int64](r, 0, 0, 1000, 65534)
		if r.Intn(2) == 0 {
			p.Spec.SecurityContext.RunAsUser = ptr(uid)
		} else {
			container(r, p).SecurityContext.RunAsUser = ptr(uid)
		}
	}},
	{"ephemeral", func(r *rand.Rand, p *corev1.Pod) {
		sc := &corev1.SecurityContext{}
		if r.Intn(2) == 0 {
			sc.Privileged = ptr(true)
		} else {
			sc.AllowPrivilegeEscalation = ptr(false)
			sc.Capabilities = &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}}
		}
		p.Spec.EphemeralContainers = append(p.Spec.EphemeralContainers, corev1.EphemeralContainer{
			EphemeralContainerCommon: corev1.EphemeralContainerCommon{Name: fmt.Sprintf("debug%d", len(p.Spec.EphemeralContainers)), Image: "registry.example/debug:1", SecurityContext: sc}})
	}},
}

// edgeCases are fixed pods for boundaries random mutation is unlikely to
// combine.
func edgeCases() []*corev1.Pod {
	var out []*corev1.Pod
	add := func(name string, f func(*corev1.Pod)) {
		p := compliant("e-" + name)
		f(p)
		out = append(out, p)
	}
	add("compliant", func(*corev1.Pod) {})
	add("userns-root", func(p *corev1.Pod) {
		p.Spec.HostUsers = ptr(false)
		p.Spec.SecurityContext.RunAsNonRoot = nil
		p.Spec.SecurityContext.RunAsUser = ptr(int64(0))
	})
	add("userns-unmasked", func(p *corev1.Pod) {
		p.Spec.HostUsers = ptr(false)
		p.Spec.Containers[0].SecurityContext.ProcMount = ptr(corev1.UnmaskedProcMount)
	})
	add("windows-minimal", func(p *corev1.Pod) {
		p.Spec.OS = &corev1.PodOS{Name: corev1.Windows}
		p.Spec.SecurityContext.SeccompProfile = nil
		for _, c := range []*corev1.Container{&p.Spec.InitContainers[0], &p.Spec.Containers[0], &p.Spec.Containers[1]} {
			c.SecurityContext = nil
		}
	})
	add("hostnetwork-loopback-probe", func(p *corev1.Pod) {
		p.Spec.HostNetwork = true
		p.Spec.Containers[0].LivenessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Host: "127.0.0.1", Port: intstr.FromInt32(80)}}}
	})
	add("container-seccomp-only", func(p *corev1.Pod) {
		p.Spec.SecurityContext.SeccompProfile = nil
		for _, c := range []*corev1.Container{&p.Spec.InitContainers[0], &p.Spec.Containers[0], &p.Spec.Containers[1]} {
			c.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
		}
	})
	return out
}
