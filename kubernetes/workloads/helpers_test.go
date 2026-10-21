package workloads

import "testing"

func TestImageRef(t *testing.T) {
	cases := []struct{ image, tag, digest string }{
		{"nginx", "", ""},
		{"nginx:1.27", "1.27", ""},
		{"localhost:5000/app", "", ""},
		{"localhost:5000/app:v2", "v2", ""},
		{"ghcr.io/x/app@sha256:abc", "", "sha256:abc"},
		{"ghcr.io/x/app:1.0@sha256:abc", "1.0", "sha256:abc"},
	}
	for _, c := range cases {
		tag, digest := imageRef(c.image)
		if tag != c.tag || digest != c.digest {
			t.Errorf("imageRef(%q) = %q, %q; want %q, %q", c.image, tag, digest, c.tag, c.digest)
		}
	}
}

func TestCriticalHostPaths(t *testing.T) {
	for _, p := range []string{"/", "/etc", "/etc/kubernetes/pki", "/var/run/docker.sock", "/run/containerd/containerd.sock", "/var/lib/kubelet/pods", "/proc/",
		// Run or served as root by the node: CNI plugins, FlexVolume
		// drivers, system binaries, node logs (symlink attack via the
		// kubelet's log endpoint).
		"/opt/cni/bin", "/opt", "/usr/libexec/kubernetes/kubelet-plugins/volume/exec", "/usr/local/bin", "/lib/modules", "/var/log", "/var/log/pods"} {
		if !isCriticalHostPath(p) {
			t.Errorf("%s should be critical", p)
		}
	}
	for _, p := range []string{"/data/cache", "/opt/agent", "/srv", "/var/lib/cni", "/home/app", "/usrdata", "/var/logs-archive"} {
		if isCriticalHostPath(p) {
			t.Errorf("%s should not be critical", p)
		}
	}
}
