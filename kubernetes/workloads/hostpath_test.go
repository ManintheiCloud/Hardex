package workloads

import (
	"strings"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/resource"
)

func podSpec(t *testing.T, y string) map[string]any {
	t.Helper()
	inv, err := resource.Load([]string{"-"}, strings.NewReader("apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec: "+y+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := resource.PodSpec(inv.Objects[0])
	return spec
}

func TestHostPathCritical(t *testing.T) {
	mount := func(path, mountOpts, sc string) string {
		return `{volumes: [{name: v, hostPath: {path: ` + path + `}}], containers: [{name: c, image: x` + sc + `, volumeMounts: [{name: v, mountPath: /m` + mountOpts + `}]}]}`
	}
	cases := map[string]struct {
		spec string
		want bool
	}{
		"writable manifests dir":        {mount("/etc/kubernetes/manifests", "", ""), true},
		"read-only manifests dir":       {mount("/etc/kubernetes/manifests", ", readOnly: true", ""), false},
		"read-only kubelet config file": {mount("/var/lib/kubelet/config.yaml", ", readOnly: true", ""), false},
		"read-only but privileged":      {mount("/etc/kubernetes/manifests", ", readOnly: true", ", securityContext: {privileged: true}"), true},
		"read-only but CAP_SYS_ADMIN":   {mount("/etc/kubernetes/manifests", ", readOnly: true", ", securityContext: {capabilities: {add: [CAP_SYS_ADMIN]}}"), true},
		"read-only runtime socket":      {mount("/run/containerd/containerd.sock", ", readOnly: true", ""), true},
		"read-only /var/run":            {mount("/var/run", ", readOnly: true", ""), true},
		"read-only PKI":                 {mount("/etc/kubernetes/pki", ", readOnly: true", ""), true},
		"read-only /etc (contains PKI)": {mount("/etc", ", readOnly: true", ""), true},
		"read-only kubelet dir (pods)":  {mount("/var/lib/kubelet", ", readOnly: true", ""), true},
		"read-only node root":           {mount("/", ", readOnly: true", ""), true},
		"read-only admin kubeconfig":    {mount("/etc/kubernetes/admin.conf", ", readOnly: true", ""), true},
		"unmounted sensitive volume":    {`{volumes: [{name: v, hostPath: {path: /etc/kubernetes/manifests}}], containers: [{name: c, image: x}]}`, false},
		"non-sensitive writable path":   {mount("/data/cache", "", ""), false},
		"writable CNI plugin dir":       {mount("/opt/cni/bin", "", ""), true},
		"read-only CNI plugin dir":      {mount("/opt/cni/bin", ", readOnly: true", ""), false},
		"writable node logs":            {mount("/var/log", "", ""), true},
		"read-only node logs":           {mount("/var/log", ", readOnly: true", ""), false},
		"init container writes":         {`{volumes: [{name: v, hostPath: {path: /etc/kubernetes/manifests}}], initContainers: [{name: i, image: x, volumeMounts: [{name: v, mountPath: /m}]}], containers: [{name: c, image: x, volumeMounts: [{name: v, mountPath: /m, readOnly: true}]}]}`, true},
	}
	for name, c := range cases {
		pod := podSpec(t, c.spec)
		got, _ := hostPathCritical(pod, resource.Maps(pod, "volumes")[0])
		if got != c.want {
			t.Errorf("%s: got %v, want %v", name, got, c.want)
		}
	}
	if got, _ := hostPathCritical(podSpec(t, `{volumes: [{name: e, emptyDir: {}}], containers: [{name: c, image: x}]}`), map[string]any{"name": "e", "emptyDir": map[string]any{}}); got {
		t.Error("non-hostPath volume reported")
	}
}
