package node

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/resource"
)

func write(t *testing.T, root, path, content string) {
	t.Helper()
	p := filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func kubelet(t *testing.T, res *Result) map[string]any {
	t.Helper()
	objs := res.Inventory.OfKind("KubeletConfiguration")
	if len(objs) != 1 {
		t.Fatalf("got %d kubelet configurations", len(objs))
	}
	return objs[0].Raw
}

func TestFlagsOverrideConfig(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/var/lib/kubelet/config.yaml", "apiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\nauthentication: {anonymous: {enabled: false}}\nreadOnlyPort: 0\n")
	write(t, root, "/var/lib/kubelet/kubeadm-flags.env", `KUBELET_KUBEADM_ARGS="--anonymous-auth=true --read-only-port=10255 --authorization-mode=AlwaysAllow --protect-kernel-defaults"`+"\n")
	write(t, root, "/etc/kubernetes/manifests/kube-apiserver.yaml", "apiVersion: v1\nkind: Pod\nmetadata: {name: kube-apiserver, namespace: kube-system}\nspec: {containers: [{name: kube-apiserver, image: x, command: [kube-apiserver]}]}\n")
	write(t, root, "/etc/kubernetes/manifests/README", "not a manifest")
	res, err := Collect(Options{Root: root, NodeName: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	raw := kubelet(t, res)
	if v, _ := resource.Bool(raw, "authentication", "anonymous", "enabled"); !v {
		t.Error("--anonymous-auth=true not applied")
	}
	if n, _ := resource.Number(raw, "readOnlyPort"); n != 10255 {
		t.Errorf("readOnlyPort = %v", n)
	}
	if resource.String(raw, "authorization", "mode") != "AlwaysAllow" {
		t.Error("authorization mode not applied")
	}
	if v, _ := resource.Bool(raw, "protectKernelDefaults"); !v {
		t.Error("bare boolean flag not applied")
	}
	if res.Inventory.OfKind("KubeletConfiguration")[0].Name != "n1" {
		t.Error("node name not applied")
	}
	if len(res.Inventory.OfKind("Pod")) != 1 {
		t.Error("static pod manifest not collected")
	}
	if len(res.Errors) != 0 {
		t.Error(res.Errors)
	}
}

func TestConfigFromFlagAndFlagsOnly(t *testing.T) {
	root := t.TempDir()
	write(t, root, "/etc/systemd/system/kubelet.service.d/10-kubeadm.conf", "[Service]\nEnvironment=\"KUBELET_CONFIG_ARGS=--config=/opt/kubelet.json\"\n")
	write(t, root, "/opt/kubelet.json", `{"apiVersion":"kubelet.config.k8s.io/v1beta1","kind":"KubeletConfiguration","readOnlyPort":10255}`)
	res, err := Collect(Options{Root: root, NodeName: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	if n, _ := resource.Number(kubelet(t, res), "readOnlyPort"); n != 10255 {
		t.Error("--config path not followed")
	}

	root = t.TempDir()
	write(t, root, "/etc/default/kubelet", "KUBELET_EXTRA_ARGS=--anonymous-auth=true --read-only-port 10255\n")
	res, err = Collect(Options{Root: root, NodeName: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	raw := kubelet(t, res)
	if v, _ := resource.Bool(raw, "authentication", "anonymous", "enabled"); !v {
		t.Error("flags-only kubelet not assessed")
	}
	if _, set := resource.Number(raw, "readOnlyPort"); set {
		t.Error("space-separated value misparsed")
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "no configuration file") {
		t.Error(res.Notes)
	}
}

func TestNothingFound(t *testing.T) {
	if _, err := Collect(Options{Root: t.TempDir()}); err == nil {
		t.Error("expected an error for an empty root")
	}
}
