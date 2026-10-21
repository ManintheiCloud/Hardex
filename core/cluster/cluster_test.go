package cluster

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"github.com/ManintheiCloud/Hardex/core/resource"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeAPI serves a tiny cluster: two pages of pods (one owned by a
// ReplicaSet), a forbidden resource, and empty lists for everything else.
type fakeAPI struct {
	forbid     string // plural to answer 403 for
	token      string // expected bearer token ("" = no check)
	patches    atomic.Int32
	lastPatch  []byte
	seenTokens []string
}

func (f *fakeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	f.seenTokens = append(f.seenTokens, auth)
	if f.token != "" && auth != "Bearer "+f.token {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]any{"message": "Unauthorized"})
		return
	}
	if r.Method == http.MethodPatch {
		f.patches.Add(1)
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		f.lastPatch = buf
		json.NewEncoder(w).Encode(map[string]any{"kind": "Deployment", "metadata": map[string]any{"name": "web"}})
		return
	}
	plural := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	if plural == f.forbid {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]any{"message": "forbidden"})
		return
	}
	resp := map[string]any{"metadata": map[string]any{}, "items": []any{}}
	if plural == "pods" {
		if r.URL.Query().Get("continue") == "" {
			resp["metadata"] = map[string]any{"continue": "page2"}
			resp["items"] = []any{map[string]any{
				"metadata": map[string]any{"name": "standalone", "namespace": "shop"},
				"spec":     map[string]any{"containers": []any{map[string]any{"name": "c", "image": "x:1", "securityContext": map[string]any{"privileged": true}}}},
			}}
		} else {
			resp["items"] = []any{map[string]any{
				"metadata": map[string]any{"name": "web-abc-123", "namespace": "shop",
					"ownerReferences": []any{map[string]any{"kind": "ReplicaSet", "name": "web-abc", "controller": true}}},
				"spec": map[string]any{"containers": []any{map[string]any{"name": "c", "image": "x:1"}}},
			}, map[string]any{
				// kubectl debug --profile=sysadmin on a Deployment's pod
				"metadata": map[string]any{"name": "web-abc-456", "namespace": "shop",
					"ownerReferences": []any{map[string]any{"kind": "ReplicaSet", "name": "web-abc", "controller": true}}},
				"spec": map[string]any{
					"hostNetwork":         true,
					"containers":          []any{map[string]any{"name": "c", "image": "x:1"}},
					"ephemeralContainers": []any{map[string]any{"name": "debugger-x", "image": "busybox", "securityContext": map[string]any{"privileged": true}}},
				},
			}}
		}
	}
	if plural == "nodes" {
		resp["items"] = []any{map[string]any{
			"metadata": map[string]any{"name": "n1", "labels": map[string]any{"pool": "a"}, "annotations": map[string]any{"x": "y"}},
			"spec":     map[string]any{"taints": []any{map[string]any{"key": "dedicated", "effect": "NoSchedule"}}, "podCIDR": "10.0.0.0/24"},
			"status":   map[string]any{"addresses": []any{map[string]any{"type": "InternalIP", "address": "10.1.2.3"}}},
		}}
	}
	json.NewEncoder(w).Encode(resp)
}

func newFake(t *testing.T, f *fakeAPI) (*httptest.Server, *Config) {
	t.Helper()
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	return srv, &Config{Context: "test", Server: srv.URL, CAData: ca, Token: "secret-token"}
}

func TestCollectPaginatesAndDeduplicates(t *testing.T) {
	f := &fakeAPI{token: "secret-token"}
	_, cfg := newFake(t, f)
	c, err := NewClient(cfg, ReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	col, err := Collect(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	pods := col.Inventory.OfKind("Pod")
	if len(pods) != 2 || pods[0].Name != "standalone" || pods[1].Name != "web-abc-456" {
		t.Fatalf("pods = %v; want the standalone pod and the owned pod with a debug container", pods)
	}
	// The owned pod is kept for its ephemeral container only.
	spec := resource.Map(pods[1].Raw, "spec")
	if len(resource.Maps(spec, "containers")) != 0 || len(resource.Maps(spec, "ephemeralContainers")) != 1 || spec["hostNetwork"] != nil {
		t.Errorf("owned pod spec = %v; want only its ephemeral container", spec)
	}
	if col.Skipped != 1 {
		t.Errorf("skipped = %d, want 1 (ReplicaSet-owned pod)", col.Skipped)
	}
	if pods[0].Kind != "Pod" || pods[0].APIVersion != "v1" {
		t.Error("kind/apiVersion not set on list items")
	}
	if len(col.Errors) != 0 {
		t.Errorf("unexpected errors: %v", col.Errors)
	}
}

func TestCollectReportsForbiddenResources(t *testing.T) {
	_, cfg := newFake(t, &fakeAPI{forbid: "clusterroles"})
	c, _ := NewClient(cfg, ReadOnly)
	col, err := Collect(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if len(col.Errors) != 1 || !strings.Contains(col.Errors[0], "clusterroles") {
		t.Errorf("errors = %v", col.Errors)
	}
}

func TestCollectNeverReadsSecrets(t *testing.T) {
	for _, r := range Collected {
		if r.Plural == "secrets" {
			t.Fatal("collection must not list secrets")
		}
	}
}

func TestReadOnlyClientRefusesWrites(t *testing.T) {
	f := &fakeAPI{}
	_, cfg := newFake(t, f)
	c, _ := NewClient(cfg, ReadOnly)
	if _, err := c.JSONPatch(context.Background(), "/apis/apps/v1/namespaces/x/deployments/web", []byte("[]")); err == nil {
		t.Fatal("read-only client sent a PATCH")
	}
	if f.patches.Load() != 0 {
		t.Fatal("request reached the server")
	}
	rw, _ := NewClient(cfg, ReadWrite)
	if _, err := rw.JSONPatch(context.Background(), "/apis/apps/v1/namespaces/x/deployments/web", []byte("[]")); err != nil {
		t.Fatal(err)
	}
}

func TestUntrustedServerCertificateRejected(t *testing.T) {
	_, cfg := newFake(t, &fakeAPI{})
	cfg.CAData = nil // system roots do not trust the test server
	c, _ := NewClient(cfg, ReadOnly)
	if _, err := c.Get(context.Background(), "/api/v1/pods", nil); err == nil {
		t.Fatal("connected to a server with an untrusted certificate")
	}
}

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const kubeconfigTmpl = `apiVersion: v1
kind: Config
current-context: dev
preferences: {}
clusters:
  - name: dev-cluster
    cluster:
      server: SERVER
      certificate-authority: ca.crt
      extensions: []
contexts:
  - name: dev
    context: {cluster: dev-cluster, user: dev-user, namespace: shop}
  - name: other
    context: {cluster: dev-cluster, user: other-user}
users:
  - name: dev-user
    user:
      tokenFile: token
  - name: other-user
    user:
      token: inline
`

func TestLoadKubeconfigResolvesRelativePaths(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "ca.crt", "CA")
	writeFile(t, dir, "token", "file-token\n")
	kc := writeFile(t, dir, "config", strings.Replace(kubeconfigTmpl, "SERVER", "https://k8s.example:6443", 1))

	cfg, err := LoadKubeconfig([]string{kc}, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Context != "dev" || string(cfg.CAData) != "CA" || cfg.TokenFile != filepath.Join(dir, "token") {
		t.Errorf("cfg = %+v", cfg)
	}
	other, err := LoadKubeconfig([]string{kc}, "other")
	if err != nil || other.Token != "inline" {
		t.Errorf("explicit context: %+v, %v", other, err)
	}
	if _, err := LoadKubeconfig([]string{kc}, "missing"); err == nil {
		t.Error("accepted unknown context")
	}
}

func TestLoadKubeconfigRefusesUnsafeTransport(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "ca.crt", "CA")
	plain := writeFile(t, dir, "plain", strings.Replace(kubeconfigTmpl, "SERVER", "http://k8s.example:8080", 1))
	if _, err := LoadKubeconfig([]string{plain}, ""); err == nil {
		t.Error("accepted http:// server")
	}
	insecure := writeFile(t, dir, "insecure", strings.Replace(
		strings.Replace(kubeconfigTmpl, "SERVER", "https://k8s.example", 1),
		"certificate-authority: ca.crt", "insecure-skip-tls-verify: true", 1))
	if _, err := LoadKubeconfig([]string{insecure}, ""); err == nil {
		t.Error("accepted insecure-skip-tls-verify")
	}
}

func TestTokenFileIsReadPerRequestAndExecPlugin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell plugin")
	}
	f := &fakeAPI{}
	_, cfg := newFake(t, f)
	dir := t.TempDir()

	cfg.Token = ""
	cfg.TokenFile = writeFile(t, dir, "token", "one")
	c, _ := NewClient(cfg, ReadOnly)
	c.Get(context.Background(), "/api/v1/namespaces", nil)
	os.WriteFile(cfg.TokenFile, []byte("two"), 0o600)
	c.Get(context.Background(), "/api/v1/namespaces", nil)

	cfg.TokenFile = ""
	plugin := writeFile(t, dir, "plugin.sh", "#!/bin/sh\necho '{\"apiVersion\":\"client.authentication.k8s.io/v1\",\"kind\":\"ExecCredential\",\"status\":{\"token\":\"from-plugin\"}}'\n")
	os.Chmod(plugin, 0o700)
	cfg.Exec = &ExecConfig{Command: plugin}
	c2, _ := NewClient(cfg, ReadOnly)
	if _, err := c2.Get(context.Background(), "/api/v1/namespaces", nil); err != nil {
		t.Fatal(err)
	}
	want := []string{"Bearer one", "Bearer two", "Bearer from-plugin"}
	for i, w := range want {
		if f.seenTokens[i] != w {
			t.Errorf("request %d auth = %q, want %q", i, f.seenTokens[i], w)
		}
	}
}

func TestCollectNodesMinimallyAndOptionally(t *testing.T) {
	_, cfg := newFake(t, &fakeAPI{})
	c, _ := NewClient(cfg, ReadOnly)
	col, err := Collect(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	nodes := col.Inventory.OfKind("Node")
	if len(nodes) != 1 {
		t.Fatalf("nodes = %v", nodes)
	}
	raw := nodes[0].Raw
	if resource.Map(raw, "status") != nil || resource.Map(raw, "metadata", "annotations") != nil || resource.String(raw, "spec", "podCIDR") != "" {
		t.Errorf("node not minimised: %v", raw)
	}
	if len(resource.Maps(raw, "spec", "taints")) != 1 || resource.String(raw, "metadata", "labels", "pool") != "a" {
		t.Errorf("node labels/taints lost: %v", raw)
	}

	_, cfg = newFake(t, &fakeAPI{forbid: "nodes"})
	c, _ = NewClient(cfg, ReadOnly)
	col, err = Collect(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if len(col.Errors) != 0 || len(col.Warnings) != 1 || !strings.Contains(col.Warnings[0], "nodes") {
		t.Errorf("forbidden nodes must warn, not fail: errors %v warnings %v", col.Errors, col.Warnings)
	}
}
