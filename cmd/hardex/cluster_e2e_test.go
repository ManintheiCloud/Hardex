package main

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ManintheiCloud/Hardex/core/cluster"
	"github.com/ManintheiCloud/Hardex/core/remediation"
)

// fakeCluster is a stateful API server: LIST, GET and JSON PATCH against an
// in-memory object store, with resourceVersion bumps like the real thing.
type fakeCluster struct {
	mu      sync.Mutex
	objects map[string]map[string]any // object path -> object
	rv      int
	deny    string // object name whose PATCH is rejected (simulated admission)
	// inject names an object to which a "mutating webhook" adds
	// hostPID: true on every change, introducing a finding.
	inject string
	// lose names an object whose PATCH is applied but answered with a
	// gateway timeout, as when the response is lost.
	lose string
}

func (f *fakeCluster) add(r cluster.Resource, obj map[string]any) {
	ns, _ := obj["metadata"].(map[string]any)["namespace"].(string)
	name := obj["metadata"].(map[string]any)["name"].(string)
	f.rv++
	obj["metadata"].(map[string]any)["resourceVersion"] = fmt.Sprint(f.rv)
	f.objects[r.ObjectPath(ns, name)] = obj
}

func (f *fakeCluster) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer test-token" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodPatch {
		obj, ok := f.objects[r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		name := obj["metadata"].(map[string]any)["name"]
		if name == f.deny {
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(map[string]any{"message": "denied by admission webhook"})
			return
		}
		var ops []remediation.Op
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &ops); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		patched, err := remediation.Apply(obj, ops)
		if err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(map[string]any{"message": err.Error()})
			return
		}
		tests := true
		for _, op := range ops {
			tests = tests && op.Op == "test"
		}
		if tests { // a no-op patch changes nothing, not even resourceVersion
			json.NewEncoder(w).Encode(patched)
			return
		}
		if name == f.inject {
			patched["spec"].(map[string]any)["template"].(map[string]any)["spec"].(map[string]any)["hostPID"] = true
		}
		f.rv++
		patched["metadata"].(map[string]any)["resourceVersion"] = fmt.Sprint(f.rv)
		f.objects[r.URL.Path] = patched
		if name == f.lose && strings.Contains(string(body), "/metadata/resourceVersion") {
			f.lose = "" // only the forward patch's response is lost
			w.WriteHeader(http.StatusGatewayTimeout)
			return
		}
		json.NewEncoder(w).Encode(patched)
		return
	}
	for _, res := range cluster.Collected {
		if r.URL.Path == res.ListPath() {
			items := []any{}
			for p, o := range f.objects {
				if strings.Contains(p, "/"+res.Plural+"/") && strings.HasPrefix(p, strings.TrimSuffix(res.ListPath(), "/"+res.Plural)) {
					items = append(items, o)
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"metadata": map[string]any{}, "items": items})
			return
		}
	}
	w.WriteHeader(http.StatusNotFound)
}

func (f *fakeCluster) get(path string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.objects[path]
}

func deploymentObj(name string) map[string]any {
	return map[string]any{
		"apiVersion": "apps/v1", "kind": "Deployment",
		"metadata": map[string]any{"name": name, "namespace": "shop"},
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"containers": []any{map[string]any{"name": "web", "image": "x:1", "securityContext": map[string]any{"privileged": true}}},
		}}},
	}
}

var deployRes, _ = cluster.ResourceForKind("Deployment")

func startFakeCluster(t *testing.T, names ...string) (*fakeCluster, string) {
	t.Helper()
	f := &fakeCluster{objects: map[string]map[string]any{}}
	for _, n := range names {
		f.add(deployRes, deploymentObj(n))
	}
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	os.WriteFile(filepath.Join(dir, "ca.crt"), ca, 0o600)
	kc := filepath.Join(dir, "config")
	os.WriteFile(kc, []byte(fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: test
clusters: [{name: c, cluster: {server: %s, certificate-authority: ca.crt}}]
contexts: [{name: test, context: {cluster: c, user: u}}]
users: [{name: u, user: {token: test-token}}]
`, srv.URL)), 0o600)
	return f, kc
}

func privileged(obj map[string]any) any {
	v, _ := remediation.Get(obj, "/spec/template/spec/containers/0/securityContext/privileged")
	return v
}

func TestClusterScanFixVerifyRollback(t *testing.T) {
	f, kc := startFakeCluster(t, "web")
	path := deployRes.ObjectPath("shop", "web")

	if code, out, errOut := cli(t, "", "scan", "--cluster", "--kubeconfig", kc, "--profile", "minimal"); code != exitFindings || !strings.Contains(out, "HX-WL-001") {
		t.Fatalf("scan: exit %d\n%s\n%s", code, out, errOut)
	}
	if code, _, _ := cli(t, "", "fix", "--cluster", "--kubeconfig", kc, "--apply", "--yes"); code != exitUsage {
		t.Fatalf("--apply without --rules: exit %d, want %d", code, exitUsage)
	}
	// Declining confirmation changes nothing.
	cli(t, "no\n", "fix", "--cluster", "--kubeconfig", kc, "--rules", "HX-WL-001", "--apply")
	if privileged(f.get(path)) != true {
		t.Fatal("changed the cluster without confirmation")
	}

	backups := t.TempDir()
	code, out, errOut := cli(t, "", "fix", "--cluster", "--kubeconfig", kc, "--rules", "HX-WL-001,HX-WL-004",
		"--apply", "--yes", "--backup-dir", backups, "--profile", "restricted", "--fail-on", "none")
	if code != exitOK || !strings.Contains(out, "Verified") {
		t.Fatalf("fix --apply: exit %d\n%s\n%s", code, out, errOut)
	}
	if privileged(f.get(path)) != false {
		t.Fatal("patch was not applied")
	}

	files, _ := filepath.Glob(filepath.Join(backups, "hardex-backup-*.json"))
	if len(files) != 1 {
		t.Fatalf("backups = %v", files)
	}
	if code, out, errOut := cli(t, "", "rollback", files[0], "--kubeconfig", kc, "--yes"); code != exitOK {
		t.Fatalf("rollback: exit %d\n%s\n%s", code, out, errOut)
	}
	if privileged(f.get(path)) != true {
		t.Fatal("rollback did not restore the original value")
	}
	if code, out, _ := cli(t, "", "rollback", files[0], "--kubeconfig", kc, "--yes"); code != exitOK || !strings.Contains(out, "Nothing to roll back") {
		t.Fatalf("second rollback: exit %d\n%s", code, out)
	}
}

func TestClusterApplyFailureRollsBackEverything(t *testing.T) {
	f, kc := startFakeCluster(t, "a-first", "b-denied")
	f.deny = "b-denied"
	code, _, errOut := cli(t, "", "fix", "--cluster", "--kubeconfig", kc, "--rules", "HX-WL-001",
		"--apply", "--yes", "--backup-dir", t.TempDir())
	if code != exitIncomplete || !strings.Contains(errOut, "rolled back 1") {
		t.Fatalf("exit %d\n%s", code, errOut)
	}
	if privileged(f.get(deployRes.ObjectPath("shop", "a-first"))) != true {
		t.Fatal("first object left patched after a later failure")
	}
}

// Success is defined by the re-assessment (ADR 0003): when it finds a new
// problem, the changes are rolled back unless --keep-unverified.
func TestClusterFailedVerificationRollsBack(t *testing.T) {
	for _, keep := range []bool{false, true} {
		f, kc := startFakeCluster(t, "web")
		f.inject = "web"
		path := deployRes.ObjectPath("shop", "web")
		args := []string{"fix", "--cluster", "--kubeconfig", kc, "--rules", "HX-WL-001", "--apply", "--yes",
			"--backup-dir", t.TempDir(), "--profile", "restricted", "--fail-on", "high"}
		if keep {
			args = append(args, "--keep-unverified")
		}
		code, out, errOut := cli(t, "", args...)
		if code != exitFindings || !strings.Contains(out, "Verification failed") || !strings.Contains(out, "introduced [high] HX-WL-002") {
			t.Fatalf("keep=%v: exit %d\n%s\n%s", keep, code, out, errOut)
		}
		want := any(true) // rolled back
		if keep {
			want = false
		}
		if got := privileged(f.get(path)); got != want {
			t.Errorf("keep=%v: privileged = %v, want %v\n%s", keep, got, want, out)
		}
	}
}

// A patch the server applied but whose response was lost is undone too.
func TestClusterLostResponseIsRolledBack(t *testing.T) {
	f, kc := startFakeCluster(t, "a-first", "b-lost")
	f.lose = "b-lost"
	code, out, errOut := cli(t, "", "fix", "--cluster", "--kubeconfig", kc, "--rules", "HX-WL-001",
		"--apply", "--yes", "--backup-dir", t.TempDir())
	if code != exitIncomplete || !strings.Contains(errOut, "rolled back 2") || strings.Contains(errOut, "INCOMPLETE") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	for _, n := range []string{"a-first", "b-lost"} {
		if privileged(f.get(deployRes.ObjectPath("shop", n))) != true {
			t.Errorf("%s left patched", n)
		}
	}
}

func TestFixManifestsWritesOutputWithoutTouchingInputs(t *testing.T) {
	in := filepath.Join(t.TempDir(), "app.yaml")
	src := "apiVersion: v1\nkind: Pod\nmetadata: {name: \"../../evil\", namespace: shop}\nspec:\n  containers: [{name: c, image: x:1, securityContext: {privileged: true}}]\n"
	os.WriteFile(in, []byte(src), 0o644)
	out := t.TempDir()
	if code, stdout, stderr := cli(t, "", "fix", in, "--out", out); code != exitOK {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	if b, _ := os.ReadFile(in); string(b) != src {
		t.Fatal("input manifest was modified")
	}
	files, _ := filepath.Glob(filepath.Join(out, "*"))
	for _, f := range files {
		if filepath.Dir(f) != out {
			t.Fatalf("file written outside output dir: %s", f)
		}
	}
	if code, _, _ := cli(t, "", "scan", "--profile", "minimal", out); code != exitOK {
		t.Fatal("patched output still has minimal-profile findings")
	}
}

func TestFleetAcrossTwoClusters(t *testing.T) {
	_, kcA := startFakeCluster(t, "web")
	_, kcB := startFakeCluster(t)
	// Merge the two single-context kubeconfigs into one with contexts a and b.
	read := func(p, ctx string) string {
		b, _ := os.ReadFile(p)
		dir := filepath.Dir(p)
		s := strings.ReplaceAll(string(b), "certificate-authority: ca.crt", "certificate-authority: "+filepath.Join(dir, "ca.crt"))
		s = strings.ReplaceAll(s, "{name: c,", "{name: c-"+ctx+",")
		s = strings.ReplaceAll(s, "{name: u,", "{name: u-"+ctx+",")
		s = strings.ReplaceAll(s, "{cluster: c, user: u}", "{cluster: c-"+ctx+", user: u-"+ctx+"}")
		return strings.ReplaceAll(s, "{name: test,", "{name: "+ctx+",")
	}
	a, b := read(kcA, "a"), read(kcB, "b")
	section := func(s, key string) string {
		for _, line := range strings.Split(s, "\n") {
			if strings.HasPrefix(line, key+": [") {
				return strings.TrimSuffix(strings.TrimPrefix(line, key+": ["), "]")
			}
		}
		return ""
	}
	merged := "apiVersion: v1\nkind: Config\ncurrent-context: a\n"
	for _, key := range []string{"clusters", "contexts", "users"} {
		merged += key + ": [" + section(a, key) + ", " + section(b, key) + "]\n"
	}
	kc := filepath.Join(t.TempDir(), "config")
	os.WriteFile(kc, []byte(merged), 0o600)

	out := t.TempDir()
	code, stdout, stderr := cli(t, "", "fleet", "--kubeconfig", kc, "--contexts", "a,b", "--out", out, "--profile", "minimal")
	if code != exitFindings || !strings.Contains(stdout, "HX-WL-001") || !strings.Contains(stdout, "inconsistent across clusters") {
		t.Fatalf("exit %d\n%s\n%s", code, stdout, stderr)
	}
	for _, f := range []string{"a.json", "b.json"} {
		if _, err := os.Stat(filepath.Join(out, f)); err != nil {
			t.Errorf("report %s not saved", f)
		}
	}
	if code, stdout, _ := cli(t, "", "compare", filepath.Join(out, "a.json"), filepath.Join(out, "b.json")); code != exitOK || !strings.Contains(stdout, "HX-WL-001") {
		t.Fatalf("compare: exit %d\n%s", code, stdout)
	}
}
