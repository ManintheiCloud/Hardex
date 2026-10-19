package resource

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, y string) (*Inventory, error) {
	t.Helper()
	return Load([]string{"-"}, strings.NewReader(y))
}

func TestLoadMultiDocumentWithLines(t *testing.T) {
	inv, err := load(t, `# leading comment
apiVersion: v1
kind: ConfigMap
metadata: {name: a}
---
# comment before object
apiVersion: v1
kind: ConfigMap
metadata: {name: b, namespace: x}
---
---
`)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Objects) != 2 {
		t.Fatalf("got %d objects, want 2", len(inv.Objects))
	}
	if inv.Objects[0].Line != 2 || inv.Objects[1].Line != 7 {
		t.Errorf("lines = %d, %d; want 2, 7", inv.Objects[0].Line, inv.Objects[1].Line)
	}
	if inv.Objects[0].EffectiveNamespace() != "default" || inv.Objects[1].EffectiveNamespace() != "x" {
		t.Error("namespace resolution wrong")
	}
}

func TestLoadExpandsLists(t *testing.T) {
	inv, err := load(t, `apiVersion: v1
kind: List
items:
  - {apiVersion: v1, kind: ServiceAccount, metadata: {name: a}}
  - {apiVersion: v1, kind: ServiceAccount, metadata: {name: b}}
`)
	if err != nil || len(inv.OfKind("ServiceAccount")) != 2 {
		t.Fatalf("list not expanded: %v", err)
	}
}

func TestLoadRecordsNonKubernetesDocuments(t *testing.T) {
	inv, err := load(t, "replicaCount: 3\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Objects) != 0 || len(inv.Skipped) != 1 {
		t.Errorf("objects=%d skipped=%d; want 0, 1", len(inv.Objects), len(inv.Skipped))
	}
}

func TestLoadRejectsMalformedAndAmbiguousYAML(t *testing.T) {
	for name, y := range map[string]string{
		"syntax":        "kind: Pod\n  metadata: [\n",
		"duplicate key": "kind: Pod\nmetadata: {name: a}\nspec: {hostNetwork: false}\nspec: {hostNetwork: true}\n",
		"not a mapping": "- a\n- b\n",
	} {
		if _, err := load(t, y); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadAllowsBenignAnchors(t *testing.T) {
	inv, err := load(t, `apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  containers:
    - &c {name: a, image: x:1}
    - *c
`)
	if err != nil || len(Containers(Map(inv.Objects[0].Raw, "spec"))) != 2 {
		t.Fatalf("anchors not resolved: %v", err)
	}
}

func TestLoadRejectsAliasBomb(t *testing.T) {
	var b strings.Builder
	b.WriteString("kind: ConfigMap\nmetadata: {name: x}\na0: &a0 [x,x,x,x,x,x,x,x,x,x]\n")
	for i := 1; i <= 9; i++ {
		b.WriteString("a" + string(rune('0'+i)) + ": &a" + string(rune('0'+i)) + " [")
		for j := 0; j < 10; j++ {
			if j > 0 {
				b.WriteString(",")
			}
			b.WriteString("*a" + string(rune('0'+i-1)))
		}
		b.WriteString("]\n")
	}
	if _, err := load(t, b.String()); err == nil || !strings.Contains(err.Error(), "aliases") {
		t.Fatalf("alias bomb not rejected: %v", err)
	}
}

func TestLoadDirectorySkipsHiddenAndNonManifests(t *testing.T) {
	dir := t.TempDir()
	write := func(p, s string) {
		full := filepath.Join(dir, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, []byte(s), 0o644)
	}
	write("a.yaml", "kind: ServiceAccount\nmetadata: {name: a}\n")
	write("sub/b.yml", "kind: ServiceAccount\nmetadata: {name: b}\n")
	write(".git/c.yaml", "kind: ServiceAccount\nmetadata: {name: c}\n")
	write("README.md", "kind: ServiceAccount\n")
	inv, err := Load([]string{dir}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Objects) != 2 {
		t.Errorf("got %d objects, want 2", len(inv.Objects))
	}
}

// Kubernetes reads unquoted yes/on/y as true (YAML 1.1). Hardex must read
// them the same way, or `privileged: yes` would evade detection.
func TestLoadMatchesKubernetesYAML11Booleans(t *testing.T) {
	inv, err := load(t, `apiVersion: v1
kind: Pod
metadata: {name: p}
spec:
  hostNetwork: on
  hostPID: Yes
  hostIPC: n
  enableServiceLinks: off
  containers:
    - name: "yes"
      image: x:1
      securityContext: {privileged: y}
      env: [{name: A, value: 'on'}]
  nodeSelector: {on: "true"}
`)
	if err != nil {
		t.Fatal(err)
	}
	spec := Map(inv.Objects[0].Raw, "spec")
	for field, want := range map[string]bool{"hostNetwork": true, "hostPID": true, "hostIPC": false, "enableServiceLinks": false} {
		if got, set := Bool(spec, field); !set || got != want {
			t.Errorf("%s = %v (set %v), want %v", field, got, set, want)
		}
	}
	c := Containers(spec)[0]
	if v, set := Bool(c.Spec, "securityContext", "privileged"); !set || !v {
		t.Error("privileged: y not read as true")
	}
	if c.Name != "yes" {
		t.Errorf("quoted scalar changed: name = %q", c.Name)
	}
	if String(Maps(c.Spec, "env")[0], "value") != "on" {
		t.Error("quoted 'on' must stay a string")
	}
	if _, ok := Map(spec, "nodeSelector")["on"]; !ok {
		t.Error("mapping keys must not be converted")
	}
}
