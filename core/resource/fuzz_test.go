package resource

import (
	"bytes"
	"testing"
	"time"
)

// FuzzLoad checks that arbitrary input never panics the loader. Run longer
// with: go test -fuzz=FuzzLoad ./core/resource
func FuzzLoad(f *testing.F) {
	for _, seed := range []string{
		"apiVersion: v1\nkind: Pod\nmetadata: {name: p}\nspec: {containers: [{name: c}]}\n",
		"kind: List\nitems: [{kind: Pod}]\n---\nkind: X\n",
		"a: &a [1]\nb: [*a, *a]\nkind: K\n",
		"kind: Pod\nspec: {hostNetwork: yes}\n",
		"--- \n...\n---\n# only comment\n",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		done := make(chan struct{})
		go func() { Load([]string{"-"}, bytes.NewReader(data)); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("slow input %q", data)
		}
		inv, err := Load([]string{"-"}, bytes.NewReader(data))
		if err == nil {
			for _, o := range inv.Objects {
				_ = o.Ref()
				pod, _ := PodSpec(o)
				_ = Containers(pod)
			}
		}
	})
}
