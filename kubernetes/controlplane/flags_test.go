package controlplane

import "testing"

func TestParseFlags(t *testing.T) {
	got := parseFlags([]string{"kube-apiserver", "--a=1", "--b", "2", "--c", "-d=x=y", "--a=3"})
	want := map[string]string{"a": "3", "b": "2", "c": "true", "d": "x=y"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("flag %s = %q, want %q", k, got[k], v)
		}
	}
}

func TestRuns(t *testing.T) {
	if !runs([]string{"/usr/local/bin/kube-apiserver", "--x"}, "kube-apiserver") {
		t.Error("absolute binary path not recognised")
	}
	if runs([]string{"sh", "-c", "kube-apiserver"}, "kube-apiserver") {
		t.Error("shell wrapper misidentified as the binary")
	}
}
