package durable

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRename(t *testing.T) {
	dir := t.TempDir()
	tmp, dst := filepath.Join(dir, "a.tmp"), filepath.Join(dir, "a")
	if err := os.WriteFile(tmp, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Rename(tmp, dst, dir); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(dst); err != nil || string(b) != "x" {
		t.Fatalf("got %q, %v", b, err)
	}
	if err := SyncDir(filepath.Join(dir, "missing")); err == nil && runtime.GOOS != "windows" {
		t.Error("SyncDir of a missing directory succeeded")
	}
}
