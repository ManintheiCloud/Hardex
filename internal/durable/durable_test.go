package durable

import (
	"errors"
	"io"
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

func TestWriteFileKeepsOldFileOnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.json")
	if err := WriteFile(path, 0o600, func(w io.Writer) error { _, err := w.Write([]byte("complete")); return err }); err != nil {
		t.Fatal(err)
	}
	err := WriteFile(path, 0o600, func(w io.Writer) error {
		w.Write([]byte("trunc"))
		return errors.New("disk full")
	})
	if err == nil {
		t.Fatal("error not returned")
	}
	if b, _ := os.ReadFile(path); string(b) != "complete" {
		t.Errorf("file = %q, want the previous content", b)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".*.tmp")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
	if info, _ := os.Stat(path); runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", info.Mode().Perm())
	}
}
