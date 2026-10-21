// Package durable makes file replacements survive a crash of the operating
// system, not only of the process.
//
// Writing a temporary file, syncing it and renaming it over the target is
// atomic, but the rename itself is a change to the directory: until the
// directory is synced, a power loss or kernel crash can leave the old file
// in place. Hardex's remediation backup is a write-ahead journal, so losing
// the latest rename would lose the record of a change about to be made.
package durable

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// SyncDir flushes a directory's entries (renames, creations) to stable
// storage. Windows cannot sync a directory handle; there, NTFS journals
// metadata and SyncDir does nothing.
func SyncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if cerr := d.Close(); err == nil {
		err = cerr
	}
	return err
}

// Rename renames oldpath to newpath and syncs the directory of newpath.
func Rename(oldpath, newpath, dir string) error {
	if err := os.Rename(oldpath, newpath); err != nil {
		return err
	}
	return SyncDir(dir)
}

// WriteFile writes a file through write and replaces path only if every
// step succeeded: a temporary file in the same directory is written,
// synced, closed and renamed over path, then the directory is synced. On
// any error path is untouched and the temporary file is removed, so an
// interrupted or failed write never leaves a truncated file where a
// complete one is expected.
func WriteFile(path string, perm os.FileMode, write func(io.Writer) error) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err = f.Chmod(perm); err != nil && runtime.GOOS != "windows" {
		return err
	}
	if err = write(f); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return Rename(tmp, path, dir)
}
