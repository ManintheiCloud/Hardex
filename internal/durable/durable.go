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
	"os"
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
