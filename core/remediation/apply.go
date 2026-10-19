package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// BackupSchema identifies the backup file format.
const BackupSchema = "hardex.dev/backup/v1alpha1"

// Backup records everything needed to undo an apply. It is written before
// the first change and updated after each one, so an interrupted run still
// leaves an accurate record of what was changed.
type Backup struct {
	Schema    string         `json:"schema"`
	CreatedAt time.Time      `json:"createdAt"`
	Context   string         `json:"context"`
	Server    string         `json:"server"`
	Objects   []BackupObject `json:"objects"`
	path      string
}

// BackupObject is one object's original state and the patches applied to it.
type BackupObject struct {
	Target   Target         `json:"target"`
	Original map[string]any `json:"original"`
	Patch    []Op           `json:"patch"`
	Inverse  []Op           `json:"inverse"`
	Fixes    []FixSummary   `json:"fixes"`
	Applied  bool           `json:"applied"`
	// RolledBack is set once the inverse has been applied.
	RolledBack bool `json:"rolledBack,omitempty"`
}

// PatchFunc sends a JSON patch for a target to the cluster.
type PatchFunc func(ctx context.Context, t Target, patch []Op) error

// NewBackup creates and persists a backup for the plan's objects in dir.
func NewBackup(dir, kubeContext, server string, objects []ObjectPlan, now time.Time) (*Backup, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	b := &Backup{Schema: BackupSchema, CreatedAt: now.UTC(), Context: kubeContext, Server: server,
		path: filepath.Join(dir, "hardex-backup-"+now.UTC().Format("20060102T150405Z")+".json")}
	for _, o := range objects {
		b.Objects = append(b.Objects, BackupObject{Target: o.Target, Original: o.Original, Patch: o.Patch, Inverse: o.Inverse, Fixes: o.Fixes})
	}
	return b, b.save()
}

// Path returns where the backup is stored.
func (b *Backup) Path() string { return b.path }

// LoadBackup reads a backup file.
func LoadBackup(path string) (*Backup, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Backup
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if b.Schema != BackupSchema {
		return nil, fmt.Errorf("%s: unsupported backup schema %q", path, b.Schema)
	}
	b.path = path
	return &b, nil
}

// save writes the backup atomically (write, sync, rename), readable only by
// the owner: it contains full object specs.
func (b *Backup) save() error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	tmp := b.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, b.path)
}

// ApplyResult describes an apply run.
type ApplyResult struct {
	Applied    []Target
	RolledBack []Target
	// Err is the error that stopped the run, if any.
	Err error
	// RollbackErr is set if automatic rollback itself failed; the backup
	// file then records exactly which objects still carry changes.
	RollbackErr error
}

// ApplyAll applies each object's patch in order. If any patch fails, every
// patch already applied in this run is reverted, so the cluster is never left
// partially remediated (ADR 0003, constraint 5).
func ApplyAll(ctx context.Context, b *Backup, patch PatchFunc) ApplyResult {
	var res ApplyResult
	for i := range b.Objects {
		o := &b.Objects[i]
		if err := patch(ctx, o.Target, o.Patch); err != nil {
			res.Err = fmt.Errorf("%s: %w", o.Target, err)
			rb := Rollback(ctx, b, patch)
			res.RolledBack, res.RollbackErr = rb.RolledBack, rb.Err
			return res
		}
		o.Applied = true
		res.Applied = append(res.Applied, o.Target)
		if err := b.save(); err != nil {
			res.Err = fmt.Errorf("recording backup after %s: %w", o.Target, err)
			rb := Rollback(ctx, b, patch)
			res.RolledBack, res.RollbackErr = rb.RolledBack, rb.Err
			return res
		}
	}
	return res
}

// RollbackResult describes a rollback run.
type RollbackResult struct {
	RolledBack []Target
	Err        error
}

// Rollback applies the inverse patch of every applied, not yet rolled back
// object, in reverse order. Inverse patches test the values Hardex set; if
// someone changed an object since, its rollback fails and is reported rather
// than overwriting their change.
func Rollback(ctx context.Context, b *Backup, patch PatchFunc) RollbackResult {
	var res RollbackResult
	var errs []error
	for i := len(b.Objects) - 1; i >= 0; i-- {
		o := &b.Objects[i]
		if !o.Applied || o.RolledBack {
			continue
		}
		if err := patch(ctx, o.Target, o.Inverse); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", o.Target, err))
			continue
		}
		o.RolledBack = true
		res.RolledBack = append(res.RolledBack, o.Target)
	}
	if err := b.save(); err != nil {
		errs = append(errs, fmt.Errorf("recording rollback: %w", err))
	}
	if len(errs) > 0 {
		res.Err = fmt.Errorf("rollback incomplete: %v", errs)
	}
	return res
}
