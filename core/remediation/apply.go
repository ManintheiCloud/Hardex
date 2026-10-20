package remediation

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ManintheiCloud/Hardex/internal/durable"
)

// BackupSchema identifies the backup file format.
const BackupSchema = "hardex.dev/backup/v1alpha1"

// Backup records everything needed to undo an apply. It is a write-ahead
// journal: each object is marked Attempted, durably, before its patch is
// sent, and Applied after the API server confirms it. An object that is
// Attempted but not Applied (the process died, or the request failed in a
// way that does not say whether the server applied it) has an unknown
// outcome; Rollback resolves it against the live object.
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
	// Attempted is recorded before the patch is sent.
	Attempted bool `json:"attempted,omitempty"`
	// Applied is recorded after the API server accepted the patch.
	Applied bool `json:"applied"`
	// RolledBack is set once the inverse has been applied.
	RolledBack bool `json:"rolledBack,omitempty"`
	// NotApplied is set when an attempted patch is found not to have
	// changed the object.
	NotApplied bool `json:"notApplied,omitempty"`
}

// uncertain reports whether the object's patch may or may not have been
// applied.
func (o *BackupObject) uncertain() bool {
	return o.Attempted && !o.Applied && !o.RolledBack && !o.NotApplied
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

// save writes the backup atomically and durably (write, sync, rename, sync
// the directory), readable only by the owner: it contains full object specs.
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
	// The directory sync makes the rename itself durable: the journal must
	// survive an operating-system crash, not only a process crash.
	return durable.Rename(tmp, b.path, filepath.Dir(b.path))
}

// ApplyResult describes an apply run.
type ApplyResult struct {
	Applied    []Target
	RolledBack []Target
	// NotApplied lists objects whose patch failed and turned out not to
	// have changed them.
	NotApplied []Target
	// Err is the error that stopped the run, if any.
	Err error
	// RollbackErr is set if automatic rollback itself failed; the backup
	// file then records exactly which objects still carry changes.
	RollbackErr error
}

// ApplyAll applies each object's patch in order. If any patch fails, every
// patch that was or may have been applied in this run is reverted, so the
// cluster is never left partially remediated (ADR 0003, constraint 5).
// Rollback does not use ctx's cancellation: an interrupted run must still
// be able to undo what it did.
func ApplyAll(ctx context.Context, b *Backup, patch PatchFunc) ApplyResult {
	var res ApplyResult
	fail := func(err error) ApplyResult {
		res.Err = err
		rb := Rollback(ctx, b, patch)
		res.RolledBack, res.NotApplied, res.RollbackErr = rb.RolledBack, rb.NotApplied, rb.Err
		return res
	}
	for i := range b.Objects {
		o := &b.Objects[i]
		if err := ctx.Err(); err != nil {
			return fail(fmt.Errorf("interrupted before %s: %w", o.Target, err))
		}
		// Write-ahead: record the attempt before the cluster can change.
		o.Attempted = true
		if err := b.save(); err != nil {
			o.Attempted = false
			return fail(fmt.Errorf("recording backup before %s: %w", o.Target, err))
		}
		if err := patch(ctx, o.Target, o.Patch); err != nil {
			// The object stays Attempted: a timeout or cancellation may
			// have been applied by the server. Rollback finds out.
			return fail(fmt.Errorf("%s: %w", o.Target, err))
		}
		o.Applied = true
		res.Applied = append(res.Applied, o.Target)
		if err := b.save(); err != nil {
			return fail(fmt.Errorf("recording backup after %s: %w", o.Target, err))
		}
	}
	return res
}

// RollbackTimeout bounds a rollback, which runs even after the apply's
// context was cancelled.
var RollbackTimeout = 2 * time.Minute

// RollbackResult describes a rollback run.
type RollbackResult struct {
	RolledBack []Target
	// NotApplied lists objects whose outcome was unknown and that turned
	// out not to have been changed.
	NotApplied []Target
	Err        error
}

// Rollback undoes, in reverse order, every object that was applied, and
// resolves every object whose outcome is unknown: if its inverse applies,
// the patch had landed and is now undone; if instead every field the patch
// touches still has its original value, there is nothing to undo. Inverse patches test the values
// Hardex set, so an object someone changed since is reported, never
// overwritten. The backup is saved after each object. Rollback ignores the
// cancellation of ctx (it is often called because ctx was cancelled) and
// is bounded by RollbackTimeout instead.
func Rollback(ctx context.Context, b *Backup, patch PatchFunc) RollbackResult {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), RollbackTimeout)
	defer cancel()
	var res RollbackResult
	var errs []error
	for i := len(b.Objects) - 1; i >= 0; i-- {
		o := &b.Objects[i]
		switch {
		case o.Applied && !o.RolledBack:
			if err := patch(ctx, o.Target, o.Inverse); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", o.Target, err))
				continue
			}
			o.RolledBack = true
			res.RolledBack = append(res.RolledBack, o.Target)
		case o.uncertain():
			if err := patch(ctx, o.Target, o.Inverse); err == nil {
				o.Applied, o.RolledBack = true, true
				res.RolledBack = append(res.RolledBack, o.Target)
			} else if tests := testsOnly(o.Patch); len(tests) > 0 && patch(ctx, o.Target, tests) == nil {
				o.NotApplied = true
				res.NotApplied = append(res.NotApplied, o.Target)
			} else {
				errs = append(errs, fmt.Errorf("%s: unknown whether the patch was applied, and the object no longer matches either the original or the patched state (changed since?): %w", o.Target, err))
				continue
			}
		default:
			continue
		}
		if err := b.save(); err != nil {
			errs = append(errs, fmt.Errorf("recording rollback of %s: %w", o.Target, err))
		}
	}
	if len(errs) > 0 {
		res.Err = fmt.Errorf("rollback incomplete: %v", errs)
	}
	return res
}

// Pending lists the objects a rollback would act on: applied and not yet
// rolled back, or with an unknown outcome.
func (b *Backup) Pending() (applied, uncertain []Target) {
	for i := range b.Objects {
		o := &b.Objects[i]
		switch {
		case o.Applied && !o.RolledBack:
			applied = append(applied, o.Target)
		case o.uncertain():
			uncertain = append(uncertain, o.Target)
		}
	}
	return applied, uncertain
}

// testsOnly returns the test operations of a patch on the values it
// replaces: sent alone, they check, without changing anything, that every
// field the patch touches still has its original value. The
// resourceVersion guard is left out: it moves with any update (a
// controller writing status, say), and a field-level match already means
// there is nothing to undo.
func testsOnly(ops []Op) []Op {
	var out []Op
	for _, op := range ops {
		if op.Op == "test" && op.Path != "/metadata/resourceVersion" {
			out = append(out, op)
		}
	}
	return out
}
