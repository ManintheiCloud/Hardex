# ADR 0005: Remediation as guarded, reversible JSON patches

- Status: accepted
- Date: 2026-10-19
- Implements the constraints of [ADR 0003](0003-assessment-before-remediation.md)

## Decision

1. **Fixes are data.** A fixer maps a finding to field assignments (or, for missing NetworkPolicies, a new object). The engine turns assignments into RFC 6902 operations, combining all fixes for one object against its progressively patched state so that fixes never overwrite each other.
2. **Every replaced value is guarded.** Each `replace`/`remove` is preceded by a `test` of the value it replaces. Against a live cluster the patch also tests `metadata.resourceVersion`, so a patch computed from a stale read fails instead of overwriting newer state.
3. **Every patch has an inverse**, computed at planning time and itself guarded by tests on the values Hardex set. Rollback therefore refuses to undo a field someone else has since changed. Planning self-checks that the patch applies and the inverse restores the original exactly; a failure is treated as a bug and aborts.
4. **Risk is explicit.** Each fix is rated low, medium or high by its likelihood of disrupting the workload. `--max-risk` defaults to medium; high-risk fixes are listed but excluded unless requested.
5. **Dry-run is the default.** `hardex fix` prints the plan and a *predicted* result (a re-assessment of the patched objects). `--out` writes patched manifests to a new directory; inputs are never modified.
6. **Applying needs explicit authorization:** `--cluster --apply`, an explicit `--rules` list (no "fix everything"), and an interactive `yes` (or `--yes`).
7. **Backup before change, all-or-nothing.** The backup file (original objects, patches, inverses) is written before the first patch and updated after each. If any patch fails, every patch already applied in the run is rolled back automatically.
8. **Success is verified, not assumed.** After applying, the cluster is re-collected and re-assessed; the run reports findings resolved, introduced and still present, and exits non-zero on regressions or unresolved targets.
9. **Some changes are never applied automatically:** new objects (NetworkPolicies), RBAC, control-plane and node configuration, and immutable kinds (Pods, Jobs). These are emitted for review or left to guidance.

## Consequences

- Remediated manifests written with `--out` lose comments and field order; users diff and merge them. Kustomize/Helm-aware output is future work.
- Pod-template changes trigger rollouts; this is intended and is why risk ratings and per-rule selection exist.
