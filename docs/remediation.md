# Remediation

Hardex can propose, apply, verify and undo fixes. Everything is a dry run unless you explicitly ask otherwise. Design: [ADR 0003](adr/0003-assessment-before-remediation.md), [ADR 0005](adr/0005-remediation-engine.md).

## Plan fixes for manifests

```sh
hardex fix ./k8s                          # print the plan and predicted result
hardex fix ./k8s --out ./k8s-fixed        # also write patched manifests + plan.json
hardex fix ./k8s --rules HX-WL-004,HX-WL-008 --max-risk low
```

`--out` never touches your input files. Patched objects are written one per file; comments and field order are not preserved, so diff them against your originals and merge.

To keep your manifests exactly as they are, write a **Kustomize overlay** instead:

```sh
hardex fix ./k8s --out ./hardening --kustomize
# edit hardening/kustomization.yaml: uncomment "- ../base" and point it at your manifests
kubectl kustomize ./hardening | hardex scan -     # verify before applying
```

The overlay contains one JSON 6902 patch per object (including the guarding `test` operations, so Kustomize fails loudly if the base no longer matches what Hardex assessed) and any new objects such as default-deny NetworkPolicies. CI verifies overlays end to end with real Kustomize (`make kustomize-check`).

## Fix a live cluster

```sh
hardex fix --cluster                                   # dry run against the cluster
hardex fix --cluster --rules HX-WL-004,HX-WL-008 --apply
```

Applying requires `--rules` and an interactive `yes` (or `--yes` in automation). Hardex then:

1. writes a backup to `--backup-dir` (default `./hardex-backups`) **before** changing anything;
2. applies each object's patch, guarded by its `resourceVersion` and the values being replaced. The backup is a write-ahead journal: each object is recorded as *attempted*, durably, before its patch is sent, and as *applied* once the API server confirms it;
3. if any patch fails, or the run is interrupted (Ctrl-C, SIGTERM), **rolls back every patch that was or may have been applied** in this run. The rollback runs even though the run was cancelled;
4. re-collects and re-assesses the cluster, and reports what was resolved, introduced or is still present;
5. if that verification fails (a finding at or above `--fail-on` introduced, a targeted finding still present) or cannot run (collection failed or was incomplete), **rolls the changes back** and exits non-zero. `--keep-unverified` keeps them instead.

**Interrupted runs.** If the process dies mid-run (killed, a second Ctrl-C, a crash, a lost connection), the backup still records every attempted change. A patch whose outcome is unknown (attempted but not confirmed, e.g. a request that timed out) is resolved against the live object when you roll back: if Hardex's undo patch applies, the change had landed and is undone; if instead every field the patch touches still has its original value, there is nothing to undo (other updates, such as a controller writing status, do not matter); if neither holds, someone has changed it since, and it is reported, not overwritten.

Undo later with the backup file:

```sh
hardex rollback hardex-backups/hardex-backup-20261019T120000Z.json --cluster
```

It lists what it will restore, including any patches with an unknown outcome. Rollback refuses to run against a different API server than the backup came from, and refuses to overwrite a field that someone changed after Hardex set it.

Writing requires credentials that can `patch` the affected workloads; the read-only `hardex-reader` role is not enough by design. Use a separate, short-lived identity for remediation.

## Available fixes

| Rule | Change | Risk |
|---|---|---|
| HX-WL-001 | `privileged: false` | medium |
| HX-WL-002 | `hostNetwork`/`hostPID`/`hostIPC: false` | high |
| HX-WL-004 | `allowPrivilegeEscalation: false` | low |
| HX-WL-005 | `runAsNonRoot: true` (not when UID 0 is set explicitly) | medium |
| HX-WL-007 | `capabilities.drop: ["ALL"]` | medium |
| HX-WL-008 | `seccompProfile.type: RuntimeDefault` | low (medium if replacing `Unconfined`) |
| HX-WL-009 | `readOnlyRootFilesystem: true` | high |
| HX-WL-013 | `automountServiceAccountToken: false` | medium |
| HX-WL-014 | remove `hostPort` | high |
| HX-WL-015 | `appArmorProfile.type: RuntimeDefault` | medium |
| HX-WL-017 | `procMount: Default` | low |
| HX-NET-001/002 | new default-deny NetworkPolicy (manifest only, never auto-applied) | high |

Everything else needs a human decision — which UID, which image version, which capability, which RBAC grant — and is left to each rule's guidance (`hardex rules <ID>`).

## Risk levels

- **low** — removes something almost no workload uses.
- **medium** — most workloads are unaffected; some will fail to start. Test first.
- **high** — commonly breaks workloads or connectivity. Excluded unless `--max-risk high`, and never applied in bulk.

Pods and Jobs cannot be patched in place; fix their controllers or manifests instead.
