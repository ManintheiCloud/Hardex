# Admission control

`hardex admission` is a validating admission webhook: the same rules that run in CI and in scheduled scans are applied by the API server at the moment an object is created or updated. Design: [ADR 0008](adr/0008-admission-webhook.md).

## Modes

| `--mode` | Effect |
|---|---|
| `warn` (default) | Every request is admitted; findings are returned to the client as warnings (`kubectl` prints them). Use this to roll out. |
| `enforce` | Requests with active findings at or above `--deny-at` (default `high`) are rejected with the findings in the message; lower findings become warnings. Requests that cannot be evaluated are **rejected** (fail closed). |
| `audit` | Every request is admitted silently; decisions are only logged. |

Every decision is logged to stdout as one JSON line (request UID, user, operation, kind, namespace, name, dry-run flag, mode, decision, rule IDs).

## What runs at admission

The webhook sees one object at a time, so rules whose verdict depends on other objects do not run there: default-deny NetworkPolicy checks (HX-NET-001/002), resource-limit defaults from LimitRanges (HX-WL-010), service account automount (HX-WL-013), RBAC reachability (HX-RBAC-008) and attack paths (HX-PATH-001). They remain in `scan` and `monitor`. Everything else in the selected `--profile` runs, plus `--module` rules. Waivers in `--config` apply, so an accepted risk is accepted everywhere.

## Deploy

[`deploy/hardex-admission.yaml`](../deploy/hardex-admission.yaml) (requires cert-manager):

- two replicas spread across nodes, a PodDisruptionBudget, no service account token, Pod Security `restricted`-compatible settings;
- serving certificate from cert-manager, **reloaded automatically** when rotated (a broken rotation keeps serving the last good certificate);
- `failurePolicy: Fail` (see HX-CP-009), `timeoutSeconds: 5`, and a namespace selector excluding `kube-system`, `hardex` and `cert-manager` so the webhook and its certificate can always be recovered;
- guards Pods, workload controllers, Services, ServiceAccounts, RBAC objects and Ingresses on CREATE and UPDATE.

Roll out in `warn` mode, review the warnings developers see and the decision log, add waivers where risk is accepted, then switch to `--mode=enforce`.

### Before enforcing

Enforce mode applies to everything outside the excluded namespaces, including platform components that legitimately need privileges and create pods on their own. The end-to-end test shows the common case: kind's local-path storage provisioner prepares each volume with a root `hostPath` helper pod in `local-path-storage`, so with the shipped exclusions, **enforce mode stops PersistentVolumeClaims from being provisioned**. Other storage drivers, CNI and CSI node agents, and GPU or monitoring agents behave similarly.

Before switching to `--mode=enforce`:

1. Run `hardex admission --preflight --cluster` (same `--profile`, `--deny-at`, `--config` and `--exclude-namespaces` as the webhook). It evaluates every existing object exactly as the webhook would and lists, by namespace, what enforce mode would reject — a rejected controller can no longer be updated or create pods. It exits 1 if anything would be rejected, so it can gate the switch in CI.
2. Run in `warn` mode for long enough to see every controller's pods, including ones that only appear on demand (such as provisioner helpers, which preflight cannot see), and check the decision log for denials-to-be.
3. Add the namespaces of trusted platform components to the webhook's `namespaceSelector` exclusion list (`values: [kube-system, hardex, cert-manager, local-path-storage, …]`), or waive their specific findings in the policy configuration.
4. Switch to enforce and keep watching the decision log.

```sh
kubectl apply -f deploy/hardex-reader.yaml      # namespace and baseline policy
kubectl apply -f deploy/hardex-admission.yaml
kubectl run test --image=nginx --privileged     # in warn mode: admitted with a Hardex warning
```
