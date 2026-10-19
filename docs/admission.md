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

```sh
kubectl apply -f deploy/hardex-reader.yaml      # namespace and baseline policy
kubectl apply -f deploy/hardex-admission.yaml
kubectl run test --image=nginx --privileged     # in warn mode: admitted with a Hardex warning
```
