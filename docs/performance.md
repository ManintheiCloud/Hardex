# Performance

Hardex is designed to assess large clusters within the time budget of a CI job or a scheduled scan.

## Method

`tests/perf_test.go` generates a synthetic cluster: namespaces each with a default-deny NetworkPolicy, a namespaced Role, and per-workload ServiceAccounts, RoleBindings and Deployments (one in ten privileged), plus 200 ClusterRoles. Every rule of the `restricted` profile runs, including RBAC reachability and attack-path analysis.

```sh
make bench                                  # benchmarks at three sizes
go test -run TestScaleLargeCluster -v ./tests   # the scale gate (skipped with -short)
```

## Results

On a 2-vCPU development machine (Go stable, October 2026); expect similar orders of magnitude elsewhere:

| Objects | Time per full assessment |
|---|---|
| 530 | ~12 ms |
| 3,350 | ~130 ms |
| 15,800 | ~0.9 s |

The scale test fails if ~16,000 objects take longer than 15 seconds, so regressions are caught in CI.

## Design choices that keep it linear

- RBAC bindings are indexed by subject, and each service account's effective permissions are computed once.
- Attack paths are found with one backwards breadth-first search per goal (cluster administrator, node root) over the whole graph, instead of one search per workload. Before this change the same 15,800-object cluster took 35 seconds.
- Live-cluster collection pages through LIST results (500 per page) and skips controller-owned objects, so a Deployment's ReplicaSets and Pods are not assessed three times.

## Real clusters

Synthetic clusters bound the analysis cost; real clusters add API latency, unusual RBAC shapes and CRD volume. `--stats` prints the load and evaluation time and the ten slowest rules to stderr, without any names from the cluster:

```sh
hardex scan --cluster --stats --format json -o report.json
# stats: 15800 objects, load 0s, evaluate 994ms (55 rules)
# stats:   HX-PATH-001       310ms  ...
```

Collection time over the network is the wall-clock time minus the evaluation time. Please share results — fast or slow — with the [performance report](https://github.com/ManintheiCloud/Hardex/issues/new?template=performance.yml) issue template; they are how the targets above are kept honest for real clusters.

## Admission webhook

The webhook is fail-closed with a 5-second timeout (`deploy/hardex-admission.yaml`), so its latency under load matters: a webhook that falls behind makes the API server reject changes. `integrations/admission/load_test.go` measures a full request (decode, evaluate, encode) and runs a concurrent mixed load in CI:

| Object | Size | Time per decision |
|---|---|---|
| Typical pod (compliant or privileged) | < 1 KiB | ~0.1 ms |
| ClusterRole with 2,000 rules | ~160 KiB | ~7 ms |
| Deployment with 40 containers × 300 variables (near the API server's ~1.5 MiB object limit) | ~1.3 MiB | ~35 ms |

Most of the time on large objects is JSON decoding (the AdmissionReview and the object), not rule evaluation. Under 32 concurrent requests on 2 vCPUs — a quarter of them near-maximum Deployments — p50 is ~4 ms and p99 ~1 s; CI fails if p99 exceeds 2 s. One replica with the shipped 1 CPU limit handles typical traffic with a wide margin; the shipped two replicas (and a PodDisruptionBudget) are for availability. Raise the CPU limit if your cluster routinely admits very large objects in bursts.

Measured while writing this: HX-SEC-002's credential-name check used an unanchored case-insensitive regular expression, a third of the time on objects with thousands of environment variables; it is now a set of substring tests, verified equivalent on 20,000 generated names.
