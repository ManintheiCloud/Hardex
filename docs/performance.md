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
