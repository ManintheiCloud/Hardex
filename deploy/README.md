# Deploying Hardex in a cluster

- `hardex-reader.yaml` — a least-privilege, read-only ClusterRole for `hardex scan --cluster`, a `hardex` namespace (Pod Security `restricted`), a ServiceAccount, its binding, and a NetworkPolicy allowing only API-server and DNS egress. It grants **no** access to Secrets, `pods/exec`, `nodes/proxy` or any write verb.
- `hardex-cronjob.yaml` — an example nightly in-cluster scan writing a JSON report to the job log.
- `hardex-admission.yaml` — the validating admission webhook (cert-manager, two replicas, PDB, fail-closed configuration); starts in `warn` mode. See [docs/admission.md](../docs/admission.md).
- `hardex-node.yaml` — a DaemonSet that assesses each node's kubelet configuration (with flag overrides) and static pod manifests from read-only file mounts, without `nodes/proxy`. See [docs/node-scanning.md](../docs/node-scanning.md). Expected findings: HX-WL-003 (high: three host files mounted read-only) and HX-WL-005 (it reads 0600 files as root); nothing critical, which the end-to-end test enforces.
- `hardex-monitor.yaml` — hourly `hardex monitor --once` with history on a PersistentVolumeClaim and a signed webhook (see [docs/monitoring.md](../docs/monitoring.md)).

Scanning these manifests with `--profile restricted` reports only expected findings: HX-WL-013 (the scanner needs its API token), HX-WL-012 (replace the example image tags with digests), and for the node DaemonSet HX-WL-003 and HX-WL-005 as described above.

Remediation (`hardex fix --apply`) is not meant to run from this CronJob: it needs write access and a human decision about which rules to apply.
