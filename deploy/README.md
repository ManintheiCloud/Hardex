# Deploying Hardex in a cluster

- `hardex-reader.yaml` — a least-privilege, read-only ClusterRole for `hardex scan --cluster`, a `hardex` namespace (Pod Security `restricted`), a ServiceAccount, its binding, and a NetworkPolicy allowing only API-server and DNS egress. It grants **no** access to Secrets, `pods/exec`, `nodes/proxy` or any write verb.
- `hardex-cronjob.yaml` — an example nightly in-cluster scan writing a JSON report to the job log.
- `hardex-monitor.yaml` — hourly `hardex monitor --once` with history on a PersistentVolumeClaim and a signed webhook (see [docs/monitoring.md](../docs/monitoring.md)).

Scanning these manifests with `--profile restricted` reports only expected findings: HX-WL-013 (the scanner needs its API token) and HX-WL-012 (replace the example image tags with digests).

Remediation (`hardex fix --apply`) is not meant to run from this CronJob: it needs write access and a human decision about which rules to apply.
