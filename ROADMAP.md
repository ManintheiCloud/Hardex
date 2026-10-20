# Roadmap

Roadmap items are development objectives, not completed or guaranteed features. Status as of v0.8.6. Every Phase I–IV objective is complete; ongoing work is listed at the end.

## Phase I — Foundation

- [x] Define project architecture and technical requirements — [docs/architecture.md](docs/architecture.md), [ADRs](docs/adr/)
- [x] Establish the initial threat model — [docs/threat-model.md](docs/threat-model.md)
- [x] Define supported Kubernetes versions and environments — [docs/compatibility.md](docs/compatibility.md)
- [x] Build the initial cluster assessment framework — `core/assessment`, `core/resource`, 55 rules
- [x] Develop configuration inspection capabilities — static pods, KubeletConfiguration, workloads, RBAC, network, secrets
- [x] Create the first security baseline — `minimal`, `baseline`, `restricted` profiles; full PSS coverage
- [x] Establish contribution guidelines and development workflows — CONTRIBUTING, CI, templates
- [x] Item-level mappings for CIS and NSA/CISA, reviewed against named versions — CIS Kubernetes Benchmark v2.0 items and NSA/CISA v1.2 sections per rule ([docs/baselines.md](docs/baselines.md))
- [x] Signed releases (checksums, cosign signatures, SLSA provenance, SBOM)
- [x] Fuzzing in CI — manifest loader, policy config, rule modules, admission requests, control-plane flags

## Phase II — Hardening Engine

- [x] Implement prioritized security findings — severity model, deterministic ordering, per-occurrence severity
- [x] Develop policy evaluation mechanisms — profiles, overrides, expiring waivers
- [x] Read-only live-cluster collection (Kubernetes API) as an Inventory source — `hardex scan --cluster`, [ADR 0004](docs/adr/0004-live-cluster-client.md)
- [x] Introduce dry-run remediation (JSON patches per finding) — `hardex fix`, [ADR 0005](docs/adr/0005-remediation-engine.md)
- [x] Build configuration backup and rollback mechanisms — backups before change, automatic rollback on failure, `hardex rollback`
- [x] Implement post-remediation verification — `hardex diff` (fingerprint-based; resolved vs. unverified)
- [x] Establish automated security testing — detection, false-positive, regression suites
- [x] RBAC reachability: effective permissions per workload through bindings and service accounts — HX-RBAC-008
- [x] Kustomize-aware remediation output — `hardex fix --kustomize` (patch overlays; your manifests stay untouched)
- [x] Kubelet configuration collection from live nodes without `nodes/proxy` — `hardex scan --node` with flag overrides, `deploy/hardex-node.yaml` ([docs/node-scanning.md](docs/node-scanning.md))

## Phase III — Continuous Protection

- [x] Configuration drift detection — `hardex monitor`, against the previous run or an approved `--baseline` ([ADR 0006](docs/adr/0006-continuous-monitoring.md))
- [x] Recurring posture assessments — `monitor --interval`, `monitor --once` for cron, `deploy/hardex-monitor.yaml`
- [x] Historical assessment comparisons beyond two reports — `scan --history`, `hardex history`
- [x] Security event reporting integrations — JSON Lines, HMAC-signed webhooks, Slack format
- [x] Expand analysis: Ingress TLS (HX-NET-005), fail-open admission webhooks (HX-CP-009)
- [x] Expand analysis: Cilium and Calico policies in default-deny detection; ingress-nginx snippets (HX-NET-006) and the retired ingress-nginx controller (HX-NET-007)
- [x] Expand analysis: mutating webhooks (HX-CP-009, HX-CP-010), Gateway API (HX-NET-008, HX-NET-009)
- [x] Out-of-tree, community-maintained rule modules — declarative YAML modules ([ADR 0007](docs/adr/0007-declarative-rule-modules.md))

## Phase IV — Advanced Security Engineering

- [x] Admission-control integration running the same rules at admission time — `hardex admission` ([ADR 0008](docs/adr/0008-admission-webhook.md))
- [x] Cross-cluster security analysis — `hardex fleet`, `hardex compare`
- [x] Supply-chain evaluation: digest resolution and cosign key-based signature verification (`hardex images`); registry allow-lists via rule modules
- [x] Keyless (Fulcio/Rekor) and Sigstore-bundle verification inside Hardex, offline against the trusted root; vulnerability data from SBOM attestations via OSV — `hardex images`, `hardex verify-blob` ([docs/image-verification.md](docs/image-verification.md))
- [x] Privilege-escalation path analysis across RBAC, workloads, node placement and cloud identities — HX-PATH-001, HX-PATH-002
- [x] Posture scoring and evidence reporting — `hardex report` ([ADR 0009](docs/adr/0009-posture-scoring.md))
- [x] Performance validation — synthetic 16k-object scale gate in CI, benchmarks ([docs/performance.md](docs/performance.md))
- [x] Performance validation on real clusters: `scan --stats` and a [performance report](https://github.com/ManintheiCloud/Hardex/issues/new?template=performance.yml) template ([docs/performance.md](docs/performance.md))

## Beyond Phase IV

- [x] Signed releases (checksums, keyless cosign signatures, SLSA provenance, SBOM) and a published multi-arch container image
- [x] Keyless signature verification and vulnerability data in `hardex images`
- [x] Item-level CIS and NSA/CISA mappings reviewed against named versions
- [x] Node-affinity-aware attack paths; cloud IAM (IRSA, GKE and Azure Workload Identity) in reachability

## Ongoing

These are continuing efforts rather than milestones:

- Collect real-cluster performance reports and keep the scale targets honest. (Functional behaviour on a real cluster is tested on every push; see README, Security validation.)
- Re-review framework mappings when CIS or NSA/CISA publish new versions; refresh the embedded Sigstore trusted root (checked weekly and before every release).

Done since 0.6.0: Rekor v2 entries and the Sigstore conformance suite in keyless verification; node-aware co-location from Node labels and taints; cloud role permissions from IAM exports (`--cloud-iam`). Preferred and inter-pod affinity are deliberately not modelled: they do not prevent two pods from sharing a node, so they cannot break an attack path.
