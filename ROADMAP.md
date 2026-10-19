# Roadmap

Roadmap items are development objectives, not completed or guaranteed features. Status as of v0.4.0-dev.

## Phase I — Foundation

- [x] Define project architecture and technical requirements — [docs/architecture.md](docs/architecture.md), [ADRs](docs/adr/)
- [x] Establish the initial threat model — [docs/threat-model.md](docs/threat-model.md)
- [ ] Define supported Kubernetes versions and environments — *proposed:* the three most recent upstream minor releases; kubeadm-style static pods for control-plane checks
- [x] Build the initial cluster assessment framework — `core/assessment`, `core/resource`, 49 rules
- [x] Develop configuration inspection capabilities — static pods, KubeletConfiguration, workloads, RBAC, network, secrets
- [x] Create the first security baseline — `minimal`, `baseline`, `restricted` profiles; full PSS coverage
- [x] Establish contribution guidelines and development workflows — CONTRIBUTING, CI, templates
- [ ] Item-level mappings for CIS and NSA/CISA, reviewed against named versions
- [ ] Signed releases (checksums, cosign signatures, SLSA provenance, SBOM)
- [ ] Fuzzing of the loader and flag parser (`go test -fuzz`) in CI

## Phase II — Hardening Engine

- [x] Implement prioritized security findings — severity model, deterministic ordering, per-occurrence severity
- [x] Develop policy evaluation mechanisms — profiles, overrides, expiring waivers
- [x] Read-only live-cluster collection (Kubernetes API) as an Inventory source — `hardex scan --cluster`, [ADR 0004](docs/adr/0004-live-cluster-client.md)
- [x] Introduce dry-run remediation (JSON patches per finding) — `hardex fix`, [ADR 0005](docs/adr/0005-remediation-engine.md)
- [x] Build configuration backup and rollback mechanisms — backups before change, automatic rollback on failure, `hardex rollback`
- [x] Implement post-remediation verification — `hardex diff` (fingerprint-based; resolved vs. unverified)
- [x] Establish automated security testing — detection, false-positive, regression suites
- [x] RBAC reachability: effective permissions per workload through bindings and service accounts — HX-RBAC-008
- [ ] Kustomize/Helm-aware remediation output (preserve comments and layout)
- [ ] Kubelet configuration collection from live nodes without `nodes/proxy`

## Phase III — Continuous Protection

- [x] Configuration drift detection — `hardex monitor`, against the previous run or an approved `--baseline` ([ADR 0006](docs/adr/0006-continuous-monitoring.md))
- [x] Recurring posture assessments — `monitor --interval`, `monitor --once` for cron, `deploy/hardex-monitor.yaml`
- [x] Historical assessment comparisons beyond two reports — `scan --history`, `hardex history`
- [x] Security event reporting integrations — JSON Lines, HMAC-signed webhooks, Slack format
- [x] Expand analysis: Ingress TLS (HX-NET-005), fail-open admission webhooks (HX-CP-009)
- [ ] Expand analysis: CNI-specific policies (Cilium, Calico), ingress controller configuration, mutating webhooks
- [x] Out-of-tree, community-maintained rule modules — declarative YAML modules ([ADR 0007](docs/adr/0007-declarative-rule-modules.md))

## Phase IV — Advanced Security Engineering

- [x] Admission-control integration running the same rules at admission time — `hardex admission` ([ADR 0008](docs/adr/0008-admission-webhook.md))
- [x] Cross-cluster security analysis — `hardex fleet`, `hardex compare`
- [ ] Supply-chain evaluation: image signature and provenance verification (Sigstore), vulnerability data. Registry allow-lists are possible today with rule modules.
- [x] Privilege-escalation path analysis across RBAC, workloads and nodes — HX-PATH-001
- [x] Posture scoring and evidence reporting — `hardex report` ([ADR 0009](docs/adr/0009-posture-scoring.md))
- [x] Performance validation — synthetic 16k-object scale gate in CI, benchmarks ([docs/performance.md](docs/performance.md))
- [ ] Performance validation on real large clusters (community reports welcome)

## Beyond Phase IV

- [ ] Signed releases (checksums, cosign signatures, SLSA provenance, SBOM) and a published container image
- [ ] Image signature/provenance verification and vulnerability data
- [ ] CNI-specific network policy support (Cilium, Calico)
- [ ] Kustomize/Helm-aware remediation output
- [ ] Item-level CIS and NSA/CISA mappings reviewed against named versions
- [ ] Node-affinity-aware attack paths; cloud IAM (IRSA, Workload Identity) in reachability
