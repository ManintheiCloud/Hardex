# Roadmap

Roadmap items are development objectives, not completed or guaranteed features. Status as of v0.2.0-dev.

## Phase I — Foundation

- [x] Define project architecture and technical requirements — [docs/architecture.md](docs/architecture.md), [ADRs](docs/adr/)
- [x] Establish the initial threat model — [docs/threat-model.md](docs/threat-model.md)
- [ ] Define supported Kubernetes versions and environments — *proposed:* the three most recent upstream minor releases; kubeadm-style static pods for control-plane checks
- [x] Build the initial cluster assessment framework — `core/assessment`, `core/resource`, 46 rules
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

- [ ] Configuration drift detection (scheduled scans + `verification.Compare`)
- [ ] Recurring posture assessments
- [ ] Historical assessment comparisons beyond two reports
- [ ] Security event reporting integrations
- [ ] Expand workload and network analysis (CNI-specific policies, ingress controllers, admission webhook configuration)
- [ ] Out-of-tree, community-maintained rule modules

## Phase IV — Advanced Security Engineering

- [ ] Admission-control integration running the same rules at admission time
- [ ] Cross-cluster security analysis
- [ ] Supply-chain evaluation (signatures, provenance, vulnerability data)
- [ ] Privilege-escalation path analysis across RBAC, workloads and nodes
- [ ] Posture scoring and evidence reporting
- [ ] Performance validation across diverse environments
