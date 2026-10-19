# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). Before 1.0, minor versions may contain breaking changes.

## 0.7.0 — 2026-10-19

### Added
- Keyless verification supports Rekor v2 (tile-based) log entries: the entry is recomputed from the bundle and proven against the log's signed checkpoint, with the signing time from a timestamp authority. `intoto` 0.0.2 entries (older attestations) are supported too.
- The Sigstore project's client conformance suite runs in Hardex's tests; every certificate-based case passes.
- Attack paths use Node objects when present: pods are placed on exactly the nodes their `nodeName`, `nodeSelector`, required node affinity (all operators, ORed terms) and tolerations allow, so control-plane and dedicated-pool taints separate workloads. Live scans collect nodes (labels and taints only); if `nodes` cannot be listed the scan stays complete and warns.

### Changed
- Bundles v0.2 and later must carry an inclusion proof (a signed entry timestamp alone is accepted only in v0.1 bundles, as the Sigstore specification requires); bundles whose certificate chain includes a root certificate are rejected; trusted roots must give a start for every validity period.
- `deploy/hardex-reader.yaml` grants `get`/`list` on `nodes` (not `nodes/proxy`).

## 0.6.0 — 2026-10-19

### Added
- Keyless Sigstore verification inside Hardex, completely offline: Fulcio certificate chain at a verified signing time, embedded SCT, signer identity and OIDC issuer policy, message and DSSE signatures, Rekor entry consistency, signed entry timestamps, inclusion proofs against signed checkpoints, and RFC 3161 timestamps. The Sigstore public-good trusted root is embedded; `--trusted-root` overrides it.
  - `hardex images --certificate-identity[-regexp] --certificate-oidc-issuer[-regexp]`: verifies bundles attached as OCI referrers (cosign v3, GitHub attestations; referrers API or tag fallback) and cosign's legacy keyless format.
  - `hardex verify-blob`: verifies a file against a Sigstore bundle (for example a Hardex release's `SHA256SUMS`).
- `hardex images --vulns`: known vulnerabilities (OSV) for the packages in each image's SBOM attestation; `--fail-on-vulns`. `--image` checks references given on the command line.
- `hardex scan --node`: kubelet configuration (with security-relevant command-line flag overrides) and static pod manifests read on the node, without `nodes/proxy`; `--node-root`, `--node-name`, `--kubelet-config`, `--every`. `deploy/hardex-node.yaml`: a read-only, tokenless, network-isolated DaemonSet.
- `hardex scan --stats`: load and evaluation time and the slowest rules; a performance-report issue template.
- Attack paths follow node placement: token theft through a node is modelled only between pods whose `nodeSelector`, `nodeName` or required node affinity let them share a node. Cloud workload identities (EKS IRSA, GKE Workload Identity, Azure Workload Identity) are path goals.
- HX-PATH-002: workloads whose token assumes a cloud identity.
- HX-CP-010: admission webhooks served by URL from outside the cluster (high for mutating webhooks). HX-CP-009 now covers mutating webhooks.
- HX-NET-008: Gateway API listeners serving plain HTTP with no TLS listener for the hostname. HX-NET-009: Gateway listeners accepting routes from every namespace.
- Item-level framework mappings: every rule references CIS Kubernetes Benchmark v2.0 items and NSA/CISA Kubernetes Hardening Guidance v1.2 sections; a CIS coverage table in docs/baselines.md.
- Live scans collect `MutatingWebhookConfiguration` and Gateway API `Gateway` objects; the reader role grants them.
- CI verifies the latest published image and release with the code under test; bundle and timestamp parsers are fuzzed.

### Changed
- The roadmap's phase I–IV objectives are complete; ongoing work is listed separately.

## 0.5.0 — 2026-10-19

### Added
- Default-deny detection (HX-NET-001/002) understands Cilium (`CiliumNetworkPolicy`, `CiliumClusterwideNetworkPolicy`) and Calico (`NetworkPolicy`, `GlobalNetworkPolicy`) policies; live scans collect them when installed.
- HX-NET-006: Ingresses using ingress-nginx snippet annotations (CVE-2021-25742 class).
- HX-NET-007: the retired ingress-nginx controller (no security fixes since March 2026).
- `hardex fix --kustomize`: remediation as a Kustomize overlay of JSON 6902 patches, verified end to end with real Kustomize in CI.
- Fuzzing in CI for the manifest loader, policy configuration, rule modules, admission requests and control-plane flags.
- Compatibility policy: supported Kubernetes versions, environments and platforms (docs/compatibility.md).

### Fixed
- A malformed configuration could crash Hardex through a panic in the YAML library (found by fuzzing). All YAML decoding now converts library panics into errors.

## 0.4.0 (Phase IV: Advanced Security Engineering) — 2026-10-19

### Added
- HX-PATH-001: multi-step privilege-escalation paths (container escape, token theft from co-located pods, workload creation, exec, token minting, RBAC escalation) to cluster administrator or node root.
- `hardex admission`: validating admission webhook running the same rules (warn, enforce fail-closed, audit), certificate hot-reload, decision log; `deploy/hardex-admission.yaml`.
- `hardex report` and `scan --format html|markdown`: posture score, grade, framework evidence, accepted risks, and the SHA-256 of the source report.
- `hardex fleet` and `hardex compare`: multi-cluster assessment and a matrix of inconsistent controls.
- Scale test (~16k objects) and benchmarks; `make bench`.
- `hardex images`: resolve image tags to digests with pin suggestions; verify cosign key-based signatures (`--key`, `--require-signature`, `--require-digest`); minimal registry client with digest-verified content.
- Release pipeline: multi-platform binaries, SHA256SUMS signed keylessly with Sigstore, SPDX SBOM, SLSA build-provenance attestations, and a signed multi-arch image at `ghcr.io/manintheicloud/hardex`.

### Changed
- RBAC bindings are indexed by subject and attack paths use one backwards search per goal: a 15,800-object assessment went from 35 s to under 1 s.
- Rules declare `NeedsInventory` when their verdict depends on other objects.

## 0.3.0 (Phase III: Continuous Protection)

### Added
- `scan --history DIR` and `hardex history`: recorded assessments and trend tables.
- `hardex monitor`: repeated (`--interval`) or one-shot (`--once`) assessment with drift detection against the previous run or an approved `--baseline`; events as JSON Lines and HTTPS webhooks signed with HMAC-SHA256 (generic or Slack format).
- Declarative rule modules (`--module`), with an example organisation policy.
- HX-NET-005 (Ingress without TLS) and HX-CP-009 (fail-open validating webhooks); Ingresses and ValidatingWebhookConfigurations are now collected from live clusters.
- `deploy/hardex-monitor.yaml` for hourly in-cluster monitoring.

### Fixed
- HX-CP-005 reported two different problems with the same fingerprint, so `diff` could conflate them. Findings now have distinct paths, and the engine guarantees unique fingerprints.
- CI: removed the workflow CodeQL job that conflicted with GitHub's default setup; build and scan with the latest stable Go.

## 0.2.0 (Phase II: Hardening Engine)

### Added
- `hardex scan --cluster` / `--in-cluster`: read-only live-cluster assessment with a dependency-free API client (kubeconfig tokens, client certificates, exec plugins, in-cluster service accounts). Secrets are never read; unreadable resources make the assessment incomplete unless `--allow-partial`.
- `deploy/hardex-reader.yaml` least-privilege role and `deploy/hardex-cronjob.yaml` example.
- HX-RBAC-008: RBAC reachability — workloads whose service account token can read secrets, exec, mint tokens, reach kubelets, create workloads, escalate, impersonate or control everything.
- `hardex fix`: risk-rated remediation plans with predicted results; `--out` writes patched manifests and new default-deny NetworkPolicies.
- `hardex fix --cluster --apply`: explicitly authorised, guarded JSON patches with backup, automatic all-or-nothing rollback on failure, and post-change verification.
- `hardex rollback`: undo an apply from its backup file.

## 0.1.0 (Phase I: Foundation)

### Added
- Assessment engine with fail-safe rule evaluation (rule failures → exit code 3).
- 45 rules: workloads (HX-WL, full Pod Security Standards coverage), secrets (HX-SEC), RBAC (HX-RBAC), networking (HX-NET), control plane (HX-CP), kubelet (HX-NODE).
- `minimal`, `baseline` and `restricted` profiles.
- Policy configuration with justified rule disabling, severity overrides and expiring waivers.
- Text, JSON (`hardex.dev/report/v1alpha1`) and SARIF 2.1.0 output.
- `hardex diff` for remediation verification.
- Hardened input handling: size limits, alias-bomb protection, duplicate-key rejection, YAML 1.1 boolean compatibility with Kubernetes (prevents `privileged: yes` evasion), terminal-escape sanitisation.
