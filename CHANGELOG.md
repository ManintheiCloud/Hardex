# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). Before 1.0, minor versions may contain breaking changes.

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
