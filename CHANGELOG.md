# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). Before 1.0, minor versions may contain breaking changes.

## [Unreleased] — 0.4.0 (Phase IV: Advanced Security Engineering)

### Added
- HX-PATH-001: multi-step privilege-escalation paths (container escape, token theft from co-located pods, workload creation, exec, token minting, RBAC escalation) to cluster administrator or node root.
- `hardex admission`: validating admission webhook running the same rules (warn, enforce fail-closed, audit), certificate hot-reload, decision log; `deploy/hardex-admission.yaml`.
- `hardex report` and `scan --format html|markdown`: posture score, grade, framework evidence, accepted risks, and the SHA-256 of the source report.
- `hardex fleet` and `hardex compare`: multi-cluster assessment and a matrix of inconsistent controls.
- Scale test (~16k objects) and benchmarks; `make bench`.

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
