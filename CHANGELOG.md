# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). Before 1.0, minor versions may contain breaking changes.

## [Unreleased] — 0.2.0 (Phase II: Hardening Engine)

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
