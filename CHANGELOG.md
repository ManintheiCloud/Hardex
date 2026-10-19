# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). Before 1.0, minor versions may contain breaking changes.

## [Unreleased]

### Added
- Assessment engine with fail-safe rule evaluation (rule failures → exit code 3).
- 45 rules: workloads (HX-WL, full Pod Security Standards coverage), secrets (HX-SEC), RBAC (HX-RBAC), networking (HX-NET), control plane (HX-CP), kubelet (HX-NODE).
- `minimal`, `baseline` and `restricted` profiles.
- Policy configuration with justified rule disabling, severity overrides and expiring waivers.
- Text, JSON (`hardex.dev/report/v1alpha1`) and SARIF 2.1.0 output.
- `hardex diff` for remediation verification.
- Hardened input handling: size limits, alias-bomb protection, duplicate-key rejection, YAML 1.1 boolean compatibility with Kubernetes (prevents `privileged: yes` evasion), terminal-escape sanitisation.
