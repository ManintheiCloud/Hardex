# Baselines, profiles and guidance mappings

## Profiles

| Profile | Rules | Intent |
|---|---|---|
| `minimal` | 16 | Direct paths to node or cluster compromise. Every finding is incident-grade. Use as a first CI gate. |
| `baseline` (default) | 34 | Broadly applicable hardening most workloads meet without application changes. |
| `restricted` | 46 (all) | Defence in depth; PSS Restricted for workloads. Expect application changes. |

Profiles are nested (`minimal ⊂ baseline ⊂ restricted`); a test enforces this, and that `restricted` contains every rule. The files live in [`baselines/profiles/`](../baselines/profiles/) and are embedded into the binary. A custom profile is any YAML file of the same shape, passed as `--profile ./my-profile.yaml`.

## Mapping policy

> An imprecise citation that is correct is better than a precise one that is wrong.

| Framework | Cited at | Status |
|---|---|---|
| Kubernetes Pod Security Standards | Individual control (e.g. "Baseline: Host Namespaces") | Verified against the published standard. HX-WL rules cover every Baseline and Restricted control. |
| NSA/CISA Kubernetes Hardening Guidance v1.2 | Section | Section-level; item-level mapping is a Phase I task. |
| CIS Kubernetes Benchmark | Section (e.g. §5.1 RBAC and Service Accounts) | Section-level only. Item numbers change between benchmark versions, and item-level mappings must be checked against a specific licensed version before being published. |
| NIST SP 800-190 | Not yet cited | Planned. |

## Pod Security Standards coverage

| PSS level | Control | Hardex rule |
|---|---|---|
| Baseline | HostProcess | HX-WL-020 |
| Baseline | Host Namespaces | HX-WL-002 |
| Baseline | Privileged Containers | HX-WL-001 |
| Baseline | Capabilities | HX-WL-006 |
| Baseline | HostPath Volumes | HX-WL-003 |
| Baseline | Host Ports | HX-WL-014 |
| Baseline | AppArmor | HX-WL-015 |
| Baseline | SELinux | HX-WL-016 |
| Baseline | /proc Mount Type | HX-WL-017 |
| Baseline | Seccomp | HX-WL-008 (explicit Unconfined → high) |
| Baseline | Sysctls | HX-WL-018 |
| Restricted | Volume Types | HX-WL-019 (+ HX-WL-003) |
| Restricted | Privilege Escalation | HX-WL-004 |
| Restricted | Running as Non-root | HX-WL-005 |
| Restricted | Running as Non-root user | HX-WL-005 (UID 0 → high) |
| Restricted | Seccomp | HX-WL-008 (unset → medium) |
| Restricted | Capabilities | HX-WL-007 |

Differences from the in-cluster `PodSecurity` admission controller, by design:

- Hardex places some Restricted controls in its `baseline` profile (e.g. seccomp) because NSA/CISA and CIS recommend them broadly.
- Hardex additionally reports controls outside PSS (read-only root filesystem, resource limits, image references, token automount).
- Hardex skips control-plane static pods in workload rules unless `--include-system` is given; those pods are assessed by HX-CP rules instead.

## Contributing a mapping

A mapping change must state the framework version and the exact control, and should be reviewed by a second maintainer against the source document. See [CONTRIBUTING.md](../CONTRIBUTING.md).
