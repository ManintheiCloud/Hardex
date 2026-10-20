# Baselines, profiles and guidance mappings

## Profiles

| Profile | Rules | Intent |
|---|---|---|
| `minimal` | 17 | Direct paths to node or cluster compromise. Every finding is incident-grade. Use as a first CI gate. |
| `baseline` (default) | 39 | Broadly applicable hardening most workloads meet without application changes. |
| `restricted` | 51 (all) | Defence in depth; PSS Restricted for workloads. Expect application changes. |

Profiles are nested (`minimal ⊂ baseline ⊂ restricted`); a test enforces this, and that `restricted` contains every rule. The files live in [`baselines/profiles/`](../baselines/profiles/) and are embedded into the binary. A custom profile is any YAML file of the same shape, passed as `--profile ./my-profile.yaml`.

## Mapping policy

> An imprecise citation that is correct is better than a precise one that is wrong.

| Framework | Cited at | Status |
|---|---|---|
| Kubernetes Pod Security Standards | Individual control (e.g. "Baseline: Host Namespaces") | Verified against the published standard. HX-WL rules cover every Baseline and Restricted control. |
| CIS Kubernetes Benchmark **v2.0** (Kubernetes 1.34–1.35) | Individual item (e.g. 5.2.2) | Item-level. Items and titles were taken from kube-bench's open-source encoding of the benchmark (`cfg/cis-2.0`); a test checks every cited item exists. Rules with no corresponding item cite none. |
| NSA/CISA Kubernetes Hardening Guidance **v1.2** (August 2022) | Exact section heading (e.g. "Kubernetes Pod security › Pod security enforcement") | Section-level, using the document's own table of contents; the guidance has no numbered items. |
| NIST SP 800-190 | Not yet cited | Planned. |

**Newer CIS versions.** CIS has since published Kubernetes Benchmark v2.0.1 (June 2026, Kubernetes 1.34–1.35) and v2.1.0 (by October 2026). Hardex's mappings have not been reviewed against either: their text is available only through CIS WorkBench, and kube-bench has no encoding of them yet. Item numbers usually carry over between point releases, but treat the v2.0 citations as exactly that until a review lands. (Re-checked 2026-10-20: all 42 cited v2.0 items and titles still match kube-bench's `cfg/cis-2.0`.)

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
- Hardex skips workloads in `kube-system` (kube-proxy, the CNI, CoreDNS, control-plane static pods) in workload rules unless `--include-system` is given: they need host access by design and are not changed by cluster users. Control-plane static pods are assessed by the HX-CP rules either way. RBAC objects created by Kubernetes (`system:`) and kubeadm (`kubeadm:`) are likewise skipped.

Mappings live in one table, [`baselines/mappings.go`](../baselines/mappings.go), rather than in each rule, so they can be reviewed together whenever a benchmark version changes.

## CIS v2.0 coverage

| CIS item | Hardex rules |
|---|---|
| 1.2.1 Ensure that the --anonymous-auth argument is set to false | HX-CP-001 |
| 1.2.3 Ensure that the --DenyServiceExternalIPs is set | HX-NET-004 |
| 1.2.5 Ensure that the --kubelet-certificate-authority argument is set as appropriate | HX-CP-008 |
| 1.2.6 Ensure that the --authorization-mode argument is not set to AlwaysAllow | HX-CP-002 |
| 1.2.8 Ensure that the --authorization-mode argument includes RBAC | HX-CP-002 |
| 1.2.10 Ensure that the admission control plugin AlwaysAdmit is not set | HX-CP-005 |
| 1.2.14 Ensure that the admission control plugin NodeRestriction is set | HX-CP-005 |
| 1.2.15 Ensure that the --profiling argument is set to false | HX-CP-004 |
| 1.2.16 Ensure that the --audit-log-path argument is set | HX-CP-003 |
| 1.2.23 Ensure that the --etcd-certfile and --etcd-keyfile arguments are set as appropriate | HX-CP-006 |
| 1.2.26 Ensure that the --etcd-cafile argument is set as appropriate | HX-CP-006 |
| 1.2.27 Ensure that the --encryption-provider-config argument is set as appropriate | HX-CP-007 |
| 1.3.2 Ensure that the --profiling argument is set to false | HX-CP-004 |
| 1.4.1 Ensure that the --profiling argument is set to false | HX-CP-004 |
| 2.1 Ensure that the --cert-file and --key-file arguments are set as appropriate | HX-CP-006 |
| 2.2 Ensure that the --client-cert-auth argument is set to true | HX-CP-006 |
| 2.3 Ensure that the --auto-tls argument is not set to true | HX-CP-006 |
| 2.5 Ensure that the --peer-client-cert-auth argument is set to true | HX-CP-006 |
| 2.6 Ensure that the --peer-auto-tls argument is not set to true | HX-CP-006 |
| 3.2.1 Ensure that a minimal audit policy is created | HX-CP-003 |
| 4.2.1 Ensure that the --anonymous-auth argument is set to false | HX-NODE-001 |
| 4.2.2 Ensure that the --authorization-mode argument is not set to AlwaysAllow | HX-NODE-002 |
| 4.2.4 Verify that if defined, the --read-only-port argument is set to 0 | HX-NODE-003 |
| 5.1.1 Ensure that the cluster-admin role is only used where required | HX-RBAC-002 |
| 5.1.2 Minimize access to secrets | HX-RBAC-003 |
| 5.1.3 Minimize wildcard use in Roles and ClusterRoles | HX-RBAC-001 |
| 5.1.4 Minimize access to create pods | HX-RBAC-006 |
| 5.1.6 Ensure that Service Account Tokens are only mounted where necessary | HX-RBAC-008, HX-WL-013 |
| 5.1.8 Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster | HX-RBAC-004 |
| 5.1.10 Minimize access to the proxy sub-resource of nodes | HX-RBAC-005 |
| 5.1.13 Minimize access to the service account token creation | HX-RBAC-005 |
| 5.2.2 Minimize the admission of privileged containers | HX-WL-001 |
| 5.2.3 Minimize the admission of containers wishing to share the host process ID namespace | HX-WL-002 |
| 5.2.4 Minimize the admission of containers wishing to share the host IPC namespace | HX-WL-002 |
| 5.2.5 Minimize the admission of containers wishing to share the host network namespace | HX-WL-002 |
| 5.2.6 Minimize the admission of containers with allowPrivilegeEscalation | HX-WL-004 |
| 5.2.7 Minimize the admission of root containers | HX-WL-005 |
| 5.2.8 Minimize the admission of containers with the NET_RAW capability | HX-WL-006 |
| 5.2.9 Minimize the admission of containers with capabilities assigned | HX-WL-006, HX-WL-007 |
| 5.2.10 Minimize the admission of Windows HostProcess containers | HX-WL-020 |
| 5.2.11 Minimize the admission of HostPath volumes | HX-WL-003 |
| 5.2.12 Minimize the admission of containers which use HostPorts | HX-WL-014 |
| 5.3.2 Ensure that all Namespaces have NetworkPolicies defined | HX-NET-001, HX-NET-002 |
| 5.4.1 Prefer using Secrets as files over Secrets as environment variables | HX-SEC-002 |
| 5.4.2 Consider external secret storage | HX-SEC-001 |
| 5.6.2 Ensure that the seccomp profile is set to docker/default in your Pod definitions | HX-WL-008 |
| 5.6.3 Apply SecurityContext to your Pods and Containers | HX-WL-009, HX-WL-015, HX-WL-016, HX-WL-017, HX-WL-018 |

## Contributing a mapping

A mapping change must state the framework version and the exact control, and should be reviewed by a second maintainer against the source document. See [CONTRIBUTING.md](../CONTRIBUTING.md).
