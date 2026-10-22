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
| NIST SP 800-190 (September 2017) | Countermeasure section (e.g. "4.4.3 Insecure container runtime configurations") | Section-level, by the document's own numbering and headings; only where the section's text recommends what the rule checks. |

**Newer CIS versions.** CIS has since published Kubernetes Benchmark v2.0.1 (June 2026, Kubernetes 1.34–1.35) and v2.1.0 (by October 2026). Hardex's mappings have not been reviewed against either: their text is available only through CIS WorkBench, and kube-bench has no encoding of them yet. Item numbers usually carry over between point releases, but treat the v2.0 citations as exactly that until a review lands. (Re-checked 2026-10-20: all 42 cited v2.0 items and titles still match kube-bench's `cfg/cis-2.0`.)

## Pod Security Standards coverage

| PSS level | Control | Hardex rule |
|---|---|---|
| Baseline | HostProcess | HX-WL-020 |
| Baseline | Host Namespaces | HX-WL-002 |
| Baseline | Privileged Containers | HX-WL-001 |
| Baseline | Capabilities | HX-WL-006 (names matched exactly, as by PodSecurity: `chown` or `CAP_CHOWN` is not the allowed `CHOWN` → low) |
| Baseline | HostPath Volumes | HX-WL-003 |
| Baseline | Host Ports | HX-WL-014 |
| Baseline | Host Probes / Lifecycle Hooks (v1.34+) | HX-WL-021 (loopback in a hostNetwork pod → low) |
| Baseline | AppArmor | HX-WL-015 |
| Baseline | SELinux | HX-WL-016 |
| Baseline | /proc Mount Type | HX-WL-017 (in a user namespace, `hostUsers: false` → low: Baseline allows it since v1.35, Restricted does not) |
| Baseline | Seccomp | HX-WL-008 (explicit Unconfined → high) |
| Baseline | Sysctls | HX-WL-018 (safe set as of v1.37) |
| Restricted | Volume Types | HX-WL-019 (+ HX-WL-003; image volumes are allowed) |
| Restricted | Privilege Escalation | HX-WL-004 |
| Restricted | Running as Non-root | HX-WL-005 (not reported for `hostUsers: false` pods, as since v1.35; reported for Windows pods too) |
| Restricted | Running as Non-root user | HX-WL-005 (UID 0 → high; not reported for `hostUsers: false` pods) |
| Restricted | Seccomp | HX-WL-008 (unset → medium) |
| Restricted | Capabilities | HX-WL-007 (`drop` must name `ALL` exactly) |

The table follows the standard as of Kubernetes 1.37, checked against the `PodSecurity` admission controller's policy package (`k8s.io/pod-security-admission/policy`), including the user-namespace relaxations that the published page describes on the [user namespaces](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/#integration-with-pod-security-admission-checks) page. CI checks it continuously: [`tools/k8s-diff`](../tools/k8s-diff/README.md) builds thousands of pods near each control's boundary and fails if Hardex and that policy package disagree on any of them, at Baseline or Restricted.

Differences from the in-cluster `PodSecurity` admission controller, by design:

- Hardex places some Restricted controls in its `baseline` profile (e.g. seccomp) because NSA/CISA and CIS recommend them broadly.
- Hardex additionally reports controls outside PSS (read-only root filesystem, resource limits, image references, token automount).
- Hardex skips workloads in `kube-system` (kube-proxy, the CNI, CoreDNS, control-plane static pods) in workload rules unless `--include-system` is given: they need host access by design and are not changed by cluster users. Control-plane static pods are assessed by the HX-CP rules either way. So that anything else placed in `kube-system` stays visible, HX-WL-022 lists every host-access workload there as information, and `hardex monitor` sends an event for each new entry. RBAC objects created by Kubernetes and kubeadm are likewise skipped, but only when they grant no more than their default definition (`kubernetes/rbac/defaults.json`, from the upstream bootstrap policy for 1.34–1.37): a `system:` name or the `rbac-defaults` label alone is not trusted, and a default with an added subject or permission is assessed.

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

## NIST SP 800-190 coverage

Cited by countermeasure section (section 4 of the September 2017 publication; no revision has been published). A rule cites a section only where the section's text recommends what the rule checks; a test checks every cited heading against the document's table of contents.

| Section | Hardex rules |
|---|---|
| 4.1.2 Image configuration defects | HX-WL-005 |
| 4.1.4 Embedded clear text secrets | HX-SEC-001, HX-SEC-002, HX-CP-007 |
| 4.1.5 Use of untrusted images | HX-WL-011, HX-WL-012 |
| 4.3.1 Unbounded administrative access | HX-RBAC-001, HX-RBAC-002, HX-RBAC-003, HX-RBAC-004, HX-RBAC-005, HX-RBAC-006, HX-RBAC-007, HX-RBAC-008, HX-CP-002, HX-PATH-001 |
| 4.3.2 Unauthorized access | HX-RBAC-002, HX-RBAC-007, HX-CP-001, HX-CP-002 |
| 4.3.3 Poorly separated inter-container network traffic | HX-NET-001 |
| 4.3.4 Mixing of workload sensitivity levels | HX-PATH-001 |
| 4.3.5 Orchestrator node trust | HX-CP-006, HX-CP-008, HX-NODE-001, HX-NODE-002, HX-NODE-003 |
| 4.4.2 Unbounded network access from containers | HX-NET-002 |
| 4.4.3 Insecure container runtime configurations | HX-WL-001, HX-WL-002, HX-WL-004, HX-WL-006, HX-WL-007, HX-WL-008, HX-WL-015, HX-WL-016, HX-WL-017, HX-WL-018, HX-WL-020 |
| 4.4.4 App vulnerabilities | HX-WL-009 |
| 4.4.5 Rogue containers | HX-RBAC-006, HX-CP-003, HX-CP-005 |
| 4.5.5 Host file system tampering | HX-WL-003 |

Not cited, because they are outside what Hardex can observe in Kubernetes objects and node configuration: image contents (4.1.1 vulnerabilities, 4.1.3 malware; `hardex images --vulns` reports SBOM-based vulnerabilities but is not a rule), registries (4.2), runtime software and behaviour (4.4.1), the host OS (4.5.1–4.5.4) and hardware (4.6). Rules with no section whose text covers what they check cite none: HX-CP-004, HX-CP-009, HX-CP-010, HX-NET-003, HX-NET-004, HX-NET-005, HX-NET-006, HX-NET-007, HX-NET-008, HX-NET-009, HX-NODE-004, HX-PATH-002, HX-WL-010, HX-WL-013, HX-WL-014, HX-WL-019, HX-WL-021.

## Contributing a mapping

A mapping change must state the framework version and the exact control, and should be reviewed by a second maintainer against the source document. See [CONTRIBUTING.md](../CONTRIBUTING.md).
