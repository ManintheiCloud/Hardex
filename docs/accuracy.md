# Accuracy review

Findings on software that thousands of clusters run unchanged are the best test of a rule set: every false positive there is noise for everyone. Hardex is reviewed against:

- a fresh **kind** cluster (Kubernetes 1.37) with cert-manager and Hardex's own deployments, on every push (`tests/e2e/kind.sh` publishes every finding outside the deliberately insecure fixtures for review, and fails if Hardex's own deployments have a critical finding);
- the published install manifests of widely used components, at pinned releases, scanned with `--profile baseline` on every push (`tests/corpus`, `make corpus`). Every finding is compared with a reviewed golden file, so a rule change that alters what Hardex says about real-world software fails CI until the new findings are reviewed and the golden files updated in the same change. Each manifest is also pinned by SHA-256 (`corpus.sha256`), so an upstream file that changes under the same tag is reported as an upstream change, never mistaken for a change in Hardex.

## Review of October 2026 (v0.8.5)

| Component (manifest) | Findings kept | Verdict |
|---|---|---|
| kind defaults (kube-proxy, kindnet, CoreDNS, kubeadm RBAC) | none by default | **Fixed false positives:** `kube-system` workloads and `kubeadm:` RBAC are platform-managed and now need `--include-system` (0.8.1). |
| local-path-provisioner (kind) | HX-PATH-001, HX-RBAC-008, HX-NET-001/002, hardening gaps | True: it can create pods in a namespace without Pod Security enforcement, i.e. privileged pods, i.e. node root. |
| cert-manager v1.21 (`cert-manager.yaml`) | HX-RBAC-003 ×7, HX-RBAC-008 ×2, HX-PATH-001 | True: the controller reads Secrets cluster-wide and creates solver pods anywhere. |
| Argo CD 3.5 (`manifests/install.yaml`) | HX-RBAC-001, -003, -008 | True: the application controller has `*` on `*`. (The unreleased `master` manifests also use `:latest`, HX-WL-011.) |
| prometheus-operator (`bundle.yaml`) | HX-RBAC-003, -008, HX-PATH-001 | True: it reads Secrets and creates StatefulSets cluster-wide. |
| kube-state-metrics (standard example) | HX-RBAC-003 | True: `list` on Secrets returns their contents. |
| Calico (`calico.yaml`) | HX-RBAC-001 at **low** | **Recalibrated:** a resource wildcard inside an operator's own API groups (`crd.projectcalico.org`) cannot reach built-in objects; it was high. |
| Gatekeeper 3.23 (`deploy/gatekeeper.yaml`) | HX-RBAC-008, HX-PATH-001 (nodes/proxy), HX-CP-009 | HX-CP-009: its webhooks fail open by default, a documented availability trade-off. HX-RBAC-008 and HX-PATH-001 are true, and severe: its read-everything role includes `get nodes/proxy`, and the kubelet authorizes WebSocket exec as `get nodes/proxy` (checked in the kubelet source), so it can execute in every pod on every node. **Fixed false positive:** `get pods/exec` no longer counts as exec, since the API server requires `create` for WebSocket exec from 1.35 (`AuthorizePodWebsocketUpgradeCreatePermission`). |
| Kyverno 1.19 (`install.yaml`) | HX-RBAC-008 at medium (Secrets in its own namespace) | True. **Recalibrated:** reading Secrets only in the workload's own namespace (typically its own certificates) is medium, not high; the same applies to Argo CD's components and Envoy Gateway's certgen job. |
| Envoy Gateway 1.9 (`install.yaml`) | HX-RBAC-003, -008, HX-PATH-001 | True: it creates the proxy Deployments in its namespace. |
| Longhorn (`deploy/longhorn.yaml`) | HX-WL-001, -003 critical, HX-RBAC-002, -008 | True: a privileged storage DaemonSet with host `/dev`, `/proc`, `/etc`, `/boot`; a cluster-admin binding for support bundles. Expected for block storage; isolate it. |
| metrics-server (`manifests/base`) | none | — |
| Flux 2.9 (`install.yaml`) | HX-RBAC-002, -008 critical; HX-PATH-001 critical; HX-RBAC-005 | True, and worth knowing: helm-controller and kustomize-controller hold cluster-admin by design, and every other Flux controller can mint a token for any service account (`serviceaccounts/token` create, for workload identity) — including theirs, so compromising source-controller is a path to cluster-admin. **Recalibrated:** `*` verbs and resources on Flux's own API groups are low. |
| MetalLB 0.16 (`metallb-native.yaml`) | HX-WL-002, -006 (speaker), HX-RBAC-003/-008 medium | True: the speaker needs host networking and NET_RAW for L2/BGP announcements. **Recalibrated:** `*` verbs on `metallb.io` resources are low. |
| Sealed Secrets 0.40 (`controller.yaml`) | HX-RBAC-003, HX-RBAC-007 at low | True: the controller reads Secrets. **Recalibrated:** HX-RBAC-007 for granting every user read and proxy access to the one named controller Service (how `kubeseal` fetches the public certificate) is low, not high. |
| KEDA 2.21 (`keda-2.21.0.yaml`) | HX-RBAC-008, HX-PATH-001 (nodes/proxy), HX-RBAC-003 | True: the operator has `get` on every resource, which includes Secrets and `nodes/proxy` (exec through the kubelet). **Recalibrated:** `*/scale` across all groups is medium; the external metrics API wildcard is low. |
| Strimzi 1.3 | HX-RBAC-003, -005 | True: the operator reads Secrets and mints tokens. |
| Rook Ceph 1.21 (`common.yaml`, `operator.yaml`) | HX-RBAC-003, -005, -008, HX-PATH-001 | True: the operator execs into pods and creates privileged storage daemons. |
| Knative Serving 1.23 (`serving-core.yaml`) | HX-RBAC-003, -008 medium | True. **Recalibrated:** `*/scale` across all groups is medium; wildcards on Knative's own groups are low. |
| node-problem-detector 1.37 | none | — |
| Hardex's own deployments | HX-WL-003 (high), HX-WL-005, HX-WL-012, HX-WL-013 | Documented in `deploy/README.md`. **Fixed false positive:** read-only mounts of individual host files were treated as node escape (0.8.1). |

"True" means the finding describes a real capability an attacker inheriting that workload's identity would have — not that the project is misconfigured. Many components need powerful access; Hardex's job is to make it visible, so it can be isolated (dedicated namespaces with Pod Security enforced, NetworkPolicies, separate node pools) and accepted with a waiver that expires.

Report a false positive with the [issue template](https://github.com/ManintheiCloud/Hardex/issues/new?template=false-result.yml).
