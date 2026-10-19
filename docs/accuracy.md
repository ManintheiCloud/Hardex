# Accuracy review

Findings on software that thousands of clusters run unchanged are the best test of a rule set: every false positive there is noise for everyone. Hardex is reviewed against:

- a fresh **kind** cluster (Kubernetes 1.37) with cert-manager and Hardex's own deployments, on every push (`tests/e2e/kind.sh` publishes every finding outside the deliberately insecure fixtures for review, and fails if Hardex's own deployments have a critical finding);
- the published install manifests of widely used components, scanned with `--profile baseline`.

## Review of October 2026 (v0.8.2)

| Component (manifest) | Findings kept | Verdict |
|---|---|---|
| kind defaults (kube-proxy, kindnet, CoreDNS, kubeadm RBAC) | none by default | **Fixed false positives:** `kube-system` workloads and `kubeadm:` RBAC are platform-managed and now need `--include-system` (0.8.1). |
| local-path-provisioner (kind) | HX-PATH-001, HX-RBAC-008, HX-NET-001/002, hardening gaps | True: it can create pods in a namespace without Pod Security enforcement, i.e. privileged pods, i.e. node root. |
| cert-manager v1.21 (`cert-manager.yaml`) | HX-RBAC-003 ×7, HX-RBAC-008 ×2, HX-PATH-001 | True: the controller reads Secrets cluster-wide and creates solver pods anywhere. |
| Argo CD (`manifests/install.yaml`) | HX-RBAC-001, -003, -008, HX-WL-011 | True: the application controller has `*` on `*`; the master manifests use `:latest`. |
| prometheus-operator (`bundle.yaml`) | HX-RBAC-003, -008, HX-PATH-001 | True: it reads Secrets and creates StatefulSets cluster-wide. |
| kube-state-metrics (standard example) | HX-RBAC-003 | True: `list` on Secrets returns their contents. |
| Calico (`calico.yaml`) | HX-RBAC-001 at **low** | **Recalibrated:** a resource wildcard inside an operator's own API groups (`crd.projectcalico.org`) cannot reach built-in objects; it was high. |
| Gatekeeper (`deploy/gatekeeper.yaml`) | HX-RBAC-008, HX-PATH-001 (nodes/proxy) | True, and severe: its read-everything role includes `get nodes/proxy`, and the kubelet authorizes WebSocket exec as `get nodes/proxy` (checked in the kubelet source), so it can execute in every pod on every node. **Fixed false positive:** `get pods/exec` no longer counts as exec, since the API server requires `create` for WebSocket exec from 1.35 (`AuthorizePodWebsocketUpgradeCreatePermission`). |
| Kyverno 1.15 (`install.yaml`) | HX-RBAC-008 (Secrets in its namespace) | True. |
| Envoy Gateway 1.5 (`install.yaml`) | HX-RBAC-003, -008, HX-PATH-001 | True: it creates the proxy Deployments in its namespace. |
| Longhorn (`deploy/longhorn.yaml`) | HX-WL-001, -003 critical, HX-RBAC-002, -008 | True: a privileged storage DaemonSet with host `/dev`, `/proc`, `/etc`, `/boot`; a cluster-admin binding for support bundles. Expected for block storage; isolate it. |
| metrics-server (`manifests/base`) | none | — |
| Hardex's own deployments | HX-WL-003 (high), HX-WL-005, HX-WL-012, HX-WL-013 | Documented in `deploy/README.md`. **Fixed false positive:** read-only mounts of individual host files were treated as node escape (0.8.1). |

"True" means the finding describes a real capability an attacker inheriting that workload's identity would have — not that the project is misconfigured. Many components need powerful access; Hardex's job is to make it visible, so it can be isolated (dedicated namespaces with Pod Security enforced, NetworkPolicies, separate node pools) and accepted with a waiver that expires.

Report a false positive with the [issue template](https://github.com/ManintheiCloud/Hardex/issues/new?template=false-result.yml).
