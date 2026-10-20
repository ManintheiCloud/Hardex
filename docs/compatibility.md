# Compatibility

## Kubernetes versions

Hardex supports the Kubernetes minor versions that are supported upstream. As of October 2026 these are **1.35, 1.36 and 1.37**, plus 1.34 until its end of life on 2026-10-27. When a minor version leaves upstream support, Hardex stops guaranteeing correct results for it in its next release.

Hardex reads only stable (`v1`) APIs: `v1`, `apps/v1`, `batch/v1`, `networking.k8s.io/v1`, `rbac.authorization.k8s.io/v1`, `admissionregistration.k8s.io/v1`, and `admission.k8s.io/v1` for the webhook. Newer fields (for example `securityContext.appArmorProfile`) are understood alongside their legacy forms (the AppArmor annotation), so manifests written for older clusters are assessed correctly.

## Environments

| Environment | Workloads, RBAC, network, secrets, paths | Control plane (HX-CP) | Kubelet (HX-NODE) |
|---|---|---|---|
| kubeadm and other self-managed clusters | ✓ | ✓ from static pod manifests (or the mirror pods `--cluster` collects), plus the API server's authentication, authorization and encryption configuration files when they are in the input | ✓ from `KubeletConfiguration` files |
| Managed clusters (EKS, GKE, AKS, …) | ✓ | not visible: the provider runs the control plane | ✓ if you have node configuration files |
| Manifest repositories, Helm/Kustomize output | ✓ | ✓ for static pod manifests in the input | ✓ for `KubeletConfiguration` in the input |

For Helm and Kustomize, assess the rendered output: `helm template … | hardex scan -`, `kubectl kustomize … | hardex scan -`.

## Network plugins

Default-deny detection (HX-NET-001/002) understands Kubernetes `NetworkPolicy`, Cilium (`CiliumNetworkPolicy`, `CiliumClusterwideNetworkPolicy`) and Calico (`NetworkPolicy`, `GlobalNetworkPolicy` in `crd.projectcalico.org/v1` or `projectcalico.org/v3`), following each project's reference semantics. Only policies that select every pod count; anything ambiguous is treated as not isolating, so a namespace is reported rather than silently passed.

## Platforms

Release binaries: Linux, macOS and Windows on amd64 and arm64. Container image: linux/amd64 and linux/arm64. Building from source needs Go 1.24 or later.
