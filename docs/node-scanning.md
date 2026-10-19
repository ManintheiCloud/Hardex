# Node configuration

Kubelet configuration and control-plane static pod manifests live on the nodes, not in the API. The API server can serve a kubelet's running configuration through `nodes/NAME/proxy/configz`, but **Hardex does not use it**: `nodes/proxy` lets its holder execute commands in every pod on the node (HX-RBAC-008 reports it as root-equivalent), so a scanner holding it would be the most valuable credential in the cluster.

Instead, `hardex scan --node` reads the files on the node itself:

| What | Where (first found wins) |
|---|---|
| Kubelet configuration file | `--kubelet-config`, else the kubelet's `--config` flag, else `/var/lib/kubelet/config.yaml` (kubeadm), `/etc/kubernetes/kubelet/config.json` (EKS AL2023), `/etc/kubernetes/kubelet/kubelet-config.json` (EKS AL2), `/home/kubernetes/kubelet-config.yaml` (GKE), `/etc/default/kubeletconfig.json` (AKS) |
| Kubelet command-line flags | `/var/lib/kubelet/kubeadm-flags.env`, `/etc/default/kubelet`, `/etc/sysconfig/kubelet`, systemd drop-ins in `/etc/systemd/system/kubelet.service.d` and `/usr/lib/systemd/system/kubelet.service.d` |
| Static pod manifests | `/etc/kubernetes/manifests` |

Command-line flags override the configuration file, so the security-relevant ones (`--anonymous-auth`, `--authentication-token-webhook`, `--authorization-mode`, `--read-only-port`, `--protect-kernel-defaults`, `--client-ca-file`, `--rotate-certificates`, `--event-qps`, `--tls-cert-file`, `--tls-private-key-file`, `--make-iptables-util-chains`, `--streaming-connection-idle-timeout`) are applied on top of it before the HX-NODE rules run. A kubelet with no configuration file is assessed from its flags alone. Hardex says on stderr which file and which overrides it used.

```sh
sudo hardex scan --node                                  # on the node
hardex scan --node --node-root /host --node-name "$NODE_NAME"   # host filesystem mounted at /host
hardex scan --node --kubelet-config /etc/rancher/k3s/kubelet.yaml   # any other layout
```

Findings name the node (`KubeletConfiguration worker-1`), so reports from many nodes can be merged with `hardex fleet`.

## As a DaemonSet

[`deploy/hardex-node.yaml`](../deploy/hardex-node.yaml) runs the node scan on every node, every 24 hours (`--every 24h`), writing a JSON report to the pod log. It mounts **only** the kubelet configuration file, kubeadm's flags file and the manifests directory, read-only — not `/var/lib/kubelet` (which holds pod volumes, including Secrets) and not `/etc/kubernetes` (which holds `admin.conf` and PKI keys on control-plane nodes). The pod has no API token and a deny-all NetworkPolicy. It runs as UID 0 with every capability dropped, because static pod manifests are mode 0600; hostPath volumes are not allowed by the baseline Pod Security Standard, so it runs in its own `privileged` namespace. Scanning the manifest reports exactly these choices (HX-WL-003, HX-WL-005).

The example uses kubeadm's paths. For other distributions, change the hostPath volumes and pass `--kubelet-config`.

## Limitations

- Flags given as `--flag value` (with a space) in the files above are not recognised; `--flag=value` and bare boolean flags are.
- Flags set in the kubelet's systemd `ExecStart` line directly are read; flags injected by other means (wrapper scripts, cloud bootstrap at runtime) are not visible. Running kubelet processes are not inspected.
- Managed control planes (EKS, GKE, AKS) have no static pod manifests on worker nodes; control-plane rules do not apply to them.
