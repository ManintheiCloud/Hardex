# Changelog

All notable changes are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/). Before 1.0, minor versions may contain breaking changes.

## Unreleased

### Fixed
- Rollback of a patch with an unknown outcome (0.10.0) decided "never applied" only if the object's `resourceVersion` had not moved. On a real cluster it moves with any update, for example the Deployment controller writing status, so an untouched object was reported as changed by someone else and left for manual review. Rollback now compares the fields the patch touches: if all still have their original values, there is nothing to undo. Found by the new end-to-end crash replay below.

### Tests
- The kind end-to-end test replays a crash during `fix --apply` against the real API server, both ways: a patch that landed before the crash is undone by `hardex rollback`, and one that never landed is left untouched (its `resourceVersion` does not move). This checks, on a real cluster, that a JSON patch made only of `test` operations is accepted without changing the object, which recovery relies on.

## 0.10.0 — 2026-10-20

### Fixed
Remediation (`hardex fix --apply`, `hardex rollback`) could leave changes in a cluster without a record or an undo. Reported by an external review; each case is reproduced by a test that fails on 0.9.2.
- **Crash between patch and record.** The backup recorded a change only after the API server confirmed it, so a process that died in between left a change `hardex rollback` did not know about. The backup is now a write-ahead journal: each object is recorded as attempted before its patch is sent.
- **Lost responses.** A request that timed out after the server applied it was treated as not applied and left in place, with no rollback error. Attempted objects with an unknown outcome are now resolved against the live object: undone if the patch landed, left alone if it did not, reported if the object has changed since.
- **Interrupted runs.** Ctrl-C killed the process mid-apply; when the context was cancelled, the automatic rollback reused it and every undo request failed. `fix --apply` now handles SIGINT/SIGTERM by stopping cleanly, and rollback runs on its own context (bounded at two minutes), saving the backup after each object.
- **Failed verification.** When the re-assessment after applying found new problems, still-present targets, or could not run, `fix --apply` only printed how to undo. It now rolls the changes back automatically (ADR 0003: success is defined by the re-assessment); `--keep-unverified` keeps them.

### Changed
- Releases need a person's approval: after a version change reaches `main`, the release is built and tested automatically, then waits for a reviewer to approve it in GitHub (the protected `release` environment) before anything is signed, tagged or published. The release-time protection check also verifies the environment.

## 0.9.2 — 2026-10-20

### Fixed
- The API server's structured configuration files were trusted without being read: with `--authentication-config`, `--authorization-config` or `--encryption-provider-config` set, HX-CP-001, HX-CP-002 and HX-CP-007 reported nothing whatever the files said. When the files are part of the input (e.g. scan `/etc/kubernetes` with the static pod manifests), Hardex now reports:
  - HX-CP-001: an `AuthenticationConfiguration` whose anonymous authenticator is enabled without conditions, or for paths other than `/livez`, `/readyz` and `/healthz`. A file without an `anonymous` section no longer hides `--anonymous-auth`, which then still applies (default true).
  - HX-CP-002: an `AuthorizationConfiguration` that includes `AlwaysAllow` (critical) or no `RBAC` authorizer (medium).
  - HX-CP-007: an `EncryptionConfiguration` under which Secrets are still written unencrypted: no entry covers them, or the first matching entry (`secrets`, `*.` or `*.*`, in order) lists `identity` first.

## 0.9.1 — 2026-10-20

### Added
- NIST SP 800-190 citations: 39 rules cite the countermeasure sections (section 4) whose text recommends what they check, by the document's own numbering and headings ([docs/baselines.md](docs/baselines.md#nist-sp-800-190-coverage)). They appear in rule references, SARIF and `hardex report`, which groups evidence per framework. A test checks every cited heading against the document's table of contents.

### Changed
- The container image is built on `distroless/static-debian13` (Debian 13, current stable) instead of `static-debian12`, and both base images in the Dockerfile are pinned by digest. A test keeps every GitHub Action pinned to a commit SHA and every base image to a digest.

## 0.9.0 — 2026-10-20

### Added
- HX-WL-021: `host` in httpGet/tcpSocket probes and lifecycle hooks, which the Pod Security Standards Baseline forbids since Kubernetes 1.34 (the kubelet runs these from the node, so `host` lets any pod author make it connect to node-local services or the metadata endpoint). Medium; a loopback host in a `hostNetwork` pod is low. In the `baseline` and `restricted` profiles, with a fix that removes the field.

### Changed
- Brought the workload rules up to the Pod Security Standards of Kubernetes 1.37, checked against the `PodSecurity` admission controller's policy package:
  - HX-WL-005 no longer reports pods with their own user namespace (`hostUsers: false`): root there is unprivileged on the node, and the standard allows it since 1.35.
  - HX-WL-017 reports an unmasked `/proc` in such pods as low (Baseline allows it since 1.35; Restricted does not).
  - HX-WL-018 accepts the sysctls added to the safe set in 1.32 (`net.ipv4.tcp_rmem`, `tcp_wmem`) and 1.37 (`tcp_slow_start_after_idle`, `tcp_notsent_lowat`); they were false positives.
- Accuracy corpus: MetalLB's speaker gains two low HX-WL-021 findings (loopback probes in a host-network pod).

## 0.8.10 — 2026-10-20

### Fixed
- Keyless image verification did not find cosign v3 image signatures on registries without the OCI referrers API (such as GHCR): the referrers tag index lists them with the empty artifact type, which discovery skipped, so only other attestations (e.g. SLSA provenance) were checked. Such referrers are now opened and judged by their layers (at most 32 per image). Found by inspecting the published Hardex image.

### Added
- `hardex images --predicate-type`: accept only attestations of one kind (e.g. the cosign signature or SLSA provenance). Every verified signature and attestation is now listed, not only the first.
- CI and the post-release check require both the cosign signature and the SLSA provenance on the published image.

## 0.8.9 — 2026-10-20

### Fixed
- `SHA256SUMS` now covers the SBOM (`hardex.spdx.json`), as docs/verifying-releases.md stated; it was generated before the SBOM. (The SBOM was and is covered by its own build-provenance attestation.)

### Added
- After every release, the `image-smoke` workflow verifies every artifact end to end: each published file is listed in and matches `SHA256SUMS`, the checksum signature verifies with cosign, and every archive, the SBOM and the image carry SLSA provenance from the release workflow at the tagged commit (`gh attestation verify --source-digest`).

## 0.8.8 — 2026-10-20

### Added
- Admission load test and benchmarks (`integrations/admission/load_test.go`): decision latency for typical and near-maximum objects, and a concurrent mixed load in CI (p99 under 2 s; concurrency correctness also under the race detector). Numbers in docs/performance.md.

### Changed
- HX-SEC-002 matches credential-like variable names with substring tests instead of a regular expression (same results, verified on 20,000 generated names; a third faster on objects with thousands of variables).

## 0.8.7 — 2026-10-20

### Added
- `hardex admission --preflight` (with `--cluster` or manifest paths): evaluates every existing object exactly as the webhook would in enforce mode and lists, by namespace, what would be rejected, with guidance on fixing, waiving or excluding; exits 1 if anything would be. Tested to agree with the webhook object by object, and end to end against the live kind cluster.

## 0.8.6 — 2026-10-20

### Added
- End-to-end: admission enforce mode (rejects a privileged pod, admits a hardened one), the scan and monitor CronJobs run in-cluster, and monitor history persisting between runs.

### Changed
- `deploy/hardex-monitor.yaml` uses `--fail-on=none`: hourly Jobs fail only when the assessment or the webhook delivery does, not whenever findings exist.
- docs/admission.md, "Before enforcing": enforce mode blocks platform components outside the excluded namespaces — demonstrated end to end with kind's local-path storage provisioner, whose helper pods it rejects, stopping PVC provisioning.

## 0.8.5 — 2026-10-20

### Added
- Accuracy corpus extended to 18 components: Flux, MetalLB, Sealed Secrets, KEDA, Strimzi, Rook Ceph, Knative Serving and node-problem-detector (see docs/accuracy.md).

### Changed
- HX-RBAC-001: wildcard verbs, not only resources, within extension API groups or the metrics APIs are low (escalate, bind and impersonate have no meaning there); an API-group wildcard covering only `*/scale` is medium (low for Roles).
- HX-RBAC-007: one level lower (high for unauthenticated, low for authenticated) when every rule of the granted role is limited to named objects with read or proxy verbs.

## 0.8.4 — 2026-10-19

### Added
- GitHub Action (`uses: ManintheiCloud/Hardex@v0.8.4`): downloads the release for the runner (Linux, macOS, Windows; x64, ARM64), verifies it against `SHA256SUMS` and its SLSA build provenance, scans, and writes SARIF for code scanning. Tested on every hosted runner type.

### Removed
- A test binary (`tests.test`) that had been committed by mistake; `*.test` is ignored.

## 0.8.3 — 2026-10-19

### Added
- Accuracy regression corpus (`tests/corpus`, `make corpus`, CI on every push): pinned releases of cert-manager, Argo CD, prometheus-operator, Calico, kube-state-metrics, Gatekeeper, Longhorn, metrics-server, Kyverno and Envoy Gateway are scanned and every finding compared with reviewed golden files.

### Changed
- HX-RBAC-008: reading Secrets only in the workload's own namespace is medium (high when other namespaces or cluster-wide).

## 0.8.2 — 2026-10-19

Accuracy fixes from reviewing findings on widely used components (docs/accuracy.md).

### Fixed
- `get` on `pods/exec`, `pods/attach` or `pods/portforward` no longer counts as exec (HX-RBAC-005, HX-RBAC-008, attack paths): since Kubernetes 1.35 the API server requires `create` for them over WebSockets.
- HX-RBAC-001 is low, not high, when the only wildcard is resources within extension API groups (an operator's own CRDs, e.g. Calico's controllers).
- HX-RBAC-003 names the rule index, so two grants in one role are distinguishable.

### Changed
- `get` on `nodes/proxy` is described as what it is: exec in every pod on the node (the kubelet authorizes WebSocket exec as `get nodes/proxy`).

## 0.8.1 — 2026-10-19

Accuracy fixes found by reviewing an end-to-end run on a real cluster.

### Fixed
- Workloads in `kube-system` (kube-proxy, the CNI, CoreDNS) were assessed by default and reported as critical. They are platform components with host access by design; workload rules now skip `kube-system` unless `--include-system`, as the RBAC and networking rules already did.
- kubeadm's own RBAC (`kubeadm:bootstrap-signer-clusterinfo`, which kubeadm requires for node bootstrap, and `kubeadm:cluster-admins`) was reported as critical or high on every kubeadm cluster; `kubeadm:` objects are now treated like `system:` objects.
- HX-WL-003 (and the escape analysis behind HX-PATH-001) treated every mount of a sensitive host path as node takeover. Runtime sockets and paths that hold credentials stay critical even read-only; other sensitive paths are critical only when a container can write to them (mounted without `readOnly`, or privileged / `CAP_SYS_ADMIN`). Read-only mounts of, for example, the kubelet configuration file are high. Hardex's own node DaemonSet no longer reports itself as an escape path.

### Added
- End-to-end tests on a real cluster (kind, Kubernetes 1.37) on every push: least-privilege live scan, remediation apply and rollback, the node scanner DaemonSet and the admission webhook. `make e2e`.
- `tools/update-trusted-root.sh` and a weekly workflow keep the embedded Sigstore trusted root current; releases fail if it is stale.

### Notes
- The detection fixture `tests/fixtures/insecure/workloads.yaml` combines settings that a current API server rejects (it represents manifests as committed, not as admitted); the end-to-end test uses its own API-valid workload.

## 0.8.0 — 2026-10-19

### Added
- `--cloud-iam` on `scan` and `monitor`: reads `aws iam get-account-authorization-details`, `gcloud projects get-iam-policy` and `az role assignment list` exports (no cloud API calls, no cloud credentials) and classifies each workload identity as admin, escalation or limited from its unconditional grants. HX-PATH-002 becomes critical for admin identities and high for escalation; HX-PATH-001 reports chains into them as critical (control of the cloud account). See docs/cloud-iam.md.
- Fuzzing of IAM export parsing in CI.

### Changed
- The roadmap has no open items; preferred and inter-pod affinity are documented as deliberately not modelled.

## 0.7.0 — 2026-10-19

### Added
- Keyless verification supports Rekor v2 (tile-based) log entries: the entry is recomputed from the bundle and proven against the log's signed checkpoint, with the signing time from a timestamp authority. `intoto` 0.0.2 entries (older attestations) are supported too.
- The Sigstore project's client conformance suite runs in Hardex's tests; every certificate-based case passes.
- Attack paths use Node objects when present: pods are placed on exactly the nodes their `nodeName`, `nodeSelector`, required node affinity (all operators, ORed terms) and tolerations allow, so control-plane and dedicated-pool taints separate workloads. Live scans collect nodes (labels and taints only); if `nodes` cannot be listed the scan stays complete and warns.

### Changed
- Bundles v0.2 and later must carry an inclusion proof (a signed entry timestamp alone is accepted only in v0.1 bundles, as the Sigstore specification requires); bundles whose certificate chain includes a root certificate are rejected; trusted roots must give a start for every validity period.
- `deploy/hardex-reader.yaml` grants `get`/`list` on `nodes` (not `nodes/proxy`).

## 0.6.0 — 2026-10-19

### Added
- Keyless Sigstore verification inside Hardex, completely offline: Fulcio certificate chain at a verified signing time, embedded SCT, signer identity and OIDC issuer policy, message and DSSE signatures, Rekor entry consistency, signed entry timestamps, inclusion proofs against signed checkpoints, and RFC 3161 timestamps. The Sigstore public-good trusted root is embedded; `--trusted-root` overrides it.
  - `hardex images --certificate-identity[-regexp] --certificate-oidc-issuer[-regexp]`: verifies bundles attached as OCI referrers (cosign v3, GitHub attestations; referrers API or tag fallback) and cosign's legacy keyless format.
  - `hardex verify-blob`: verifies a file against a Sigstore bundle (for example a Hardex release's `SHA256SUMS`).
- `hardex images --vulns`: known vulnerabilities (OSV) for the packages in each image's SBOM attestation; `--fail-on-vulns`. `--image` checks references given on the command line.
- `hardex scan --node`: kubelet configuration (with security-relevant command-line flag overrides) and static pod manifests read on the node, without `nodes/proxy`; `--node-root`, `--node-name`, `--kubelet-config`, `--every`. `deploy/hardex-node.yaml`: a read-only, tokenless, network-isolated DaemonSet.
- `hardex scan --stats`: load and evaluation time and the slowest rules; a performance-report issue template.
- Attack paths follow node placement: token theft through a node is modelled only between pods whose `nodeSelector`, `nodeName` or required node affinity let them share a node. Cloud workload identities (EKS IRSA, GKE Workload Identity, Azure Workload Identity) are path goals.
- HX-PATH-002: workloads whose token assumes a cloud identity.
- HX-CP-010: admission webhooks served by URL from outside the cluster (high for mutating webhooks). HX-CP-009 now covers mutating webhooks.
- HX-NET-008: Gateway API listeners serving plain HTTP with no TLS listener for the hostname. HX-NET-009: Gateway listeners accepting routes from every namespace.
- Item-level framework mappings: every rule references CIS Kubernetes Benchmark v2.0 items and NSA/CISA Kubernetes Hardening Guidance v1.2 sections; a CIS coverage table in docs/baselines.md.
- Live scans collect `MutatingWebhookConfiguration` and Gateway API `Gateway` objects; the reader role grants them.
- CI verifies the latest published image and release with the code under test; bundle and timestamp parsers are fuzzed.

### Changed
- The roadmap's phase I–IV objectives are complete; ongoing work is listed separately.

## 0.5.0 — 2026-10-19

### Added
- Default-deny detection (HX-NET-001/002) understands Cilium (`CiliumNetworkPolicy`, `CiliumClusterwideNetworkPolicy`) and Calico (`NetworkPolicy`, `GlobalNetworkPolicy`) policies; live scans collect them when installed.
- HX-NET-006: Ingresses using ingress-nginx snippet annotations (CVE-2021-25742 class).
- HX-NET-007: the retired ingress-nginx controller (no security fixes since March 2026).
- `hardex fix --kustomize`: remediation as a Kustomize overlay of JSON 6902 patches, verified end to end with real Kustomize in CI.
- Fuzzing in CI for the manifest loader, policy configuration, rule modules, admission requests and control-plane flags.
- Compatibility policy: supported Kubernetes versions, environments and platforms (docs/compatibility.md).

### Fixed
- A malformed configuration could crash Hardex through a panic in the YAML library (found by fuzzing). All YAML decoding now converts library panics into errors.

## 0.4.0 (Phase IV: Advanced Security Engineering) — 2026-10-19

### Added
- HX-PATH-001: multi-step privilege-escalation paths (container escape, token theft from co-located pods, workload creation, exec, token minting, RBAC escalation) to cluster administrator or node root.
- `hardex admission`: validating admission webhook running the same rules (warn, enforce fail-closed, audit), certificate hot-reload, decision log; `deploy/hardex-admission.yaml`.
- `hardex report` and `scan --format html|markdown`: posture score, grade, framework evidence, accepted risks, and the SHA-256 of the source report.
- `hardex fleet` and `hardex compare`: multi-cluster assessment and a matrix of inconsistent controls.
- Scale test (~16k objects) and benchmarks; `make bench`.
- `hardex images`: resolve image tags to digests with pin suggestions; verify cosign key-based signatures (`--key`, `--require-signature`, `--require-digest`); minimal registry client with digest-verified content.
- Release pipeline: multi-platform binaries, SHA256SUMS signed keylessly with Sigstore, SPDX SBOM, SLSA build-provenance attestations, and a signed multi-arch image at `ghcr.io/manintheicloud/hardex`.

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
