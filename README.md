# HARDEX

**Kubernetes Hardening. Engineered for Hostile Environments.**

Harden the cluster. Reduce the attack surface. Establish trust.

---

Hardex is an open-source Kubernetes security hardening framework. It brings systematic, measurable and reproducible security controls to containerized infrastructure: assess, harden, verify, defend.

> **Status: v0.6.0.** Every roadmap objective in phases I–IV is implemented and tested: assessment (55 rules mapped to CIS v2.0 items and NSA/CISA v1.2 sections, three profiles, policy and waivers), read-only live-cluster and node scanning, RBAC reachability and placement-aware attack paths into cluster admin, nodes and cloud identities, guarded remediation with backup and rollback, history and drift monitoring with signed notifications, rule modules, an admission webhook, posture scoring with evidence reports, multi-cluster comparison, and offline keyless Sigstore verification with SBOM vulnerability lookup. Ongoing work is in [ROADMAP.md](ROADMAP.md). No production-readiness or security certification is claimed.

## What Hardex does today

```
$ hardex scan --profile restricted ./manifests

[CRITICAL] HX-WL-001 Privileged container
  resource: Deployment shop/insecure-web [web]
  location: manifests/web.yaml:3
  field:    spec.template.spec.containers[0].securityContext.privileged = true
  detail:   container "web" runs privileged
  fix:      Remove securityContext.privileged. If specific kernel access is needed, grant the single required capability instead and document why.
...
Summary: 76 findings (critical 13, high 24, medium 23, low 14, info 2), 0 waived
```

- **Assessment** of workloads, RBAC, network segmentation, Secrets handling, control-plane static pods, and kubelet configuration — [55 rules](docs/rules.md), each with rationale, remediation, known limitations and references.
- **Live-cluster scanning** (`--cluster`) with a minimal read-only client: no Secrets access, TLS required, least-privilege [reader role](deploy/hardex-reader.yaml) provided. **Node scanning** (`--node`) reads kubelet configuration, its flag overrides and static pod manifests from the node, without `nodes/proxy` ([docs/node-scanning.md](docs/node-scanning.md)).
- **RBAC reachability**: follows each workload's service account through bindings to the permissions its token really carries (HX-RBAC-008).
- **Remediation** (`hardex fix`): dry-run plans with risk ratings and a predicted result; patched manifests written to a new directory; on a cluster, explicitly authorised apply with backup, automatic all-or-nothing rollback on failure, post-change verification, and `hardex rollback`. See [docs/remediation.md](docs/remediation.md).
- **Continuous monitoring**: `scan --history` and `hardex history` record and chart posture over time; `hardex monitor` re-assesses on an interval (or `--once` from cron), detects drift from the previous run or an approved baseline, and emits events as JSON Lines or HMAC-signed webhooks (generic or Slack). See [docs/monitoring.md](docs/monitoring.md).
- **Rule modules**: organisation and community checks written in YAML, loaded with `--module`. See [docs/modules.md](docs/modules.md).
- **Attack paths** (HX-PATH-001, HX-PATH-002): finds chains such as *web pod escapes to its node → steals the token of a controller that can run on the same node → cluster-admin* or *→ the AWS role behind an IRSA token*, combining container escape, node placement, token theft, workload creation, exec, token minting, RBAC escalation and cloud workload identities, and names each link so the cheapest one can be broken.
- **Admission control** (`hardex admission`): the same rules enforced by the API server as a validating webhook, in warn, enforce (fail-closed) or audit mode. See [docs/admission.md](docs/admission.md).
- **Posture score and evidence** (`hardex report`): a transparent, recomputable score and grade, framework-by-framework control evidence, and HTML/Markdown reports tied to the JSON report by SHA-256. See [docs/scoring.md](docs/scoring.md).
- **Fleet view** (`hardex fleet`, `hardex compare`): assess many clusters and list controls that are inconsistent across them.
- **Image supply chain** (`hardex images`, `hardex verify-blob`): resolve every running image to its digest (with copy-paste pins); verify cosign key signatures or keyless Sigstore signatures — completely offline against the Sigstore trusted root, with a required signer identity; look up known vulnerabilities (OSV) from SBOM attestations. See [docs/image-verification.md](docs/image-verification.md).
- **Signed releases**: binaries, SBOM and a multi-arch container image, signed keylessly with Sigstore and carrying SLSA build provenance. See [docs/verifying-releases.md](docs/verifying-releases.md).
- **Works with your stack**: Cilium and Calico policies, Gateway API and mutating webhooks are understood; fixes can be emitted as Kustomize overlays; supported Kubernetes versions and environments are in [docs/compatibility.md](docs/compatibility.md).
- **Scales linearly**: ~16,000 objects with every rule in about a second ([docs/performance.md](docs/performance.md)).
- **Complete Pod Security Standards coverage**: every Baseline and Restricted control, plus NSA/CISA recommendations PSS does not include; every rule mapped to CIS Kubernetes Benchmark v2.0 items and NSA/CISA v1.2 sections.
- **Profiles** (`minimal` ⊂ `baseline` ⊂ `restricted`) defined as reviewable YAML, not code.
- **Policy with accountability**: disabling a rule needs a justification; waivers need a justification and an expiry date, and expired waivers resurface automatically.
- **Verification**: `hardex diff` compares two reports by stable fingerprints and refuses to call a finding "resolved" when the rule that found it did not run.
- **Machine-readable output**: versioned JSON and SARIF 2.1.0 (for GitHub code scanning and similar).
- **Fail-safe behaviour**: a crashing rule marks the assessment incomplete (exit 3) instead of silently passing; malformed configuration is an error, never a fallback.

## Quick start

Download a signed release from [Releases](https://github.com/ManintheiCloud/Hardex/releases) ([how to verify](docs/verifying-releases.md)), run the container image `ghcr.io/manintheicloud/hardex`, or build with Go 1.24+:

```sh
go install github.com/ManintheiCloud/Hardex/cmd/hardex@latest

hardex scan ./k8s/                          # baseline profile, text output
hardex scan --profile restricted ./k8s/     # every rule
hardex scan --format sarif -o hardex.sarif ./k8s/
hardex rules                                # list rules
hardex rules HX-RBAC-004                    # explain one
```

Assess a running cluster directly (uses your current kubeconfig context, read-only):

```sh
kubectl apply -f deploy/hardex-reader.yaml   # optional: least-privilege role for a scanner identity
hardex scan --cluster --context prod
```

Or scan an export: `kubectl get <kinds> -A -o yaml | hardex scan -`.

Plan and apply fixes:

```sh
hardex fix ./k8s --out ./k8s-fixed                         # dry run + patched manifests
hardex fix --cluster --rules HX-WL-004,HX-WL-008 --apply   # backup, apply, verify
hardex rollback hardex-backups/hardex-backup-<time>.json --cluster
```

Enforce at admission, report, and compare clusters:

```sh
kubectl apply -f deploy/hardex-admission.yaml               # webhook (starts in warn mode)
hardex report report.json -o evidence.html                  # score + evidence
hardex fleet --contexts prod,staging --out reports/         # cross-cluster matrix
```

Monitor continuously:

```sh
hardex monitor --cluster --interval 1h --history ./hardex-history --webhook https://hooks.example.com/hardex
hardex history ./hardex-history
```

Control-plane checks read static pod manifests (`/etc/kubernetes/manifests/*.yaml` on kubeadm nodes) and node checks read kubelet configuration files (commonly `/var/lib/kubelet/config.yaml`).

Verify a remediation:

```sh
hardex scan --format json -o before.json --fail-on none ./k8s/
# ...apply fixes...
hardex scan --format json -o after.json  --fail-on none ./k8s/
hardex diff before.json after.json          # exit 1 if anything >= high was introduced
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | No active findings at or above `--fail-on` (default `high`) |
| 1 | Findings at or above `--fail-on`; for `diff`, a regression was introduced; for `fix --apply`, verification found a regression or an unresolved target; for `monitor --once`, new findings or baseline drift; for `fleet`, any cluster with such findings |
| 2 | Invalid arguments, configuration or input |
| 3 | Incomplete — a rule failed or cluster resources could not be read (results understate risk), an apply failed and was rolled back, or a notification could not be delivered |

### Configuration

Configuration is **never loaded implicitly** — a `hardex.yaml` planted in a scanned repository cannot suppress findings. Pass it with `--config`. See [docs/configuration.md](docs/configuration.md) and [examples/hardex.yaml](examples/hardex.yaml).

## The problem

Kubernetes security is not a single configuration problem. It is an interconnected collection of risks: misconfigured workloads and excessive privileges, weak RBAC, unrestricted east-west traffic, insecure runtime settings, exposed API components, inadequate secrets management, unverified images, insufficient audit logging, configuration drift, and inconsistent practices across clusters.

Existing tools address many of these individually. Combining them into a coherent, maintainable, *verifiable* posture is the gap Hardex exists to close — with tooling powerful enough for experienced infrastructure engineers and understandable by organizations without dedicated security teams.

## Mission

Make secure Kubernetes deployment, operation and maintenance systematic, verifiable, repeatable and accessible, through four objectives:

1. **Prevention** — reduce the likelihood of exploitation through proactive hardening.
2. **Detection** — identify insecure configurations, policy violations and security-relevant changes.
3. **Enforcement** — apply well-defined controls while preserving operational stability.
4. **Verification** — demonstrate that controls work, with repeatable assessments and measurable evidence.

Security should not depend solely on administrator vigilance. It should be an engineered property of the environment.

## Design principles

| Principle | How it shows up in the code today |
|---|---|
| Security by default | Default profile is `baseline`, default `--fail-on` is `high`, system objects are only excluded where Kubernetes manages them. |
| Least privilege | Files need no credentials; live scans need only the read-only [`hardex-reader`](deploy/hardex-reader.yaml) role, which excludes Secrets. Writes need a separate identity and an explicit `--apply`. |
| Defense in depth | Overlapping controls are kept (e.g. seccomp *and* AppArmor *and* capabilities), each reported on its own. |
| Operational predictability | Rules are pure functions of their input; output is deterministic and sorted. |
| Verification over assumption | `diff` distinguishes *resolved* from *unverified*; `fix --apply` re-assesses the cluster and reports what actually changed; waived findings are never counted as fixed. |
| Transparency and auditability | Every finding cites field path, observed value, rule rationale and references; waivers record owner and justification. |
| Fail safely | Rule panics → exit 3; unknown config fields, missing justifications or undated waivers → error; YAML alias bombs and oversized inputs are rejected; YAML 1.1 spellings like `privileged: yes` are read the way Kubernetes reads them; terminal escape sequences in manifests are neutralised. |
| Open development | Apache-2.0, public threat model, documented limitations per rule. |
| Modularity | Rules live in independent packages behind one small interface; profiles are data. |

Read more: [architecture](docs/architecture.md) · [threat model](docs/threat-model.md) · [baseline mappings](docs/baselines.md) · [writing rules](docs/writing-rules.md) · [decision records](docs/adr/).

## Repository layout

```
hardex/
├── cmd/hardex/            CLI
├── hardex.go              Library entry point (hardex.Scan)
├── core/
│   ├── assessment/        Rule contract, registry, fail-safe evaluator
│   ├── cluster/           Minimal read-only Kubernetes API client and collector
│   ├── fleet/             Cross-cluster comparison
│   ├── history/           Recorded assessments and trends
│   ├── imagesig/          Image signatures: cosign keys and keyless Sigstore
│   ├── sigstore/          Offline Sigstore bundle verification (Fulcio, Rekor, CT, TSA)
│   ├── vuln/              SBOM attestations and OSV vulnerability lookup
│   ├── node/              Node-local kubelet and static pod collection
│   ├── registry/          Minimal read-only OCI registry client
│   ├── modules/           Declarative (YAML) rule modules
│   ├── finding/           Finding and report model (JSON schema v1alpha1)
│   ├── policy/            Profiles selection, config, waivers, overrides
│   ├── remediation/       Guarded JSON patches, inverses, backup, apply/rollback
│   ├── score/             Posture score and framework evidence
│   ├── resource/          Hardened YAML loader, object model
│   └── verification/      Before/after comparison
├── kubernetes/
│   ├── workloads/         HX-WL-*   pod specs (full PSS coverage)
│   ├── secrets/           HX-SEC-*  secret handling
│   ├── rbac/              HX-RBAC-* permissions and escalation paths
│   ├── networking/        HX-NET-*  segmentation and exposure
│   ├── controlplane/      HX-CP-*   API server, etcd, scheduler, controller manager
│   ├── nodes/             HX-NODE-* kubelet configuration
│   └── paths/             HX-PATH-* multi-step privilege-escalation paths
├── kubernetes/fixes.go    Automatic fixes and their risk ratings
├── baselines/             Profiles (YAML), guidance citations, CIS/NSA item mappings
├── deploy/                Reader role, scan/monitor CronJobs, node DaemonSet, admission webhook
├── integrations/
│   ├── admission/         Validating admission webhook
│   ├── reporting/         Text, JSON, SARIF, HTML/Markdown evidence
│   ├── monitoring/        Repeated assessment, drift, events
│   └── notify/            JSON Lines and signed webhook delivery
├── tests/                 End-to-end detection / false-positive suites and fixtures
├── tools/gendocs          Generates docs/rules.md from rule metadata
└── docs/
```

Every component of the original design now exists; remaining work is tracked in [ROADMAP.md](ROADMAP.md).

## Security validation

The test suite encodes the README's validation priorities:

- **Detection accuracy** — `tests/fixtures/insecure` must trigger every rule at the expected resource and severity; a test fails if any rule lacks an expectation.
- **False-positive control** — `tests/fixtures/hardened` must produce zero findings under every profile, including inherited pod-level settings, LimitRange defaults and resourceName-scoped RBAC.
- **Regression resistance** — determinism, secret-redaction, fingerprint stability and doc-freshness are all tested.

```sh
make check   # fmt, vet, race-enabled tests, govulncheck
```

## Contributing

Contributions of code, rules, fixtures, documentation and security research are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities in Hardex privately as described in [SECURITY.md](SECURITY.md).

## Security considerations

No hardening framework can eliminate all vulnerabilities, guarantee compromise prevention, or replace a broader security program. Compliance is not security: Hardex treats benchmark alignment as one source of evidence, not a verdict. Test changes to permissions, admission behaviour, network policy and control-plane configuration before applying them to production — security without reliability is an incomplete solution.

## License

[Apache License 2.0](LICENSE).

---

**HARDEX** — Open-Source Kubernetes Security Hardening. *Assess. Harden. Verify. Defend.*
