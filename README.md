# HARDEX

**Kubernetes Hardening. Engineered for Hostile Environments.**

Harden the cluster. Reduce the attack surface. Establish trust.

---

Hardex is an open-source Kubernetes security hardening framework. It brings systematic, measurable and reproducible security controls to containerized infrastructure: assess, harden, verify, defend.

> **Status: Phase I (Foundation) — v0.1.0-dev.** The assessment engine, 45 rules, three profiles, policy/waiver handling, JSON/SARIF reporting and before/after verification are implemented and tested. Automated remediation, live-cluster connectivity and continuous monitoring are **not** implemented yet; see [ROADMAP.md](ROADMAP.md). No production-readiness or security certification is claimed.

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
Summary: 65 findings (critical 10, high 23, medium 18, low 12, info 2), 0 waived
```

- **Assessment** of workloads, RBAC, network segmentation, Secrets handling, control-plane static pods, and kubelet configuration — [45 rules](docs/rules.md), each with rationale, remediation, known limitations and references.
- **Complete Pod Security Standards coverage**: every Baseline and Restricted control, plus NSA/CISA recommendations PSS does not include.
- **Profiles** (`minimal` ⊂ `baseline` ⊂ `restricted`) defined as reviewable YAML, not code.
- **Policy with accountability**: disabling a rule needs a justification; waivers need a justification and an expiry date, and expired waivers resurface automatically.
- **Verification**: `hardex diff` compares two reports by stable fingerprints and refuses to call a finding "resolved" when the rule that found it did not run.
- **Machine-readable output**: versioned JSON and SARIF 2.1.0 (for GitHub code scanning and similar).
- **Fail-safe behaviour**: a crashing rule marks the assessment incomplete (exit 3) instead of silently passing; malformed configuration is an error, never a fallback.

## Quick start

Requires Go 1.24+.

```sh
go install github.com/hardex-project/hardex/cmd/hardex@latest

hardex scan ./k8s/                          # baseline profile, text output
hardex scan --profile restricted ./k8s/     # every rule
hardex scan --format sarif -o hardex.sarif ./k8s/
hardex rules                                # list rules
hardex rules HX-RBAC-004                    # explain one
```

Assess a running cluster by exporting it (read-only credentials are sufficient):

```sh
kubectl get pods,deployments,daemonsets,statefulsets,jobs,cronjobs,services,networkpolicies,\
serviceaccounts,limitranges,roles,rolebindings,clusterroles,clusterrolebindings \
  -A -o yaml | hardex scan -
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
| 1 | Findings at or above `--fail-on`; for `diff`, a regression was introduced |
| 2 | Invalid arguments, configuration or input |
| 3 | Assessment incomplete — a rule failed; results understate risk |

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
| Least privilege | Hardex needs no cluster credentials; it reads files or a `kubectl` export. |
| Defense in depth | Overlapping controls are kept (e.g. seccomp *and* AppArmor *and* capabilities), each reported on its own. |
| Operational predictability | Rules are pure functions of their input; output is deterministic and sorted. |
| Verification over assumption | `diff` distinguishes *resolved* from *unverified*; waived findings are never counted as fixed. |
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
│   ├── finding/           Finding and report model (JSON schema v1alpha1)
│   ├── policy/            Profiles selection, config, waivers, overrides
│   ├── resource/          Hardened YAML loader, object model
│   └── verification/      Before/after comparison
├── kubernetes/
│   ├── workloads/         HX-WL-*   pod specs (full PSS coverage)
│   ├── secrets/           HX-SEC-*  secret handling
│   ├── rbac/              HX-RBAC-* permissions and escalation paths
│   ├── networking/        HX-NET-*  segmentation and exposure
│   ├── controlplane/      HX-CP-*   API server, etcd, scheduler, controller manager
│   └── nodes/             HX-NODE-* kubelet configuration
├── baselines/             Profiles (YAML) and guidance citations
├── integrations/reporting Text, JSON, SARIF
├── tests/                 End-to-end detection / false-positive suites and fixtures
├── tools/gendocs          Generates docs/rules.md from rule metadata
└── docs/
```

`core/remediation/` and `integrations/admission-control/`, `integrations/monitoring/` from the original design are deliberately absent until Phase II/III; see [ROADMAP.md](ROADMAP.md).

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
