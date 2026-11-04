# Hardex

**Hardex is an open-source Kubernetes security assessment and hardening tool written in Go.** It evaluates Kubernetes configuration against a defined rule set, reports findings, compares assessments, and offers guarded remediation for selected problems. It also includes live-cluster collection, periodic monitoring, multi-cluster comparison, an optional validating admission webhook and container-image verification utilities.

**Verified scope:** v0.13.0 at [commit `bf694101`](https://github.com/ManintheiCloud/Hardex/commit/bf694101320e9ab2d08cfa7e6aac38a6580e6199), released 25 October 2026. This overview is based on inspection of source code, tests, documentation and reported CI results. It is **not** a claim of independent production certification or that every feature has been exercised on every environment.

## What Hardex actually does

A normal scan loads Kubernetes YAML/JSON resources into an inventory, selects rules from a profile, runs the rules, applies explicitly configured policy overrides/waivers and produces structured findings. Findings describe the rule, severity, affected resource, field and remediation guidance.

The repository's [rule reference](https://github.com/ManintheiCloud/Hardex/blob/main/docs/rules.md) documents **58 built-in checks**:

| Rule family | Count | Examines |
| --- | ---: | --- |
| `HX-WL-*` | 22 | Workload privileges, security contexts, host access, image references and workload hygiene |
| `HX-CP-*` | 10 | API server, etcd, audit/encryption settings and admission configurations, where visible |
| `HX-NET-*` | 9 | Namespace isolation policies, Services, Ingress, Gateway and certain controller settings |
| `HX-RBAC-*` | 8 | Overbroad permissions, cluster-admin grants, sensitive resources and workload identity reachability |
| `HX-NODE-*` | 4 | Kubelet security settings, when the configuration is available |
| `HX-SEC-*` | 3 | Credentials and secret-like values in supplied manifests/ConfigMaps |
| `HX-PATH-*` | 2 | Modeled privilege-escalation paths and workload cloud-identity associations |

The numbers count **implemented rules**, not independently certified security controls. Each rule has its own scope, assumptions and documented limitations.

### Input and assessment methods

- **Files and standard input:** `hardex scan PATH` reads `.yaml`, `.yml` and `.json` files, recursively selected directory files, multi-document YAML, Kubernetes `List` objects and stdin (`-`). It can scan rendered Helm or Kustomize output. It does not need a cluster for this mode.
- **Live-cluster collection:** `hardex scan --cluster` uses kubeconfig/in-cluster credentials and a **read-only Kubernetes client** to retrieve a defined list of resources. The supplied reader role intentionally excludes Kubernetes Secret objects.
- **Node-local collection:** `hardex scan --node` inspects accessible kubelet configuration and static pod manifests on the local filesystem. It is not a general remote node agent unless separately deployed/configured.
- **Profiles:** `minimal`, `baseline` (default for scanning) and `restricted` select rule subsets. The profile names and enabled IDs are data-defined in the repository.
- **Policy:** An expressly supplied `--config` can disable checks with a mandatory explanation, override finding severity and accept scoped risks with an expiration date. Configuration is **never implicitly loaded** from a scanned repository.
- **Extra modules:** `--module` loads declarative YAML checks; it does not load arbitrary executable plugins.

The parser bounds input size and YAML alias expansion, rejects duplicate keys and records skipped non-Kubernetes documents. Rule panics are reported as incomplete assessments instead of being mistaken for passed checks.

**Evidence:** [scan pipeline](https://github.com/ManintheiCloud/Hardex/blob/main/hardex.go) · [CLI](https://github.com/ManintheiCloud/Hardex/blob/main/cmd/hardex/main.go) · [loader](https://github.com/ManintheiCloud/Hardex/blob/main/core/resource/loader.go) · [evaluator](https://github.com/ManintheiCloud/Hardex/blob/main/core/assessment/engine.go) · [Kubernetes collector](https://github.com/ManintheiCloud/Hardex/blob/main/core/cluster/collect.go).

## Install and basic use

Use the [v0.13.0 release](https://github.com/ManintheiCloud/Hardex/releases/tag/v0.13.0) or install from source with Go 1.24 or later:

```sh
go install github.com/ManintheiCloud/Hardex/cmd/hardex@latest

hardex scan ./k8s/
hardex scan --profile restricted ./k8s/
hardex scan --format sarif -o hardex.sarif ./k8s/
hardex scan --cluster --context prod
hardex rules
hardex rules HX-RBAC-004
```

Output formats include human-readable text, JSON and SARIF for code scanning. Results depend on the selected profile, loaded resources, and any explicit waivers.

For `scan`, exit `0` means no active finding met `--fail-on` (default `high`); `1` means one did; `2` means invalid input/options; and `3` means an **incomplete** assessment (for example, a rule or required resource collection failed). An exit `0` is *not* a declaration that the cluster is secure.

## Features beyond a one-time scan

### Compare before and after

`hardex diff` compares two JSON reports by stable finding fingerprints and distinguishes **resolved**, **introduced**, **persisting** and **unverified** findings. A finding that disappears because its rule was not evaluated in the second scan is **unverified**, not resolved.

```sh
hardex scan --format json --fail-on none -o before.json ./k8s/
# Change the configuration and rescan.
hardex scan --format json --fail-on none -o after.json ./k8s/
hardex diff before.json after.json
```

[Implementation](https://github.com/ManintheiCloud/Hardex/blob/main/core/verification/compare.go).

### Plan or apply selected remediation

`hardex fix` creates risk-rated plans for supported fixes. Its default behavior is a **dry run**. `--out` writes patched manifests or a Kustomize overlay without modifying the input files. **Only a subset of findings has automatic fixes**; application-specific decisions remain manual.

Live changes require `--cluster --rules ... --apply`, adequate write permissions, and interactive confirmation or `--yes`. The apply path creates a backup, uses guarded JSON patches, re-assesses the result and attempts rollback after failures or failed verification. A separate `hardex rollback` command consumes the backup.

```sh
hardex fix ./k8s --out ./k8s-fixed
hardex fix --cluster --rules HX-WL-004,HX-WL-008 --apply
```

Backups may include sensitive workload fields. Changes can affect availability, and rollback is not a universal guarantee of recovery. See [remediation and its supported fixes](https://github.com/ManintheiCloud/Hardex/blob/main/docs/remediation.md).

### Monitor configuration drift

`hardex scan --history` / `hardex history` save and summarize assessments. `hardex monitor` periodically evaluates manifests or a cluster (or runs once under cron/CI), compares them with prior results or an approved JSON baseline, and can send JSON Lines events and HTTPS webhooks. HMAC webhook signatures require `HARDEX_WEBHOOK_SECRET` to be configured.

```sh
hardex monitor --once --cluster --history ./hardex-history
hardex monitor --cluster --interval 1h --history ./hardex-history
```

This is **periodic configuration assessment**, not real-time process, packet or network intrusion detection. See [monitoring](https://github.com/ManintheiCloud/Hardex/blob/main/docs/monitoring.md).

### Compare environments

`hardex fleet` scans multiple kubeconfig contexts; `hardex compare` compares multiple saved JSON reports and highlights differences in finding/control status. `hardex report` creates posture scores and HTML/Markdown evidence reports.

The score is computed from weighted rule outcomes for **rules actually evaluated**. It is not a certification, penetration-test result or proof of compliance. See [scoring](https://github.com/ManintheiCloud/Hardex/blob/main/docs/scoring.md).

### Validate admission requests

`hardex admission` serves an HTTPS Kubernetes validating webhook. Its modes are:

| Mode | Behavior |
| --- | --- |
| `warn` (default) | Admit requests and return applicable findings as warnings |
| `enforce` | Reject requests with findings at/above `--deny-at`; reject requests that cannot be evaluated |
| `audit` | Admit requests and log decisions |

The webhook assesses **one object per admission request**. Rules needing a cluster-wide inventory—such as namespace default-deny checks, effective workload RBAC reachability and chained attack paths—**do not run there**. `--preflight` can identify existing objects likely to be rejected, but does not predict all pods created later by controllers. Enforcing without planning can disrupt workloads or storage provisioning. The webhook only acts when deployed and configured; installing the CLI does not turn it on.

See [admission implementation and limitations](https://github.com/ManintheiCloud/Hardex/blob/main/docs/admission.md).

### Inspect image references, signatures and known SBOM vulnerabilities

`hardex images` extracts image references and, when allowed network access, resolves their digests and checks signatures using specified cosign public keys or keyless Sigstore identity policies. `hardex verify-blob` checks file signatures with a Sigstore bundle. Verification logic can work offline against a trusted root, but fetching remote image data still needs a registry connection; `images --offline` is restricted to reference inspection.

Optional `--vulns` reads supported image SBOM attestations and queries OSV for known vulnerabilities associated with declared package versions. Without an SBOM, a supported package record, or a successful lookup, Hardex cannot claim the image has no vulnerabilities. **Signature validity does not establish that code is harmless.**

See [image verification](https://github.com/ManintheiCloud/Hardex/blob/main/docs/image-verification.md).

## Architecture in brief

The main [`hardex.Scan`](https://github.com/ManintheiCloud/Hardex/blob/main/hardex.go) function:

1. Loads or receives a Kubernetes object inventory.
2. Selects built-in and expressly loaded module rules using the configured profile.
3. Runs checks and records findings/errors.
4. Deduplicates relevant controller-owned findings; applies severity overrides and expiring waivers.
5. Produces a versioned report for output, history, scoring or comparison.

Separate packages handle Kubernetes collection, guarded remediation, monitoring, admission, image verification, scoring and fleet views. The core scan logic is available as a **Go library**, in addition to the CLI. See the [architecture guide](https://github.com/ManintheiCloud/Hardex/blob/main/docs/architecture.md).

## What Hardex does **not** establish

- **No proof of compromise.** Attack-path results model possible escalation chains from Kubernetes permissions, workload properties and available node placement data; they do not prove an attacker exploited the path.
- **No universal runtime visibility.** Hardex is not an EDR, packet sniffer, live memory inspector or continuous exploit detector.
- **No omniscient cloud view.** Cloud identity reachability depends on `--cloud-iam` exports; managed control-plane settings and individual node files can be inaccessible.
- **No live Secret-value scan.** The read-only cluster collection deliberately excludes Secret objects. Secret/credential checks on supplied manifests are a different operation.
- **No universal automatic fix or admission enforcement.** Remediation is selective and potentially disruptive; admission covers only object-local rules and applies only if configured.
- **No exhaustive image vulnerability coverage.** OSV output depends on image SBOM data and known version-based vulnerability records.
- **No absolute “secure” verdict.** An absence of findings means only that evaluated rules did not report active violations for the available data. Incomplete data and unsupported conditions are limitations, not clean passes.

[Threat model](https://github.com/ManintheiCloud/Hardex/blob/main/docs/threat-model.md) · [compatibility](https://github.com/ManintheiCloud/Hardex/blob/main/docs/compatibility.md) · [roadmap](https://github.com/ManintheiCloud/Hardex/blob/main/ROADMAP.md).

## Implementation and testing evidence

The v0.13.0 repository includes Go source, test fixtures and automated test suites. GitHub Actions reports [successful main-branch CI for the release commit](https://github.com/ManintheiCloud/Hardex/actions/runs/40146540898) and a [successful end-to-end run on 3 November 2026](https://github.com/ManintheiCloud/Hardex/actions/runs/41640412448). Those are **reported test outcomes**, not an independent audit or a warranty of production readiness.

**Project links:** [Repository](https://github.com/ManintheiCloud/Hardex) · [Release v0.13.0](https://github.com/ManintheiCloud/Hardex/releases/tag/v0.13.0) · [All rules](https://github.com/ManintheiCloud/Hardex/blob/main/docs/rules.md) · [Configuration](https://github.com/ManintheiCloud/Hardex/blob/main/docs/configuration.md) · [Contributing](https://github.com/ManintheiCloud/Hardex/blob/main/CONTRIBUTING.md) · [Security reporting](https://github.com/ManintheiCloud/Hardex/blob/main/SECURITY.md).

**License:** Apache-2.0.
