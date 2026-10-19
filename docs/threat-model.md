# Threat model

Version 0.2 — Phase II. This document has two parts: the threats Hardex helps defend **clusters** against (what the rules are for), and the threats to **Hardex itself** (how the tool must behave). Both are living documents; propose changes by pull request.

---

## Part 1 — Threats to the clusters Hardex assesses

### Assets

| Asset | Why it matters |
|---|---|
| Cluster control (API server authority) | Equivalent to control of every workload and secret |
| etcd data | Full cluster state, including all Secrets |
| Node root | Access to every pod on the node, kubelet credentials, often cloud credentials |
| Workload credentials (service account tokens, mounted secrets) | Lateral movement and data access |
| Application data and availability | The reason the cluster exists |
| Audit trail | The ability to detect and investigate everything above |

### Adversaries

| ID | Adversary | Starting position |
|---|---|---|
| A1 | External attacker | Network reach to exposed services, load balancers, or (mis)exposed control-plane/kubelet ports |
| A2 | Compromised workload | Code execution in one container (vulnerable app, malicious dependency) |
| A3 | Malicious or compromised insider / CI identity | Valid credentials with some RBAC permissions |
| A4 | Supply-chain attacker | Ability to publish or alter a container image or manifest |
| A5 | Node-level attacker | Root on one node (from A2 via escape, or infrastructure compromise) |

### Attack paths and the controls that interrupt them

| # | Path | Interrupted by |
|---|---|---|
| T1 | A2 escapes container to node | HX-WL-001, 002, 003, 006, 015–017, 020 (PSS Baseline); defence in depth from HX-WL-004, 005, 007, 008, 009 |
| T2 | A2 uses mounted service account token against the API | HX-WL-013 (no token), HX-RBAC-* (token is low-value) |
| T3 | A2/A3 escalates via RBAC (bind/escalate/impersonate, token minting, pod creation as a stronger SA, exec into stronger pods) | HX-RBAC-001, 002, 004, 005, 006 |
| T4 | A2/A3 reads Secrets | HX-RBAC-003, HX-SEC-001, HX-SEC-002, HX-CP-007 |
| T5 | A2 moves laterally over the pod network, reaches metadata endpoints or internal admin services | HX-NET-001, 002; HX-WL-002 (hostNetwork) |
| T6 | A1 reaches internal services through unintended exposure | HX-NET-003, HX-NET-004, HX-WL-014 |
| T7 | A1 abuses unauthenticated API server or kubelet access | HX-CP-001, 002, HX-RBAC-007, HX-NODE-001, 002, 003 |
| T8 | A5 or network attacker reads/modifies etcd or intercepts control-plane traffic | HX-CP-006, 008 |
| T9 | A5 tampers with other nodes or pods via kubelet credentials | HX-CP-005 (NodeRestriction) |
| T10 | A4 ships a modified image under an existing reference | HX-WL-011, 012 |
| T11 | A2 exhausts node resources (denial of service) | HX-WL-010 |
| T12 | Any adversary operates undetected | HX-CP-003 (audit logging) |
| T13 | Admission guardrails bypassed | HX-CP-005 (AlwaysAdmit, PodSecurity disabled) |

### Known gaps (not yet covered)

These are tracked in [ROADMAP.md](../ROADMAP.md):

- Image vulnerability and signature verification (A4) — Hardex checks references, not image contents or provenance.
- Runtime detection (behaviour after compromise) — out of scope; Hardex is a posture tool.
- RBAC *reachability*: which pods actually hold which effective permissions through bindings and service accounts.
- Cloud-provider IAM bindings to Kubernetes identities (IRSA, Workload Identity).
- CNI-specific network policy types; ingress controller configuration; service mesh mTLS.
- Kubelet flags (as opposed to config files); managed control planes whose flags are not visible.
- Admission webhook configuration (failure policy, namespace exclusions).

---

## Part 2 — Threats to Hardex itself

### Assets

- **Integrity of results.** A false "clean" report is the most damaging failure: it converts a security tool into a source of false assurance.
- **The operator's environment.** Hardex runs in terminals and CI with access to source code and sometimes cluster exports.
- **Secrets present in inputs.** Cluster exports and manifest repositories can contain credentials.

### Trust boundaries

1. **Input content** (manifests, exports, profiles) — untrusted. A pull request author controls the manifests a CI job scans.
2. **Configuration** (`--config`) — trusted, because the operator chooses it explicitly.
3. **Hardex binary and its dependencies** — trusted after supply-chain verification.

### Threats and mitigations

| # | Threat | Mitigation (status) |
|---|---|---|
| H1 | Attacker suppresses findings by committing a config/waiver file into the scanned repository | Configuration is never discovered implicitly; it must be passed with `--config` (implemented). CI should load config from a protected path. |
| H2 | Attacker hides a value from reviewers with duplicate YAML keys | Duplicate keys are rejected (implemented, tested) |
| H2b | Attacker exploits YAML dialect differences: Kubernetes resolves unquoted `yes`/`on`/`y` as `true` (YAML 1.1), a YAML 1.2 parser reads strings — so `privileged: yes` would run privileged yet evade detection | Loader normalises YAML 1.1 booleans to match Kubernetes before evaluation; regression fixture `tests/fixtures/evasion` (implemented, tested) |
| H3 | Resource exhaustion via YAML alias expansion ("billion laughs") or huge files | Alias expansion bounded before decoding; 32 MiB input cap (implemented, tested) |
| H4 | Terminal escape sequences in object names manipulate the operator's terminal or hide output | Control characters escaped in text output (implemented, tested) |
| H5 | A rule crashes or hangs on crafted input and the scan reports clean | Panics isolated per rule, recorded as errors, exit code 3; loader fuzz test with hang detection (implemented, tested) |
| H6 | Input files outside the intended tree read via symlinks | Directory walks do not follow symlinks (implemented) |
| H7 | Secret values copied into reports, CI logs or SARIF uploads | Rules report key counts or names only, values redacted (implemented, tested for fixtures) |
| H8 | Typo in configuration silently disables a check | Unknown fields rejected; disabled rules require justification and are listed in every report (implemented) |
| H9 | Accepted risk lingers forever | Waivers require an expiry date; expired waivers stop applying and warn; unused waivers warn (implemented) |
| H10 | "Resolved" claimed because a rule did not run | `diff` reports such findings as unverified, with caveats (implemented) |
| H11 | Compromised dependency | One direct dependency; `go.sum` pinned; govulncheck in CI (implemented). Signed releases with provenance (planned, Phase I) |
| H12 | Compromised CI action | Actions pinned by commit SHA; least-privilege workflow permissions (implemented) |
| H13 | Remediation causes an outage | Risk rating per fix, `--max-risk` default medium; dry-run default; `--apply` needs explicit `--rules` and confirmation; all-or-nothing apply with automatic rollback; post-change re-assessment; `hardex rollback` (implemented, tested) |
| H14 | Scanner credentials become a high-value target | Collector never reads Secrets; shipped `hardex-reader` role is get/list on collected kinds only; clients are read-only unless the apply path requests write (implemented, tested) |
| H15 | Credentials sent to an impostor or in clear text | `http://` servers and `insecure-skip-tls-verify` refused with no override; TLS ≥ 1.2; redirects never followed (implemented, tested) |
| H16 | Patch computed from a stale read overwrites newer state (TOCTOU) | Patches test `metadata.resourceVersion` and every value they replace (implemented, tested) |
| H17 | Rollback overwrites someone else's later change | Inverse patches test the values Hardex set; rollback refuses a different API server than the backup's (implemented, tested) |
| H18 | Hostile object names write files outside `--out` | Output file names are sanitised to a safe character set (implemented, tested) |
| H19 | Partial collection reported as a clean cluster | Unreadable resources make the assessment incomplete (exit 3) unless `--allow-partial` (implemented, tested) |

### Residual risks

- Hardex can only assess what it is given. An incomplete export produces an incomplete assessment; the report lists inputs and object counts so coverage is visible, but it cannot detect what is missing.
- Static analysis cannot observe runtime defaults that differ by cluster (e.g. kubelet `seccompDefault`). Each rule documents such limitations.
- Heuristic rules (HX-SEC-002) have both false positives and false negatives by design.
