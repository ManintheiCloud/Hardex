# Threat model

Version 0.6.0. This document has two parts: the threats Hardex helps defend **clusters** against (what the rules are for), and the threats to **Hardex itself** (how the tool must behave). Both are living documents; propose changes by pull request.

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
| T10 | A4 ships a modified image under an existing reference | HX-WL-011, 012; `hardex images` keyless/key signature verification and SBOM vulnerability lookup |
| T11 | A2 exhausts node resources (denial of service) | HX-WL-010 |
| T12 | Any adversary operates undetected | HX-CP-003 (audit logging) |
| T13 | Admission guardrails bypassed | HX-CP-005 (AlwaysAdmit, PodSecurity disabled), HX-CP-009 (fail-open webhooks) |
| T14 | A compromised or spoofed admission webhook rewrites or approves objects | HX-CP-010 (webhooks served from outside the cluster; mutating webhooks high) |
| T15 | A2/A3 chains moderate weaknesses into a full compromise, including through node co-location | HX-PATH-001 (placement-aware paths to cluster admin, cloud identity, node root) |
| T16 | A2 uses a workload's federated token against the cloud account | HX-PATH-002 (inventory of cloud identities), HX-PATH-001 (chains into them) |
| T17 | A tenant attaches routes to a shared Gateway and intercepts another application's traffic | HX-NET-009; HX-NET-005/008 (TLS) |

### Known gaps (not yet covered)

These are tracked in [ROADMAP.md](../ROADMAP.md):

- Runtime detection (behaviour after compromise) — out of scope; Hardex is a posture tool.
- Image *contents* beyond the SBOM: vulnerabilities in packages the SBOM misses, and reachability of vulnerable code.
- Permissions of the cloud roles that workload identities assume (Hardex sees the binding, not the cloud policy); EKS Pod Identity associations, which live outside Kubernetes.
- Taints and preferred affinity in co-location analysis; service mesh mTLS; managed control planes whose flags are not visible.
- Admission webhook namespace exclusions.

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
| H11 | Compromised dependency or tampered release | One direct dependency; `go.sum` pinned; govulncheck in CI; releases signed keylessly with Sigstore and attested with SLSA build provenance; SBOM published (implemented) |
| H12 | Compromised CI action | Actions pinned by commit SHA; least-privilege workflow permissions (implemented) |
| H13 | Remediation causes an outage | Risk rating per fix, `--max-risk` default medium; dry-run default; `--apply` needs explicit `--rules` and confirmation; all-or-nothing apply with automatic rollback; post-change re-assessment; `hardex rollback` (implemented, tested) |
| H14 | Scanner credentials become a high-value target | Collector never reads Secrets; shipped `hardex-reader` role is get/list on collected kinds only; clients are read-only unless the apply path requests write (implemented, tested) |
| H15 | Credentials sent to an impostor or in clear text | `http://` servers and `insecure-skip-tls-verify` refused with no override; TLS ≥ 1.2; redirects never followed (implemented, tested) |
| H16 | Patch computed from a stale read overwrites newer state (TOCTOU) | Patches test `metadata.resourceVersion` and every value they replace (implemented, tested) |
| H17 | Rollback overwrites someone else's later change | Inverse patches test the values Hardex set; rollback refuses a different API server than the backup's (implemented, tested) |
| H18 | Hostile object names write files outside `--out` | Output file names are sanitised to a safe character set (implemented, tested) |
| H19 | Partial collection reported as a clean cluster | Unreadable resources make the assessment incomplete (exit 3) unless `--allow-partial` (implemented, tested) |
| H20 | Forged or replayed alerts sent to the receiver | Webhooks are HTTPS-only and HMAC-SHA256 signed over timestamp and body; `notify.Verify` enforces a time window (implemented, tested) |
| H21 | Manifest content injects mentions or links into chat alerts | Object names escaped in Slack payloads (implemented, tested) |
| H22 | Alerts silently lost | Delivery failures are reported and make one-shot monitoring exit 3 (implemented, tested) |
| H23 | Webhook secret leaks via process listings or shell history | Secret read only from `$HARDEX_WEBHOOK_SECRET`; no flag (implemented) |
| H24 | A rule module weakens or bypasses assessment | Modules are loaded only via `--module` (never from scanned content), validated strictly, cannot reuse `HX-` IDs, and use RE2 (no catastrophic backtracking); invalid modules fail the run (implemented, tested) |
| H25 | History exposes weaknesses to other local users | History files and directory are created owner-only (0600/0700) (implemented, tested) |
| H26 | Two distinct findings share a fingerprint and are conflated by diff/history | Engine disambiguates collisions; test enforces uniqueness on fixtures (implemented, tested) |
| H27 | Admission webhook bypassed by making it unavailable | Enforce mode fails closed; shipped config uses `failurePolicy: Fail`, two replicas, a PDB and minimal namespace exclusions (implemented, tested) |
| H28 | Admission rejects valid objects for context it cannot see | Rules declaring `NeedsInventory` are skipped at admission (implemented, tested) |
| H29 | Oversized or malformed AdmissionReview exhausts the webhook | 3 MiB body limit, strict decoding, server timeouts (implemented, tested) |
| H30 | Certificate rotation breaks the webhook | Certificates reloaded on change; a broken rotation keeps the last good pair (implemented, tested) |
| H31 | Manifest content injects markup into evidence reports | `html/template` escaping; Markdown neutralisation (implemented, tested) |
| H32 | Evidence report altered after the fact | Report embeds the SHA-256 of its source JSON report (implemented, tested) |
| H33 | Registry or proxy substitutes image content | Manifests and blobs fetched by digest are re-hashed and compared (implemented, tested) |
| H34 | A valid signature for one image is replayed onto another | A signature verifies an image only if its payload names that exact digest (implemented, tested) |
| H35 | Unsupported signature types reported as verified | Keyless verification requires an identity policy; unsupported log entry types (Rekor v2) are reported as invalid with the reason, never as verified (implemented, tested) |
| H36 | A bug in the YAML library crashes Hardex on malformed input | Every YAML decode goes through `internal/yamlsafe`, which turns library panics into errors; continuous fuzzing in CI; the crashing input found by fuzzing is a permanent regression test (implemented, tested) |
| H37 | A CNI policy is misread as isolating, hiding an open namespace | Only unambiguous default-deny forms count, following each project's reference docs; everything else is reported (implemented, tested) |
| H38 | Forged keyless signature: a certificate from an untrusted CA, a signature never logged, a backdated or expired certificate, or a bundle replayed onto another artifact | Full offline verification against the trusted root: Fulcio chain at a *verified* signing time (signed entry timestamp or RFC 3161), SCT, Rekor body consistency with signature/certificate/digest, inclusion proof against a signed checkpoint, identity and issuer policy; tested against a real bundle and with mutations; bundle and timestamp parsers fuzzed (implemented, tested) |
| H39 | Stale embedded Sigstore trust root after key rotation | `--trusted-root` accepts a current root; the embedded root is refreshed from sigstore/root-signing (checked against its TUF targets hash) at release time (implemented; refresh is a release step) |
| H40 | Vulnerability lookup leaks inventory or reports "clean" without data | Only package URLs are sent to OSV; images without an SBOM are reported as unknown and fail `--fail-on-vulns` (implemented, tested) |
| H41 | Node scanner becomes a root-equivalent credential | Node configuration is read from read-only file mounts with no API token and no network; `nodes/proxy` is never used (implemented) |

### Residual risks

- Hardex can only assess what it is given. An incomplete export produces an incomplete assessment; the report lists inputs and object counts so coverage is visible, but it cannot detect what is missing.
- Static analysis cannot observe runtime defaults that differ by cluster (e.g. kubelet `seccompDefault`). Each rule documents such limitations.
- Heuristic rules (HX-SEC-002) have both false positives and false negatives by design.
