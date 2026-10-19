# Architecture

This document describes how Hardex is built today (Phase III) and where the later phases attach. Decisions with lasting consequences are recorded in [adr/](adr/).

## Pipeline

```
           ┌──────────────┐   ┌────────────────┐   ┌──────────────┐   ┌─────────────┐   ┌────────────┐
 inputs ──►│  resource    │──►│  policy        │──►│  assessment  │──►│  policy     │──►│ reporting  │──► text / JSON / SARIF
 (files,   │  Load()      │   │  SelectRules() │   │  Evaluate()  │   │  Apply()    │   │            │
  stdin)   │  Inventory   │   │  profile+config│   │  rules       │   │  waivers,   │   └────────────┘
           └──────────────┘   └────────────────┘   └──────────────┘   │  overrides  │         │
                                                                      └─────────────┘         ▼
                                                                                      verification.Compare()
                                                                                      (before vs after report)
```

`hardex.Scan` (in `hardex.go`) wires these stages together; the CLI is a thin layer over it, so every capability is also available as a Go library.

## Packages

| Package | Responsibility | Depends on |
|---|---|---|
| `core/resource` | Read untrusted YAML/JSON safely; generic object model; inventory with kind index; pod-spec extraction for all workload kinds | `goccy/go-yaml` |
| `core/finding` | Finding, Severity, Reference, Report; fingerprinting; deterministic ordering; report schema | stdlib |
| `core/assessment` | `Rule` interface, metadata validation, registry, panic-isolating evaluator | resource, finding |
| `core/policy` | Strict config parsing; profile → rule selection; waivers with expiry; severity overrides | assessment, finding |
| `core/verification` | Fingerprint-based comparison of two reports | finding |
| `kubernetes/*` | Rule implementations, one package per domain | assessment, resource, baselines |
| `baselines` | Profiles as embedded YAML; constructors for guidance citations | policy, finding |
| `integrations/reporting` | Text (sanitised), JSON, SARIF 2.1.0 | assessment, finding |
| `core/cluster` | kubeconfig/in-cluster auth; read-only-by-default API client; paginated collection into an `Inventory` | resource |
| `core/remediation` | Guarded JSON patches, inverse patches, risk-rated plans, backups, all-or-nothing apply, rollback | finding, resource |
| `kubernetes/fixes.go` | Which findings have automatic fixes, and their risk | remediation |
| `core/history` | Report store (one JSON file per assessment), trends | finding, verification |
| `core/modules` | Strictly validated declarative rules compiled to `assessment.Rule` | assessment, resource |
| `integrations/monitoring` | Record, compare, emit events per assessment | history, verification, notify |
| `integrations/notify` | JSON Lines and HMAC-signed webhook sinks | finding |

Dependency direction is strictly inward: `core/*` never imports `kubernetes/*`, `baselines` or `integrations/*`. A rule package never imports another rule package.

## The rule contract

```go
type Rule interface {
    Metadata() Metadata   // ID, title, severity, category, description, rationale, remediation, references, limitations
    Evaluate(ctx *Context) // reports findings via ctx.Report(Hit{...})
}
```

Constraints, enforced by review and tests:

- **Pure.** No I/O, no clock, no randomness, no mutation of the inventory. The same input always yields the same findings — the precondition for verification.
- **Complete metadata.** The registry rejects rules without description, rationale or remediation; a test rejects rules without references; every rule must have a detection expectation in `tests/`.
- **No secret material in findings.** `Observed` must never contain secret values; tested for the secrets fixtures.
- **One weakness, one report.** Where rules overlap (e.g. wildcards vs. specific RBAC grants), exactly one rule owns each case and the package doc says which.

Two helpers cover most rules: `ObjectRule` (evaluate objects of given kinds independently) and `InventoryRule` (reason across the whole inventory, e.g. namespace isolation).

## Input handling

All input is treated as attacker-controlled (see the [threat model](threat-model.md)):

- Files and streams are capped at 32 MiB.
- Multi-document streams are split with line tracking; leading comments are excluded so reported lines point at the object.
- Documents whose YAML aliases would expand beyond one million nodes are rejected *before* decoding.
- Unquoted YAML 1.1 booleans (`yes`, `on`, `y`, `no`, `off`, `n`) are read as booleans, matching how kubectl and the API server decode manifests; otherwise `privileged: yes` would evade detection.
- Duplicate mapping keys are rejected (they are a known technique for hiding a second value from reviewers).
- Directory walks skip hidden directories and do not follow symlinks.
- Documents without `kind` are recorded as skipped (visible in the report), not silently ignored.

## Severity model

| Severity | Meaning |
|---|---|
| critical | Directly enables node or cluster compromise on its own |
| high | Significantly expands what an attacker can reach or do; commonly a step in real attack chains |
| medium | Weakens a defensive layer or aids an attacker materially |
| low | Defence-in-depth gap |
| info | Hygiene; worth knowing, rarely worth blocking on |

Rules may raise or lower severity per occurrence where context justifies it (e.g. a hostPath mount of the container runtime socket is critical, other hostPaths high). Operators may override severities in configuration; overrides are visible in the report.

## Fingerprints

A finding's fingerprint is a hash of rule ID, resource kind/namespace/name, container and field path — deliberately excluding file path and line, so reorganising a repository does not make persisting findings look resolved. It is used for diffing and as SARIF `partialFingerprints`.

## Extension points for later phases

| Phase | Attaches at | Notes |
|---|---|---|
| II – remediation (done) | `core/remediation` + `kubernetes/fixes.go` | See [ADR 0005](adr/0005-remediation-engine.md) |
| II – live cluster (done) | `core/cluster` produces an `Inventory` | Rules are unchanged; see [ADR 0004](adr/0004-live-cluster-client.md) |
| III – continuous (done) | `core/history`, `integrations/monitoring`, `integrations/notify` | See [ADR 0006](adr/0006-continuous-monitoring.md) |
| III/IV – admission | `integrations/admission-control` running the same rules in a validating webhook | Same rule code in CI and at admission avoids drift between "what we check" and "what we block" |
| III – modules (done) | `core/modules`, `--module` | See [ADR 0007](adr/0007-declarative-rule-modules.md) |
