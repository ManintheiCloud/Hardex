# Rule modules

Organisations and the community can add checks without writing Go, as **declarative rule modules** in YAML. Design: [ADR 0007](adr/0007-declarative-rule-modules.md).

```sh
hardex scan --module ./policies/org.yaml ./k8s
hardex monitor --cluster --module ./policies/org.yaml
hardex rules --module ./policies/org.yaml            # list built-in and module rules
hardex rules --module ./policies/org.yaml ORG-SC-001
```

Modules are loaded only when named with `--module`; like configuration, they are never discovered from the scanned files. Module rules run in addition to the selected profile and can be disabled, re-rated or waived in [configuration](configuration.md) like any built-in rule.

## Format

```yaml
apiVersion: hardex.dev/v1alpha1
kind: RuleModule
name: example-organization-policy
description: Organisation-specific guardrails.
rules:
  - id: ORG-SC-001                  # 2–4 uppercase parts; HX- is reserved
    title: Image from an unapproved registry
    severity: high                  # info | low | medium | high | critical
    category: supply-chain          # free text; default "custom"
    description: What the rule checks.
    rationale: Why it matters — what an attacker gains.
    remediation: How to fix it.
    limitations: Optional known blind spots.
    references:
      - {framework: NSA-CISA, control: "…", url: "https://…"}
    match:
      scope: container              # object | podSpec | container
      kinds: [Deployment]           # required for object scope; optional filter otherwise
      namespaces: [payments]        # optional allow-list
      excludeNamespaces: [kube-system]
    violation:                      # a finding is reported when this holds
      path: image
      op: notMatches
      pattern: '^registry\.example\.com/'
    message: image is not from registry.example.com   # optional; defaults to title
```

See [`examples/modules/organization-policy.yaml`](../examples/modules/organization-policy.yaml) for a complete module.

### Scopes

| Scope | `path` is relative to | Applies to |
|---|---|---|
| `object` | the object root (`metadata…`, `spec…`) | objects of `kinds` |
| `podSpec` | the pod spec | every workload (Pod, Deployment, CronJob, …, and Argo Rollouts, Knative Services and Revisions, KEDA ScaledJobs, OpenKruise CloneSets and BroadcastJobs) |
| `container` | each container, including init and ephemeral containers | every workload |

### Paths

Dotted names, with brackets for keys containing dots or slashes and for array elements: `metadata.labels[app.kubernetes.io/name]`, `spec.containers[0].image`, `spec.containers[*].resources.limits.cpu`. `[*]` expands to every element (or every value of a map); each match is evaluated and reported separately.

### Operators

| `op` | Violation when | Needs |
|---|---|---|
| `absent` | the path does not exist | — |
| `exists` | the path exists | — |
| `equals` / `notEquals` | the value equals / differs from `value` | `value` |
| `in` / `notIn` | the value is / is not one of `values` | `values` |
| `matches` / `notMatches` | a string value matches / does not match `pattern` (RE2) | `pattern` |
| `greaterThan` / `lessThan` | a numeric value is above / below `value` | `value` |

Comparison operators only fire on paths that exist; pair them with an `absent` rule if a missing value is also a violation. Quantities such as `500m` or `1Gi` are strings, so compare them with patterns, not `greaterThan`.

## Validation

Modules are validated strictly and fail closed: unknown fields, missing description/rationale/remediation, reserved or malformed IDs, unknown operators, missing operands and invalid regular expressions are all errors (exit 2). A module that fails to load never results in a scan that silently checks less.
