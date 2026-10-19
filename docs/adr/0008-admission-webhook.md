# ADR 0008: Admission control with the same rules, one object at a time

- Status: accepted
- Date: 2026-10-19

## Decision

- `hardex admission` serves AdmissionReview v1 and evaluates the submitted object with the rules of the selected profile and modules — the same code that runs in `scan`, so what CI checks and what the cluster enforces cannot drift apart.
- Rules declare `NeedsInventory` when their verdict depends on other objects. These are skipped at admission rather than producing false denials for context the webhook cannot see.
- Three modes: `warn` (default, for rollout), `enforce`, `audit`. Enforce mode **fails closed**: a request that cannot be evaluated is rejected, consistent with HX-CP-009.
- The shipped configuration uses `failurePolicy: Fail`, two replicas with a disruption budget, and excludes only the namespaces needed to recover the webhook.
- Serving certificates are reloaded on change; a failed rotation keeps the last good certificate.
- The webhook holds no Kubernetes credentials.

## Consequences

- Admission decisions are immediate and consistent with reports; cross-object analysis remains the job of `scan`/`monitor`.
- A Hardex outage blocks guarded changes in enforce mode. This is intended (a policy that fails open is bypassable) and mitigated by high availability and namespace exclusions.
