# k8s-diff

Differential tests of Hardex against Kubernetes' own implementations of the same decisions. Each run uses a new seed, printed in the log and the job's annotations.

## Pod Security Standards (`pss_test.go`)

Checks Hardex's Pod Security Standards rules against the reference
implementation: the policy package of the PodSecurity admission controller
(`k8s.io/pod-security-admission/policy`), at its latest level version.

Each run builds a few thousand pods. Each starts from a pod that meets the
Restricted level and gets one to four random changes from a list of edge
values for every control (a capability in lower case or with a `CAP_`
prefix, a probe host of `localhost`, a Windows pod, an ephemeral container,
`hostUsers: false` with UID 0, and so on). A few fixed edge cases are added.
Every pod is judged twice:

- by PodSecurity, at Baseline and at Restricted;
- by Hardex (`restricted` profile): a finding from a PSS rule
  (docs/baselines.md, "Pod Security Standards coverage") at the matching
  level counts as a violation. Rules outside the standard are ignored.

Any pod where the two disagree fails the test, with its spec, the changes
it received, PodSecurity's reasons and Hardex's findings.

The seed changes every run and is printed; reproduce a failure with

    PSS_DIFF_SEED=<seed> go test -count=1 -run PodSecurity ./...

`PSS_DIFF_PODS` sets the number of random pods (default 3000).

## RBAC (`rbac_test.go`)

Against `k8s.io/component-helpers/auth/rbac/validation.Covers`, the rule
comparison the API server uses to prevent privilege escalation (a rule
allows a request exactly when it covers it):

- **Rule matching** (`rbac.RuleAllows`, which HX-RBAC-008 uses to decide
  what a service account can do): random rules over a vocabulary of edge
  values (`*`, `*/exec`, `pods/*`, mixed case, resource names) against every
  request built from that vocabulary. Any difference fails.
- **The defaults check** (`rbac.GrantsNoMoreThanDefault`, which decides that
  an RBAC object is a Kubernetes default and is not reported): rule sets
  derived from each default with permissions changed or added. It may
  reject a set that only restates the default differently, but a set it
  accepts must be covered by the default; otherwise an added permission
  would be hidden.

`RBAC_DIFF_SEED` reproduces a run.

## The module

It is a separate Go module, with its own `go.mod` and `go.sum`, so that the
Kubernetes libraries stay out of Hardex's own dependencies. Raise the
`k8s.io/*` versions here when a new Kubernetes minor version is released,
and update docs/baselines.md with what changed.
