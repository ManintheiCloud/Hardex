# pss-diff

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

    PSS_DIFF_SEED=<seed> go test -count=1 ./...

`PSS_DIFF_PODS` sets the number of random pods (default 3000).

It is a separate Go module, with its own `go.mod` and `go.sum`, so that the
Kubernetes libraries stay out of Hardex's own dependencies. Raise the
`k8s.io/*` versions here when a new Kubernetes minor version is released,
and update docs/baselines.md with what changed.
