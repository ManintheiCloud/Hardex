# Writing a rule

A rule is a small, pure Go value with complete metadata. This guide walks through adding one end to end. Read [architecture.md](architecture.md#the-rule-contract) first.

## 1. Check it belongs in Hardex

Open a "Rule proposal" issue first for anything non-trivial. A good rule:

- describes a weakness with a concrete attacker benefit (state it in the rationale);
- is decidable from the objects Hardex reads, or documents precisely what it cannot see;
- does not duplicate an existing rule (search `docs/rules.md`);
- has a clear, safe remediation.

## 2. Pick an ID and severity

IDs are `HX-<AREA>-NNN` and are never reused, even if a rule is retired. Areas: `WL` workloads, `SEC` secrets, `RBAC`, `NET` networking, `CP` control plane, `NODE` nodes. Choose severity using the table in [architecture.md](architecture.md#severity-model).

## 3. Implement

Put the rule in the matching `kubernetes/<area>` package and add it to that package's `Rules()`.

```go
var hostPorts = eachContainer(assessment.Metadata{
    ID:          "HX-WL-014",
    Title:       "Host port bound",
    Severity:    finding.Medium,
    Category:    assessment.CategoryWorkloads,
    Description: "Detects containers that bind a port directly on the node with hostPort.",
    Rationale:   "hostPort exposes the container on the node's address, bypassing ...",
    Remediation: "Remove hostPort and expose the workload through a Service ...",
    References:  []finding.Reference{baselines.PSS("Baseline", "Host Ports")},
    Limitations: "", // say what the rule cannot see, if anything
}, func(ctx *assessment.Context, obj *resource.Object, pod map[string]any, prefix string, c resource.Container) {
    for i, p := range resource.Maps(c.Spec, "ports") {
        if n, ok := resource.Number(p, "hostPort"); ok && n > 0 {
            ctx.Report(assessment.Hit{
                Object: obj, Container: c.Name,
                Path:     fmt.Sprintf("%s.ports[%d].hostPort", c.Path(prefix), i),
                Observed: fmt.Sprint(n),
                Message:  fmt.Sprintf("container %q binds host port %v", c.Name, n),
            })
        }
    }
})
```

Guidelines:

- Read fields only through `resource.Map/String/Bool/Number/...`. They return zero values on missing or mistyped input instead of panicking.
- Report the most specific `Path` you can, and the `Observed` value — but **never secret material**.
- For pod-level settings that containers can override (runAsNonRoot, seccompProfile, ...), resolve with `effective()`; a common false-positive source is ignoring pod-level defaults.
- Consider every workload kind (`eachPod`/`eachContainer` do this), init and ephemeral containers, Windows pods, and system objects (`ctx.Options.IncludeSystem`).
- Cite guidance via `baselines.PSS/NSA/CIS/K8s`, following the [mapping policy](baselines.md#mapping-policy).

## 4. Add it to profiles

Add the ID to `baselines/profiles/restricted.yaml`, and to `baseline.yaml`/`minimal.yaml` if it meets their bar. Profiles must stay nested.

## 5. Test it

1. Add a triggering case to `tests/fixtures/insecure/` and an expectation to `insecureExpectations` in `tests/detection_test.go` (the suite fails if a rule has none).
2. Make sure `tests/fixtures/hardened/` still produces zero findings. If your rule fires there, either the fixture is genuinely insecure (fix the fixture and explain why in the PR) or the rule has a false positive.
3. Add focused unit tests for any parsing or matching logic, including near-misses that must *not* fire.

## 6. Regenerate docs and check

```sh
go run ./tools/gendocs
make check
```
