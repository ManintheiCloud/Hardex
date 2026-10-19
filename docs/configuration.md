# Configuration

Hardex runs with sensible defaults and needs no configuration. A policy file adapts it to an environment: choosing the profile, accepting specific risks, and adjusting severities.

**Configuration is only loaded when passed with `--config`.** Hardex never looks for a `hardex.yaml` in the working directory or the scanned tree, because whoever controls the scanned files would then control which findings are reported. In CI, keep the policy file on a protected branch or outside the repository being scanned.

## Reference

```yaml
apiVersion: hardex.dev/v1alpha1
kind: HardexConfig

# minimal | baseline | restricted | path/to/profile.yaml   (default: baseline)
# The --profile flag overrides this.
profile: baseline

# Also assess Kubernetes-managed objects: system:* RBAC, kube-system
# network isolation, and control-plane static pods under workload rules.
includeSystem: false

# Turn rules off entirely. A justification is required and is printed in
# every report.
disabledRules:
  - id: HX-SEC-001
    justification: This pipeline scans a live-cluster export, where Secrets necessarily contain data.

# Adjust a rule's severity for this environment (affects --fail-on).
severityOverrides:
  HX-WL-009: medium

# Accept specific findings as known risks.
waivers:
  - rule: HX-WL-003            # required
    kind: DaemonSet            # at least one of kind / namespace / name is required
    namespace: monitoring
    name: node-exporter
    container: node-exporter   # optional
    justification: Reads /proc and /sys read-only to export node metrics; isolated namespace, no network egress.
    owner: platform-observability
    expires: "2027-03-31"      # required; valid through the end of this day (UTC)
```

## Validation rules

Hardex rejects a configuration (exit code 2) when:

- a field is unknown (catches typos such as `waviers:`) or a key is duplicated;
- `apiVersion`/`kind` are not `hardex.dev/v1alpha1`/`HardexConfig`;
- a disabled rule has no justification;
- a waiver has no justification, no valid `expires` date, or does not narrow by kind, namespace or name (use `disabledRules` to turn a rule off);
- any referenced rule ID does not exist;
- a severity override is not one of `info`, `low`, `medium`, `high`, `critical`.

## Waiver behaviour

- A waived finding moves from `findings` to `waived` in the report, keeps its fingerprint, and records the justification, owner and expiry. In SARIF it is emitted with a `suppressions` entry.
- After its expiry date a waiver stops applying, and the report warns about it.
- A waiver that matches nothing produces a warning, so stale acceptances are cleaned up.
- In `hardex diff`, a finding waived in the "after" report is *persisting*, never *resolved*.
