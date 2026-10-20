# Continuous monitoring

Security posture changes as clusters, workloads and permissions change. Hardex records every assessment, compares each with the last, and tells you what changed. Design: [ADR 0006](adr/0006-continuous-monitoring.md).

## Record history

```sh
hardex scan --cluster --history ./hardex-history --keep 720
hardex history ./hardex-history          # trend table
hardex history ./hardex-history --format json --last 30
```

Each assessment is stored as a JSON report (mode 0600) named by its UTC time. `hardex history` shows, per assessment, the totals by severity and how many findings were introduced and fixed since the previous one; it flags incomplete assessments, unverified results and changed inputs.

## Monitor for drift

```sh
# Long-running: assess every hour until stopped
hardex monitor --cluster --interval 1h --history ./hardex-history

# One-shot (cron, CI, the in-cluster CronJob): exit 1 on new high/critical findings
hardex monitor --once --cluster --history ./hardex-history --fail-on high
```

`monitor` works on manifest directories too (`hardex monitor --once ./k8s`), which makes it a drift gate for GitOps repositories.

### Approved baseline

Pass an approved report with `--baseline`. Every event then also carries the number of findings that have **drifted** from the approved state, and one-shot runs fail on drift rather than only on change since the last run:

```sh
hardex scan --cluster --format json -o approved.json --fail-on none   # after review
hardex monitor --once --cluster --baseline approved.json
```

## Events

Each assessment produces:

| Event | When |
|---|---|
| `finding.introduced` | A finding at or above `--notify-min` (default `medium`) appeared since the previous assessment |
| `finding.resolved` | Such a finding disappeared and the rule that found it ran again |
| `assessment.incomplete` | Rules failed or cluster resources could not be read |
| `events.dropped` | Undelivered events were discarded after a long outage of the sink (see below) |
| `assessment.completed` | Always; summary counts, and `drift` when a baseline is set |

Events go to JSON Lines (`--events -` for stdout, the default, or `--events file.jsonl`) for log pipelines and SIEMs, and optionally to a webhook.

### Webhooks

```sh
export HARDEX_WEBHOOK_SECRET="$(openssl rand -hex 32)"
hardex monitor --cluster --webhook https://hooks.example.com/hardex
hardex monitor --cluster --webhook https://hooks.slack.com/services/... --webhook-format slack
```

- HTTPS only; redirects are not followed; transient failures (429, 5xx, network) are retried.
- Generic payload: `{"source": "hardex", "events": [...]}`.
- Every request carries `X-Hardex-Timestamp` and `X-Hardex-Signature-256: sha256=<hex>`, an HMAC-SHA256 over `timestamp + "." + body` using `$HARDEX_WEBHOOK_SECRET`. Receivers should verify the signature with a constant-time comparison and reject timestamps older than a few minutes. Go receivers can use `notify.Verify`.
- The secret is read only from the environment, never from a flag (flags appear in process listings).
- Slack format renders a short summary; object names are escaped so manifests cannot inject mentions or links.

A notification that cannot be delivered is a monitoring failure: one-shot runs exit 3. The events are not lost: they are kept in the history directory (`undelivered-<sink>.json`) and delivered, marked `"late": true`, together with the next assessment's events once the sink is reachable again. Without this, an alert missed during an outage would never be repeated, because the next run compares with the assessment already recorded. At most 1000 events are kept per sink; if older ones have to be dropped, the next delivered batch starts with an `events.dropped` event saying how many.

## In-cluster

[`deploy/hardex-monitor.yaml`](../deploy/hardex-monitor.yaml) runs `hardex monitor --once --in-cluster` hourly with history on a PersistentVolumeClaim and a signed webhook. Apply [`deploy/hardex-reader.yaml`](../deploy/hardex-reader.yaml) first.
