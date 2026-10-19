# ADR 0006: Continuous monitoring from recorded assessments

- Status: accepted
- Date: 2026-10-19

## Context

Phase III requires drift detection, recurring assessments, historical comparison and event reporting. These could be built as a resident controller with its own state store, or as repeated runs of the existing assessment with file-based history.

## Decision

- Every assessment can be recorded as a standard JSON report in a history directory (`scan --history`, `monitor`). The report format is already versioned and is the only state.
- `hardex monitor` repeats assessments (`--interval`) or runs once (`--once`) for cron, CI and the in-cluster CronJob. Each run is compared with the previous recorded run using the same fingerprint-based comparison as `hardex diff`, so "resolved" keeps its strict meaning (the rule ran again and the finding is gone).
- An optional approved baseline turns "change since last run" into "drift from the approved state".
- Events are delivered to JSON Lines and to HTTPS webhooks signed with HMAC-SHA256 over timestamp and body. Undelivered notifications make one-shot runs fail (exit 3): silent alert loss is a security failure.
- `monitor` is read-only. It never remediates.

## Consequences

- No database or controller to operate; history is portable and inspectable with standard tools.
- Very long histories are bounded with `--keep`.
- Real-time detection (watching the API) is not provided; the interval bounds detection latency. Admission-time enforcement is Phase IV.
