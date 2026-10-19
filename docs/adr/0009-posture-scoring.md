# ADR 0009: A transparent, rule-weighted posture score

- Status: accepted
- Date: 2026-10-19

## Decision

Score = weighted share of evaluated rules with no active findings, weights by default severity (10/5/3/1/0.5). Instance counts are reported but do not affect the score. Waived-only rules count as passing and are shown as accepted. Any active critical finding caps the grade at D. Incomplete assessments have no valid score.

## Rationale

- Recomputable by hand from the report, so the number can be audited and argued with.
- Rule-based rather than instance-based, so large clusters are not penalised for size and one systemic fix moves the score.
- The critical cap prevents a high score from hiding a direct path to compromise.

## Consequences

- The score compares environments and tracks progress; it is not a risk measurement and evidence reports say so.
