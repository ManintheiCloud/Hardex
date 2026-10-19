# ADR 0003: Assessment and verification before remediation

- Status: accepted
- Date: 2026-10-19

## Context

The project vision includes automated remediation. A remediation engine built before assessment is trustworthy would apply changes based on findings nobody has validated, and changes to RBAC, network policy or admission can cause outages.

## Decision

Phase I ships assessment and verification only. Remediation guidance is text in rule metadata. When remediation is built (Phase II) it must satisfy these constraints, which are recorded here so they cannot be quietly dropped:

1. Dry-run is the default; applying changes requires an explicit, per-run authorization.
2. Every change is preceded by a backup of the affected objects and is reversible.
3. Every change is followed by a re-assessment; success is defined by `verification.Compare` showing the targeted findings resolved and nothing introduced — not by the API call succeeding.
4. Changes that can affect availability (NetworkPolicy, RBAC removals, admission configuration, control-plane flags) are never applied automatically in bulk.
5. Unexpected conditions abort the run without partial application.

## Consequences

- Users get value (findings, CI gates, verified progress) without Hardex holding write credentials.
- The finding model already carries the field path and fingerprint remediation will need.
