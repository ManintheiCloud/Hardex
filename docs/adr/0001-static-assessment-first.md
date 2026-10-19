# ADR 0001: Static assessment of exported state first

- Status: accepted
- Date: 2026-10-19

## Context

Hardex must eventually assess live clusters, CI pipelines and admission requests. Building a live-cluster client first would tie the project to a client library version, require credentials from day one, and make tests depend on a running cluster.

## Decision

Phase I rules evaluate an in-memory `Inventory` of generic objects loaded from files or a `kubectl get -o yaml` stream. Rules never talk to a cluster.

## Consequences

- The same rules work in CI (on manifests), on cluster exports, and later in an admission webhook, without change.
- Tests are hermetic fixtures; results are reproducible byte-for-byte.
- Hardex needs no cluster credentials, honouring least privilege.
- Some state is invisible (kubelet flags, runtime defaults, managed control planes). Each affected rule documents this under "Known limitations".
- Live-cluster collection becomes another `Inventory` source in Phase II.
