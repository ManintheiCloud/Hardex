# ADR 0002: Go, with a minimal dependency set

- Status: accepted
- Date: 2026-10-19

## Context

A security tool's dependencies are part of its attack surface, and Kubernetes client libraries pull in hundreds of modules. The Kubernetes ecosystem is predominantly Go, which matters for contributors and for later admission-webhook integration.

## Decision

Implement Hardex in Go. Use the standard library wherever practical. The only direct dependency is `github.com/goccy/go-yaml` (no transitive dependencies), used for YAML parsing, strict config decoding and alias-expansion analysis. Objects are handled as generic maps rather than typed `k8s.io/api` structs.

## Consequences

- Small, auditable dependency graph; fast builds; a single static binary.
- Rules are independent of Kubernetes API struct versions and tolerate unknown fields.
- Rules lose compile-time field checking; this is mitigated by the `resource` accessor helpers and fixture tests.
- Adding a dependency requires a PR that justifies it and states its transitive footprint.
