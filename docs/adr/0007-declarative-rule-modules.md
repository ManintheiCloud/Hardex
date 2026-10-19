# ADR 0007: Declarative rule modules for out-of-tree rules

- Status: accepted
- Date: 2026-10-19

## Context

The roadmap calls for community-maintained rules. Go plugins are fragile (exact toolchain and dependency matching) and executing third-party code inside a security tool widens its attack surface. Embedding a general policy language would add a large dependency.

## Decision

Out-of-tree rules are YAML modules describing a violation as *the value at PATH satisfies OP*, with scopes for objects, pod specs and containers, wildcard paths, and ten operators (existence, equality, set membership, RE2 regular expressions, numeric comparison). Module rules carry the same mandatory metadata as built-ins (description, rationale, remediation) and are validated strictly. IDs follow `ORG-AREA-NNN`; the `HX-` prefix is reserved.

Modules are trusted input, like configuration: loaded only via `--module`, never discovered from scanned content. Regular expressions use Go's RE2 engine, which matches in linear time.

## Consequences

- Organisations can encode local policy (approved registries, required labels, resource requests) in minutes, and share modules as plain files.
- Cross-object reasoning (e.g. RBAC reachability, network isolation) still requires Go rules; module expressiveness can grow in later versions behind the `v1alpha1` API version.
