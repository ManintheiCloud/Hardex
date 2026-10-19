# ADR 0004: A minimal, read-only live-cluster client without client-go

- Status: accepted
- Date: 2026-10-19

## Context

Phase II adds assessment of running clusters. The standard Go client (`k8s.io/client-go`) brings well over a hundred transitive modules, which conflicts with [ADR 0002](0002-go-with-minimal-dependencies.md). Hardex only needs authenticated LIST/GET (and, for remediation, JSON PATCH).

## Decision

Implement a small client in `core/cluster` on the standard library:

- kubeconfig parsing (contexts, clusters, users; token, token file, client certificates, exec credential plugins) and in-cluster service account configuration;
- paginated LIST of a fixed set of resources, GET, and JSON PATCH;
- clients are **read-only by construction** unless the remediation apply/rollback path explicitly requests a read-write client;
- the collector **never reads Secrets**, and the shipped `deploy/hardex-reader.yaml` ClusterRole grants nothing beyond what is collected;
- unsafe transports are refused with no override: `http://` servers and `insecure-skip-tls-verify`; redirects are never followed, so a bearer token cannot be forwarded to another host;
- resources that cannot be read make the assessment incomplete (exit 3) unless `--allow-partial` is given.

Controller-owned objects (a Deployment's ReplicaSets and Pods, a CronJob's Jobs) are not assessed separately: their templates are the owner's, and reporting each would multiply every finding.

## Consequences

- One dependency remains; the client is small enough to review in full.
- Legacy `auth-provider` and basic-auth kubeconfigs are not supported (both are deprecated or removed upstream); users get a clear error.
- Watch, discovery and CRDs are out of scope; adding a collected kind is a one-line change to `cluster.Collected` plus the reader ClusterRole.
