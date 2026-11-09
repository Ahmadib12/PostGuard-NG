# Tenant isolation

**Status: partial foundation only; not sufficient for a managed multi-tenant deployment.** Organization rows and organization IDs on telemetry/session records exist, and dashboard data queries are scoped to the authenticated session's organization. A server-side client-ID-to-organization mapping can scope telemetry. This does not yet establish complete tenant isolation or tenant-specific administration.

Current limitations include:

- Static in-process client policies and environment-loaded secrets.
- One administrator credential store and a single configured organization context; there are no tenant memberships or tenant-aware roles.
- Static, environment-backed client policies and secrets; no tenant-specific client provisioning, revocation, or upstream credential management.
- Shared Redis namespace/service for an installation. Rate/replay keys are client-scoped, but no tenant control plane provisions identities or limits.
- Host, process, configuration, logs, backups, and operational access.

These are not fully partitioned or authorized by tenant. A separate client ID or secret is not sufficient isolation, and a shared database/Redis or dashboard must not be represented as tenant-isolated.

## Safe operating boundary

Use the provided Docker Compose deployment for a single customer/operator boundary. The operator must protect the host and all configuration, database, Redis, logs, and backups. The organization ID and client map are trusted deployment configuration, never request-provided tenant claims. For separate customer boundaries, run independently administered installations and infrastructure; this is operational separation, not a claim that the application implements managed tenancy.

## Isolation acceptance criteria

Before any shared multi-tenant deployment, design and verify tenant-aware authorization and data ownership across request processing, client policy, database access, Redis keys, dashboard/admin actions, audit/telemetry, exports, backups, restore, deletion, and support operations. Add negative cross-tenant tests for reads, writes, enumeration, replay/rate-limit state, and administrative actions. Document the threat model, operational controls, and residual risks, and obtain an independent review.

Related status: [Multi-tenant security](MULTI_TENANT_SECURITY.md) and [Managed deployment](MANAGED_DEPLOYMENT.md).
