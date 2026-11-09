# Multi-tenant security status

**Current state: partial telemetry scoping only; multi-tenancy is not implemented.** PostGuard-NG remains an installation-level gateway, not a multi-tenant service. The deployment-mode configuration does not create a tenant boundary.

The schema gives telemetry and sessions an organization ID, and protected dashboard queries use the organization ID stored in the administrator's session. Client telemetry can be mapped to organizations by trusted server configuration. The application still has one configured administrator identity, no tenant membership/RBAC, and static environment-based client policies/secrets. It does not provide tenant provisioning, per-tenant upstream credentials, tenant-specific retention, managed support controls, or platform administration. A client ID is not by itself a tenant identity.

## Deployment rule

Do not share one running instance across mutually untrusted organizations on the assumption that client mappings, separate secrets, or dashboard login provide complete tenant isolation. A customer-hosted installation should have one operator/customer boundary, with access to the host, configuration, Redis, database, logs, and backups restricted to that operator.

## Prerequisites before multi-tenant use

Any future multi-tenant release must define and enforce a tenant security boundary, including:

- Authenticated tenant identity derived from trusted credentials, never from an untrusted request parameter alone.
- Tenant-scoped client provisioning, policy evaluation, administration, and least-privilege support access.
- Isolation of all database queries/writes, Redis key namespaces, telemetry, audit records, exports, and operational tooling.
- Explicit cross-tenant behavior for caching, rate limits, replay protection, quotas, and identifiers.
- Tenant-aware backup, restore, retention, deletion, encryption/key management, and incident response.
- Regression tests demonstrating that one tenant cannot read, mutate, enumerate, or affect another tenant's resources, plus independent security review.

Until these requirements are delivered and validated, treat `POSTGUARD_DEPLOYMENT_MODE=managed` as a label only. See [Managed deployment](MANAGED_DEPLOYMENT.md) and [Tenant isolation](TENANT_ISOLATION.md).
