# Tenant isolation

**Status: IAM and organization-scoped dashboard foundation; not sufficient by itself for a managed multi-tenant deployment.** Organization rows and organization IDs on telemetry, audit, incident, and administrator-session records exist. Administrator memberships have server-enforced roles and permissions; tenant dashboard queries are scoped to the authenticated session's organization. A server-side client-ID-to-organization mapping assigns verified clients, and suspended organizations are blocked. This does not implement tenant-specific client credentials or upstream configuration.

Current limitations include:

- Static in-process client policies and environment-loaded secrets.
- No tenant-specific client provisioning, revocation, or upstream credential management.
- Shared Redis namespace/service for an installation. Rate/replay keys are client-scoped, but no tenant control plane provisions identities or limits.
- The organization mapping is trusted deployment configuration; authentication of a client does not independently prove its organization beyond that mapping.
- Host, process, configuration, logs, backups, and operational access.

Client policies, secrets, upstream configuration, and operational infrastructure are not fully partitioned by tenant. A separate client ID or secret is not sufficient isolation, and a shared database/Redis or dashboard must not be represented as a complete managed tenant boundary.

## Safe operating boundary

Use the provided Docker Compose deployment for a single customer/operator boundary. The operator must protect the host and all configuration, database, Redis, logs, and backups. The organization ID and client map are trusted deployment configuration, never request-provided tenant claims. For mutually untrusted customer boundaries, use independently administered installations and infrastructure until client credential/policy isolation and managed operations are designed and reviewed.

## Isolation acceptance criteria

Before any shared multi-tenant deployment, design and verify tenant-aware authorization and data ownership across request processing, client policy, database access, Redis keys, dashboard/admin actions, audit/telemetry, exports, backups, restore, deletion, and support operations. Add negative cross-tenant tests for reads, writes, enumeration, replay/rate-limit state, and administrative actions. Document the threat model, operational controls, and residual risks, and obtain an independent review.

Related status: [Multi-tenant security](MULTI_TENANT_SECURITY.md) and [Managed deployment](MANAGED_DEPLOYMENT.md).
